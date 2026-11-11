"""Optional deeper families. Read-only by default; leads, never proof.

The suite is scheduled only when the requester ticked the deep group. Every
request still crosses the relay gate, so origin, method, rate and redaction
limits are unchanged. Per-family caps keep the cost bounded and the remaining
time is divided by the deep_checks slot scheduler.
"""
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import re
import time

from scoped_scanners import Requests
from web_tools import allowed  # noqa: F401
from deep_checks import scoped_url

MARKER = 'patchriot-probe.example'
OBJECT = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}|/\d{1,12}(?:/|$|\?)|[?&]\w+=', re.I)
FILE_PARAM = re.compile(r'^(?:path|file|doc|document|image|img|id|name|page|template|include|url|redirect|next|return|to|target|view|src)$', re.I)
SCRIPT = re.compile(r'''<script[^>]+src=["']([^"']+\.m?js[^"']*)''', re.I)
ROUTE = re.compile(r'''["'](/[A-Za-z0-9_./~-]{2,90})["']''')
SECRET_SHAPE = re.compile(r'''(?:api[_-]?key|token|secret|authorization)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{16,80})''', re.I)

TECH_PATHS = {
    'actuator': ['/actuator', '/actuator/health', '/actuator/env'],
    'wp-content': ['/wp-json/', '/xmlrpc.php', '/wp-login.php'],
    'django': ['/admin/', '/static/admin/'],
    'laravel': ['/horizon', '/telescope', '/_ignition/health-check'],
    '_next': ['/_next/static/', '/_next/image'],
}
GENERIC_PATHS = ['/.git/HEAD', '/.env', '/sitemap.xml', '/swagger-ui.html', '/graphql', '/api/docs']
BYPASS = ['{}/', '{}.json', '{}%20', '{};', '{}/..;/', '{}?patchriot_probe=1', '{}#']
INJECT_HEADERS = [
    ('X-Forwarded-Host', MARKER), ('X-Forwarded-Scheme', 'http'),
    ('X-Host', MARKER), ('X-Forwarded-Server', MARKER), ('Forwarded', f'host={MARKER};proto=http'),
]


def status(reply):
    evidence = reply.get('evidence', {})
    return evidence.get('status'), evidence.get('headers', {}), reply.get('body', '')


def fetch_all(client, urls, limit):
    for url in urls[:limit]:
        if client.calls >= client.limit:
            return
        yield url, client('GET', url)


def script_urls(body, base, scope):
    found = []
    for raw in SCRIPT.findall(body or ''):
        url = scoped_url(raw, base, scope)
        if url:
            found.append(url)
    return found


def surface(client, urls):
    """Mine the client-side surface, then probe it with a missing control.

    A discovered route is only a lead: the missing-path control must differ.
    """
    discovered, scripts, secrets, tech = [], [], [], set()
    bodies = []
    for url, reply in fetch_all(client, urls, 6):
        body = reply.get('body', '')
        bodies.append(body)
        for lower, paths in TECH_PATHS.items():
            if lower in (body or '').lower():
                tech.update(paths)
        scripts.extend(script_urls(body, url, client.scope))
        discovered.extend(scoped_url(m, url, client.scope) for m in ROUTE.findall(body or ''))
        secrets.extend(SECRET_SHAPE.findall(body or ''))
        map_url = next((s for s in SCRIPT.findall(body or '') if s.endswith('.map')), None)
        if map_url:
            scripts.append(map_url)
    base = client.scope['origins'][0]
    seeds = list(dict.fromkeys(u for u in discovered if u))[:20]
    seeds.extend(base + path for path in GENERIC_PATHS + sorted(tech))
    for script in list(dict.fromkeys(scripts))[:10]:
        reply = client('GET', script)
        body = reply.get('body', '')
        seeds.extend(scoped_url(m, script, client.scope) for m in ROUTE.findall(body or ''))
        secrets.extend(SECRET_SHAPE.findall(body or ''))
    control_status = None
    if client.calls < client.limit:
        control = base + '/patchriot-missing-' + MARKER.split('.')[0]
        control_status, _, _ = status(client('GET', control))
    reachable = []
    for path in list(dict.fromkeys(p for p in seeds if p))[:24]:
        if client.calls >= client.limit or client.deadline <= time.monotonic():
            client.gaps.append('surface_probe_limit')
            break
        code, _, body = status(client('GET', path))
        if code and control_status and code == control_status and not body.strip():
            continue
        if code and control_status and code != control_status:
            reachable.append(path)
    return {'scripts': len(set(scripts)), 'discovered_routes': len(set(seeds)),
            'reachable_routes': reachable[:16], 'tech_paths': sorted(tech),
            'secret_shaped_strings': len(set(secrets)), 'missing_control_status': control_status,
            'reachable_urls': reachable,
            'limitations': ['Two link levels, no JavaScript evaluation; a secret-shaped string is not a validated secret.']}


def bypass(client, urls):
    """Compare access-control path mutations with the unmutated originals."""
    original, flipped, sampled = [], [], 0
    for url in urls[:8]:
        candidates = list(dict.fromkeys(candidate for variant in BYPASS
            if (candidate := scoped_url(variant.replace('{}', urlsplit(url).path or '/'), url, client.scope))
            and candidate != url))
        methods = [method for method in ('HEAD', 'OPTIONS') if method in client.scope['methods']]
        # Fit the original, every variant and method control before starting.
        if not client.can_start(1 + len(candidates) + len(methods)):
            break
        sampled += 1
        base_status, _, _ = status(client('GET', url))
        original.append({'url': url, 'status': base_status})
        for candidate in candidates:
            code, _, _ = status(client('GET', candidate))
            if base_status in (401, 403) and code and 200 <= code < 300:
                flipped.append({'url': candidate, 'control': base_status, 'status': code})
        for method in methods:
            code, headers, _ = status(client(method, url))
            allow = headers.get('allow') or headers.get('access-control-allow-methods')
            if base_status == 404 and code and 200 <= code < 300:
                flipped.append({'url': url, 'control': base_status, 'status': code, 'method': method})
            elif allow:
                flipped.append({'url': url, 'method': method, 'allow': allow})
    return {'controls': original, 'flipped': flipped[:16],
            'sampled_urls': sampled, 'available_urls': len(urls),
            'limitations': ['Cases, separators and method switching only; no payload or verb tampering.']}


def headers(client, urls):
    """Injected-header reflection, then a clean re-request to detect caching."""
    reflected, persisted = [], []
    # Each reflected header needs a clean control; budget both before starting.
    sampled = 0
    for url in urls[:6]:
        if not client.can_start(2 * len(INJECT_HEADERS)):
            break
        sampled += 1
        for name, value in INJECT_HEADERS:
            reply = client('GET', url, headers={name: value})
            code, headers_out, body = status(reply)
            if value in (body or '') or value in (headers_out.get('location') or ''):
                reflected.append({'url': url, 'header': name, 'status': code})
                _, clean_headers, clean_body = status(client('GET', url))
                if value in (clean_body or '') or value in (clean_headers.get('location') or ''):
                    persisted.append({'url': url, 'header': name})
    return {'reflected': reflected, 'persisted': persisted,
            'sampled_urls': sampled, 'available_urls': len(urls),
            'limitations': ['A reflected header alone is not host-header injection; the clean re-request is the cache check.']}


def injected(url, name, value):
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ''))


def inputs(client, urls):
    """Bounded parameter reflection, error-shape, traversal and pollution probes."""
    candidates = []
    for url in urls[:6]:
        query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        if query:
            candidates.append((url, query))
    if not candidates:
        for url in urls[:3]:
            for name in ('q', 'id', 'search', 'page'):
                candidates.append((injected(url, name, '1'), [(name, '1')]))
    observed, sampled = [], 0
    for url, query in candidates[:6]:
        required = 1 + sum(3 + int(bool(FILE_PARAM.match(name))) for name, _ in query[:3])
        if not client.can_start(required):
            break
        sampled += 1
        code, _, body = status(client('GET', url))
        baseline = (code, len(body or ''))
        for name, value in query[:3]:
            probes = [MARKER, value + "'"]
            if FILE_PARAM.match(name):
                probes.append('../../../etc/passwd')
            for probe in probes:
                probe_url = injected(url, name, probe)
                if not scoped_url(probe_url, url, client.scope):
                    continue
                pcode, _, pbody = status(client('GET', probe_url))
                kind = None
                if MARKER in (pbody or ''):
                    kind = 'reflected'
                elif pcode and baseline[0] and pcode != baseline[0]:
                    kind = 'status_changed'
                elif abs(len(pbody or '') - baseline[1]) > max(64, baseline[1] * 0.5):
                    kind = 'body_changed'
                if kind:
                    observed.append({'url': probe_url, 'param': name, 'probe': probe[:40],
                                     'kind': kind, 'control': baseline[0], 'status': pcode})
            polluted = urlunsplit(urlsplit(url)._replace(query=urlsplit(url).query + '&' + name + '=polluted'))
            pcode, _, pbody = status(client('GET', polluted))
            if 'polluted' in (pbody or ''):
                observed.append({'url': polluted, 'param': name, 'kind': 'pollution', 'status': pcode})
    return {'observed': observed[:24],
            'sampled_urls': sampled, 'available_urls': len(candidates),
            'limitations': ['Observed parameters or a small common-parameter sample; no wordlist mining, no payload execution, GET only.']}


def normalise(text):
    text = re.sub(r'[0-9a-f]{8,}', '#', text or '')
    text = re.sub(r'\d+', '#', text)
    return re.sub(r'\s+', ' ', text).strip()[:4000]


def cross_account(client, urls):
    """Fetch candidate objects as the first account, then the others."""
    if client.account:
        return {'deferred': 'runs once per suite'}
    if not client.scope.get('authentication'):
        return {'not_applicable': 'No account was requested for this black-box test.'}
    accounts = ['testing', 'reference'] if client.scope.get('account_policy') else ['testing']
    seeds = [u for u in urls if OBJECT.search(urlsplit(u).path + '?' + urlsplit(u).query)][:8]
    if not seeds:
        return {'not_applicable': 'No object-shaped route was observed; object access was not tested.'}
    anonymous = client
    sides = {'anonymous': anonymous}
    for account in accounts:
        sides[account] = Requests(client.scope, client.deadline, client.fetch, account,
                                  limit=min(12, client.limit), discovery=True)
    rows, compared = [], 0
    for url in seeds:
        if client.calls >= client.limit:
            client.gaps.append('cross_account_limit')
            break
        replies = {}
        for name, side in sides.items():
            replies[name] = side('GET', url)
        codes = {name: status(reply)[0] for name, reply in replies.items()}
        bodies = {name: normalise(reply.get('body', '')) for name, reply in replies.items()}
        for left in accounts:
            if left not in replies:
                continue
            compared += 1
            left_ok = codes.get(left) and 200 <= codes[left] < 300
            row = {'url': url, 'account': left, 'status': codes[left],
                   'anonymous_status': codes.get('anonymous')}
            for right in [a for a in accounts if a != left] + ['anonymous']:
                if right == left:
                    continue
                right_ok = codes.get(right) and 200 <= codes[right] < 300
                verdict = 'other'
                if left_ok and right_ok:
                    verdict = 'same' if bodies[left] == bodies[right] else 'differs'
                elif left_ok and codes.get(right) in (401, 403, 404):
                    verdict = 'denied_for_other'
                elif left_ok:
                    verdict = 'unreachable_for_other'
                row[right] = verdict
                row['compared_with'] = right
            rows.append(row)
    for name, side in sides.items():
        if name != 'anonymous':
            anonymous.records.extend(side.records)
            anonymous.gaps.extend(side.gaps)
    interesting = [r for r in rows if any(v == 'differs' or v == 'denied_for_other'
                                          for k, v in r.items() if k in accounts + ['anonymous'])]
    return {'compared': compared, 'interesting': interesting[:12], 'rows': rows[:16],
            'limitations': ['At most eight objects and twelve requests per account; body differences are normalised, not proven disclosure.']}


FAMILIES = [
    ('patchriot-surface', '1', surface, 90, 48),
    ('patchriot-bypass', '1', bypass, 60, 40),
    ('patchriot-headers', '1', headers, 40, 16),
    ('patchriot-inputs', '1', inputs, 60, 40),
    ('patchriot-cross-account', '1', cross_account, 60, 40),
]
