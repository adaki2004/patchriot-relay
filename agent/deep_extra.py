"""Optional deeper families. Read-only by default; leads, never proof.

The suite is scheduled only when the requester ticked the deep group. Every
request still crosses the relay gate, so origin, method, rate and redaction
limits are unchanged. Per-family caps keep the cost bounded and the remaining
time is divided by the deep_checks slot scheduler.
"""
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import re
import json
import time

from scoped_scanners import Requests
from schema_cases import reusable_url
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
    base = client.scope['origins'][0]
    # Get the negative control first. Mining scripts must not consume the time
    # needed to compare the routes they reveal.
    if not client.can_start(2):
        return {'state': 'blocked', 'reason': 'surface_control_unavailable'}
    control = client('GET', base + '/patchriot-missing-' + MARKER.split('.')[0])
    control_status, _, _ = status(control)
    if control_status is None:
        client.gaps.append('surface_control_unavailable')
        return {'state': 'blocked', 'reason': 'surface_control_unavailable'}
    pages_read, scripts_read = 0, 0
    for url in urls[:6]:
        if not client.can_start(2):
            break
        reply = client('GET', url)
        pages_read += 1
        body = reply.get('body', '')
        for lower, paths in TECH_PATHS.items():
            if lower in (body or '').lower():
                tech.update(paths)
        scripts.extend(script_urls(body, url, client.scope))
        discovered.extend(scoped_url(m, url, client.scope) for m in ROUTE.findall(body or ''))
        secrets.extend(SECRET_SHAPE.findall(body or ''))
        map_url = next((s for s in SCRIPT.findall(body or '') if s.endswith('.map')), None)
        if map_url:
            scripts.append(map_url)
    seeds = list(dict.fromkeys(u for u in discovered if u))[:20]
    seeds.extend(base + path for path in GENERIC_PATHS + sorted(tech))
    for script in list(dict.fromkeys(scripts))[:10]:
        if not client.can_start(2):
            break
        reply = client('GET', script)
        scripts_read += 1
        body = reply.get('body', '')
        seeds.extend(scoped_url(m, script, client.scope) for m in ROUTE.findall(body or ''))
        secrets.extend(SECRET_SHAPE.findall(body or ''))
    reachable, tested = [], []
    candidates = list(dict.fromkeys(p for p in seeds if p))
    for path in candidates[:24]:
        if not client.can_start(1):
            break
        code, _, body = status(client('GET', path))
        tested.append(path)
        if code and control_status and code == control_status and not body.strip():
            continue
        if code and control_status and code != control_status:
            reachable.append(path)
    if len(tested) < len(candidates) or pages_read < len(urls) or scripts_read < len(set(scripts)):
        client.gaps.append('route_sample_limit')
    if not tested:
        client.gaps.append('surface_no_routes_probed')
    return {'scripts': len(set(scripts)), 'discovered_routes': len(set(seeds)),
            'pages_read': pages_read, 'scripts_read': scripts_read,
            'candidate_routes': len(candidates), 'probed_routes': len(tested),
            'deferred_routes': max(0, len(candidates) - len(tested)),
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


def comparable_body(reply):
    """Compare complete JSON without erasing object IDs or private field values."""
    e = reply.get('evidence', {})
    body = reply.get('body', '')
    if (e.get('error') or reply.get('error') or e.get('truncated') or reply.get('body_truncated')
            or not isinstance(body, str) or re.search(r'redacted|\[filtered\]', body, re.I)):
        return None
    try:
        value = json.loads(body)
    except ValueError:
        return None
    if not isinstance(value, (dict, list)) or not value or (isinstance(value, dict) and value.get('error')):
        return None
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def access_matches(reply, account):
    e = reply.get('evidence', {})
    actual = (e.get('account') or 'testing') if e.get('authenticated') else None
    return not e.get('login') and not e.get('error') and not reply.get('error') and actual == account


def cross_account(client, urls):
    """Re-read observed objects in verified contexts, with a repeated baseline.

    These are comparison leads. Ownership and whether data should be private
    still need evidence; two configured account slots do not establish either.
    """
    if client.account:
        return {'deferred': 'runs once per suite'}
    if not client.scope.get('authentication'):
        return {'not_applicable': 'No account was requested for this black-box test.'}
    accounts = [a for a in ('testing', 'reference') if a in client.verified_accounts]
    if not accounts:
        return {'not_applicable': 'No verified account context is available.'}
    seeds, seen = [], set()
    for e in client.observations:
        url, account = e.get('url', ''), e.get('account')
        if (e.get('method') != 'GET' or account not in accounts or (url, account) in seen
                or not any(reusable_url(o, url) for o in client.scope['origins'])
                or not OBJECT.search(urlsplit(url).path + '?' + urlsplit(url).query)):
            continue
        seen.add((url, account)); seeds.append(e)
    if not seeds:
        return {'not_applicable': 'No successful signed-in object request was observed; object access was not tested.'}
    sides = {a: Requests(client.scope, client.deadline, client.fetch, a,
                         limit=min(12, client.limit), discovery=True) for a in accounts}
    sides[None] = client

    def fetch(account, url):
        side = sides[account]
        result = side('GET', url)
        if account:
            # Every account uses the same overall request and timing allowance.
            client.calls += 1
            client.slowest_request_seconds = max(client.slowest_request_seconds, side.slowest_request_seconds)
            client.records.extend(side.records); side.records.clear()
            client.replies.update(side.replies); side.replies.clear()
            client.gaps.extend(side.gaps); side.gaps.clear()
        return result

    rows = []
    for seed in seeds[:8]:
        owner, url = seed['account'], seed['url']
        others = [a for a in accounts if a != owner] + [None]
        if not client.can_start(2 + len(others)):
            break
        if any(sides[a].calls + (2 if a == owner else 1) > sides[a].limit for a in accounts):
            client.gaps.append('route_sample_limit'); break
        baseline = fetch(owner, url)
        comparisons = {a: fetch(a, url) for a in others}
        repeated = fetch(owner, url)
        baseline_body = comparable_body(baseline)
        stable = (access_matches(baseline, owner) and access_matches(repeated, owner)
                  and all(isinstance(status(r)[0], int) and 200 <= status(r)[0] < 300 for r in (baseline, repeated))
                  and baseline_body is not None and baseline_body == comparable_body(repeated))
        if not access_matches(baseline, owner) or not access_matches(repeated, owner):
            client.gaps.append('account_comparison_context_unverified')
        row = {'url': url, 'source_account': owner, 'source_evidence_id': seed.get('evidence_id'),
               'baseline_evidence_id': baseline.get('evidence', {}).get('id'),
               'repeat_evidence_id': repeated.get('evidence', {}).get('id'),
               'baseline_stable': stable, 'ownership_requires_confirmation': True, 'comparisons': []}
        for account, response in comparisons.items():
            code = status(response)[0]
            verdict = 'inconclusive'
            if not access_matches(response, account):
                client.gaps.append('account_comparison_context_unverified')
            elif stable and code in (401, 403, 404):
                verdict = 'denied'
            elif stable and isinstance(code, int) and 200 <= code < 300 and comparable_body(response) is not None:
                verdict = 'same_content' if baseline_body == comparable_body(response) else 'different_content'
            row['comparisons'].append({'account': account or 'anonymous', 'status': code,
                'evidence_id': response.get('evidence', {}).get('id'), 'result': verdict})
        rows.append(row)
    return {'compared': len(rows), 'rows': rows, 'verified_accounts': accounts,
            'second_account_available': len(accounts) == 2,
            'limitations': ['At most eight observed objects; twelve requests per account within one shared cap.',
                'Only complete stable JSON is compared. Shared/public data and same-user accounts can match normally.',
                'Ownership, distinct users and expected privacy require separate evidence before claiming a leak.']}


FAMILIES = [
    ('patchriot-surface', '1', surface, 90, 48),
    ('patchriot-bypass', '1', bypass, 60, 40),
    ('patchriot-headers', '1', headers, 40, 16),
    ('patchriot-inputs', '1', inputs, 60, 40),
    ('patchriot-cross-account', '1', cross_account, 60, 40),
]
