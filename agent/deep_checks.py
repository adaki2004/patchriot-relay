"""Bounded discovery using reviewed scanners; no autonomous upstream engine.

Every target request uses the relay. Anonymous work always runs first, followed
by independently verified account contexts. Scanner matches are leads, not proof.
"""
from collections import deque
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

from live_http import request
from scoped_scanners import Requests, discovery, schema_checks, zap, scanner_failure_reason, SAMPLING_LIMITS
from web_tools import allowed, record

VERSION = '1'
TOOL = 'patchriot-discovery'
COMMON = ('/', '/robots.txt', '/.well-known/security.txt', '/openapi.json', '/api/openapi.json')
UNSAFE_PATH = re.compile(r'(?:^|[/_-])(logout|signout|delete|destroy|reset|revoke|unsubscribe)(?:$|[/_.?-])', re.I)


def scoped_url(value, base, scope):
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        url = urlsplit(urljoin(base, value))
        if url.username or url.password or UNSAFE_PATH.search(url.path):
            return None
        result = urlunsplit((url.scheme, url.netloc, url.path or '/', url.query, ''))
        return result if any(allowed(origin, result) for origin in scope['origins']) else None
    except ValueError:
        return None


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        # Forms supply routes, never permission to submit a body.
        for key, value in attrs:
            if key in ('href', 'src', 'action') and value and len(self.urls) < 80:
                self.urls.append(value)


def extracted(body, base, scope):
    if not isinstance(body, str):
        return []
    body = body[:128 * 1024]
    parser = Links()
    parser.feed(body)
    values = parser.urls
    # Literal application paths only: no JS evaluation, remote schema references
    # or instructions found in target content. Ignore templates and token blobs.
    values += re.findall(r'''["'](/(?:api/|graphql|openapi|swagger)[A-Za-z0-9_./?=&%-]{0,180})["']''', body)[:40]
    return list(dict.fromkeys(url for value in values if (url := scoped_url(value, base, scope))))[:48]


def evidence_seeds(scope, directory, account=None):
    seeds = []
    for path in sorted((directory / 'http-evidence').glob('*.json')):
        try:
            e = json.loads(path.read_text())
            context = e.get('account', 'testing') if e.get('authenticated') else None
            if (context != account or e.get('login') or e.get('error')
                    or e.get('method') != 'GET' or e.get('status') != 200):
                continue
            url = scoped_url(e.get('url'), scope['origins'][0], scope)
            if url:
                seeds.append(url)
                seeds.extend(extracted(e.get('body_excerpt', ''), url, scope))
        except (OSError, ValueError, TypeError):
            continue
    return list(dict.fromkeys(seeds))[:48]


def contexts(scope, access):
    result = [(None, None)]
    missing = []
    if not scope.get('authentication'):
        return result, missing
    accounts = access.get('accounts') or [dict(account='testing', **{
        k: access.get(k) for k in ('verified', 'protected_url')})]
    for expected in ('testing', 'reference') if scope.get('account_policy') else ('testing',):
        value = next((a for a in accounts if a.get('account') == expected), {})
        if value.get('verified') is True:
            result.append((expected, value.get('protected_url')))
        else:
            missing.append('account_context_unverified:' + expected)
    return result, missing


def route_checks(client, urls):
    queue = deque((u, 0) for u in urls)
    visited, reachable = set(), []
    while queue and len(visited) < 24 and time.monotonic() < client.deadline:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        reply = client('GET', url)
        e = reply.get('evidence', {})
        if e.get('status') == 200 and not e.get('error'):
            reachable.append(url)
            if depth < 2:
                queue.extend((u, depth + 1) for u in extracted(reply.get('body', ''), url, client.scope)
                             if u not in visited)
    if queue:
        # This is deliberate sampling, never a claim that all routes were tested.
        client.gaps.append('route_sample_limit')
    return {'reachable_urls': reachable, 'sampled_urls': sorted(visited),
            'limitations': ['At most 24 routes per account context and two link levels; no form submission.']}


def compact(detail):
    """Bound display data without emitting syntactically truncated JSON."""
    if isinstance(detail, list):
        return [compact(value) for value in detail[:8]]
    if isinstance(detail, dict):
        return {key: compact(value) for key, value in detail.items()}
    return detail[:1800] if isinstance(detail, str) else detail


def run(scope, previous_tools, access, deadline, fetch=request, emit=lambda _: None,
        directory=Path('/work'), functions=None, deep=False):
    started, observed = time.monotonic(), int(time.time())
    deadline = min(deadline, started + 600)
    suite_tool = 'patchriot-deep' if deep else TOOL
    arguments = ['/patchriot/deep_checks.py', *(['--deep-suite'] if deep else []), *scope['origins']]
    emit(record(suite_tool, VERSION, arguments, started, observed, [], json.dumps({
        'receipt_schema': 1, 'coverage_complete': False, 'stop_reason': 'interrupted'}),
        exit_code=None, failure='incomplete'))
    selected, gaps = contexts(scope, access)
    if functions:
        families = functions
    elif deep:
        import deep_extra
        # The shallow families already ran; the deep pass adds new ones only.
        families = deep_extra.FAMILIES
    else:
        families = [
            ('patchriot-probes', '1', route_checks, 45, 32),
            ('ffuf', '2.1', discovery, 30, 24),
            ('schemathesis', '4.33.1', schema_checks, 75, 64),
            ('zap', '2.17.0', zap, 100, 64),
        ]
    component_runs, details, all_evidence = [], [], {}
    seeds = {account: evidence_seeds(scope, directory, account) for account, _ in selected}
    seeds[None] = list(dict.fromkeys(
        [origin + path for origin in scope['origins'] for path in COMMON] + seeds[None]))
    for account, protected in selected:
        if account:
            candidate = scoped_url(protected, scope['origins'][0], scope)
            if candidate:
                seeds[account].insert(0, candidate)
            elif scope.get('auth_check_path'):
                seeds[account].insert(0, scope['origins'][0] + scope['auth_check_path'])
            if not seeds[account]:
                gaps.append('access_context_untested:' + account)
    # Each family retains one receipt across contexts, staying under the broker's
    # tool-record cap. Public seeds do not depend on a successful account login.
    for family_index, (tool, version, function, seconds, limit) in enumerate(families):
        family_started, family_observed = time.monotonic(), int(time.time())
        family_contexts, refs, family_gaps = [], [], []
        for context_index, (account, _) in enumerate(selected):
            if deadline - time.monotonic() < 3:
                family_gaps.append('scanner_budget_reached')
                continue
            if account and not seeds[account]:
                family_gaps.append('access_context_untested')
                continue
            # Anonymous parity first. Account contexts receive bounded slices of
            # remaining time; one slow scanner cannot consume final-report time.
            remaining_weight = (seconds * (len(selected) - context_index)
                                + sum(f[3] for f in families[family_index + 1:]) * len(selected))
            slice_seconds = min(seconds, max(0, (deadline - time.monotonic()) * seconds / remaining_weight))
            client = Requests(scope, min(deadline, time.monotonic() + slice_seconds), fetch,
                              account, limit=limit, discovery=True)
            context_started = time.monotonic()
            urls = seeds[account]
            if function == schema_checks:
                # A publicly observed schema also describes the signed-in API.
                # Reuse its URL, never an anonymous response as login evidence.
                urls = list(dict.fromkeys(urls + [u for u in seeds[None]
                    if re.search('openapi|swagger|graphql', u, re.I)]))
                urls = sorted(urls, key=lambda u: (not bool(re.search('openapi|swagger|graphql', u, re.I)),
                                                  not urlsplit(u).path.endswith('.json')))
            try:
                detail = function(client, urls)
                if detail.get('reachable_urls'):
                    seeds[account] = list(dict.fromkeys(detail['reachable_urls'] + urls))
            except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
                detail = {'state': 'blocked', 'reason': scanner_failure_reason(error)}
                client.gaps.append('scanner_execution_incomplete')
            for e in client.records:
                refs.append(e['id']); all_evidence[e['id']] = e
            family_gaps.extend(client.gaps)
            family_contexts.append({'account': account or 'anonymous', 'requests': len(client.records),
                                    'allocated_seconds': round(slice_seconds, 2), 'request_limit': limit,
                                    'duration_ms': round((time.monotonic() - context_started) * 1000),
                                    'result': compact(detail), 'gaps': sorted(set(client.gaps))})
        gaps.extend(family_gaps)
        detail = {'phase': 'scoped_deep_checks' if deep else 'scoped_discovery',
                  'contexts': family_contexts, 'gaps': sorted(set(family_gaps))}
        details.append({'tool': tool, **detail})
        # Route sampling is an explicit coverage limitation, not a crashed tool.
        failures = set(family_gaps) - SAMPLING_LIMITS
        receipt = record(tool, version, ['scoped', '--deep-suite' if deep else '--discovery-suite'],
                         family_started, family_observed, refs, json.dumps(detail), 0,
                         'incomplete' if failures else None)
        if receipt['output_truncated']:
            gaps.append('receipt_output_truncated')
        component_runs.append(receipt); emit(receipt)
    counts = {account or 'anonymous': sum(
        not e.get('login') and (e.get('account', 'testing') if e.get('authenticated') else None) == account
        and isinstance(e.get('status'), int) and not e.get('error')
        and (account is None or 200 <= e['status'] < 300) for e in all_evidence.values())
        for account, _ in selected}
    for name, count in counts.items():
        if not count:
            gaps.append('access_context_untested:' + name)
    for origin in scope['origins']:
        if not any(not e.get('authenticated') and not e.get('login') and not e.get('error')
                   and isinstance(e.get('status'), int) and allowed(origin, e.get('url', ''))
                   for e in all_evidence.values()):
            gaps.append('public_origin_untested:' + origin)
    auth_count = sum(count for name, count in counts.items() if name != 'anonymous')
    incomplete = sorted(set(gaps) - SAMPLING_LIMITS)
    summary = {'engine': 'Patchriot deep checks' if deep else 'Patchriot scoped discovery',
        'receipt_schema': 1,
        'coverage_complete': not incomplete, 'stop_reason': 'checks_incomplete' if incomplete else 'done',
        'failure': 'incomplete' if incomplete else None, 'collection_errors': incomplete,
        'sampling_limits': sorted(set(gaps) & SAMPLING_LIMITS),
        'authentication_requested': bool(scope.get('authentication')),
        'access_mode': 'anonymous_and_authenticated' if auth_count else 'anonymous',
        'anonymous_evidence_count': counts.get('anonymous', 0), 'authenticated_evidence_count': auth_count,
        'account_evidence_counts': counts, 'checks': [{'tool': r['tool'], 'failure': r['failure'],
            'requests': len(r['evidence_ids'])} for r in component_runs],
        'limitations': ['Completion means the bounded plan ran, not exhaustive vulnerability coverage.',
            'Scanner leads require control requests and human review. No command execution, persistence, credential changes or database takeover checks.',
            'Public checks precede verified account checks; missing access is never a clean grey-box pass.']}
    if 'route_sample_limit' in gaps:
        summary['limitations'].append('Route sampling stopped before another complete comparison would exceed the request or time allowance; inspect component samples for untested paths.')
    if 'schema_case_sample_limit' in gaps:
        summary['limitations'].append('API schema cases were sampled across eligible operations; inspect the schema receipt for tested and deferred counts. State-changing operations require agent review and existing permissions.')
    (directory / ('deep-results.json' if deep else 'discovery-results.json')).write_text(
        json.dumps({**summary, 'details': details}))
    receipt = record(suite_tool, VERSION, arguments, started, observed, sorted(all_evidence),
                     json.dumps(summary), 0, 'incomplete' if incomplete else None)
    emit(receipt)
    return receipt, component_runs
