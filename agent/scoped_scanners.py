"""Additional bounded scanners sharing the relay's scope, sessions and evidence.

Tools produce leads. Only recorded upstream requests can support a report claim.
The module runs inside the network-isolated agent container.
"""
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from live_http import request
from schema_cases import base_candidates, base_probe_paths, reusable_url
from web_tools import ScopeMirror, allowed, capture, fetch_checked, record

ZAP_VERSION = '2.17.0'
SCHEMA_VERSION = '4.33.1'
# These describe the selected sample, not a failed request or missing login.
SAMPLING_LIMITS = {'route_sample_limit', 'schema_case_sample_limit'}


def working_requests(scope, records):
    """Index successful recorded requests, without copying bodies or credentials.

    POST entries describe field names for agent review; they are never replay
    instructions. Keep account contexts separate, including public requests.
    """
    examples, seen = [], set()
    for e in records:
        if (not isinstance(e, dict) or e.get('login') or e.get('error')
                or not isinstance(e.get('status'), int) or not 200 <= e['status'] < 300
                or e.get('method') not in ('GET', 'POST') or not e.get('id')):
            continue
        url = e.get('url', '')
        if not any(reusable_url(o, url) for o in scope['origins']):
            continue
        account = (e.get('account') or 'testing') if e.get('authenticated') else None
        if account not in (None, 'testing', 'reference'):
            continue
        key = (e['method'], url, account)
        if key in seen:
            continue
        seen.add(key)
        item = {'method': e['method'], 'url': url, 'account': account,
                'evidence_id': e['id'], 'status': e['status']}
        if e['method'] == 'POST':
            body = e.get('request_body_excerpt') or ''
            try:
                value = json.loads(body)
                fields = list(value) if isinstance(value, dict) else []
            except ValueError:
                fields = [k for k, _ in parse_qsl(body)] if '=' in body else []
            item['body_fields'] = [k for k in fields if re.fullmatch(r'[\w.-]{1,64}', k)][:20]
            item['replay'] = 'requires_agent_review_and_existing_write_permission'
        examples.append(item)
    # Prefer API requests and signed-in examples over repeated static resources.
    return sorted(examples, key=lambda e: (e['method'] != 'POST',
        not bool(re.search(r'/api(?:/|$)|/graphql(?:/|$)', urlsplit(e['url']).path)),
        e['account'] is None))[:96]


def saved_requests(scope, directory):
    records = []
    for path in sorted((directory / 'http-evidence').glob('*.json')):
        try:
            records.append(json.loads(path.read_text()))
        except (OSError, ValueError):
            continue
    return working_requests(scope, records)


class Requests:
    def __init__(self, scope, deadline, fetch=request, account=None, limit=48, discovery=True):
        self.scope, self.deadline, self.fetch = scope, deadline, fetch
        self.account, self.limit = account, limit
        self.discovery = discovery
        self.records, self.replies, self.gaps = [], {}, []
        self.observations, self.verified_accounts = [], []
        self.calls = 0
        self.slowest_request_seconds = 0.0
        self.lock = threading.Lock()

    def can_start(self, requests):
        """Plan a whole serial probe/control group before spending its first request.

        Timing is an estimate, not an extension of the deadline. A slower reply
        can still cause a real timeout, which __call__ keeps as incomplete.
        """
        with self.lock:
            remaining = self.deadline - time.monotonic()
            expected = self.slowest_request_seconds * 1.25 * requests + 0.25
            if requests > 0 and self.calls + requests <= self.limit and remaining > expected:
                return True
            self.gaps.append('route_sample_limit' if self.calls and remaining > 0 else 'scanner_budget_reached')
            return False

    def __call__(self, method, url, headers=None, **kwargs):
        # The scanner can run threads. Reserve its request slot before I/O.
        with self.lock:
            if self.calls >= self.limit or time.monotonic() >= self.deadline:
                self.gaps.append('scanner_budget_reached')
                return {'error': 'scanner_budget_reached'}
            if method not in self.scope['methods'] or not any(allowed(o, url) for o in self.scope['origins']):
                self.gaps.append('outside_approved_scope')
                return {'error': 'outside_approved_scope'}
            self.calls += 1
        started = time.monotonic()
        reply = fetch_checked(self.fetch, method, url, headers, authenticated=self.account is not None,
                              account=self.account or 'testing', discovery=self.discovery, **kwargs)
        evidence = reply.get('evidence', {})
        with self.lock:
            self.slowest_request_seconds = max(self.slowest_request_seconds, time.monotonic() - started)
            if time.monotonic() > self.deadline:
                self.gaps.append('scanner_budget_reached')
            if evidence.get('id'):
                self.records.append(evidence)
                self.replies[evidence['id']] = reply
            error = reply.get('error') or evidence.get('error')
            if error:
                self.gaps.append(error)
        return reply


def observed_urls(scope, records):
    urls = [origin + '/' for origin in scope['origins']]
    for run in records:
        if run.get('tool') != 'patchriot-crawl' or run.get('output_truncated'):
            continue
        try:
            pages = json.loads(run['output_excerpt']).get('pages', [])
            urls.extend(p['url'] for p in pages if p.get('status') == 200)
        except (ValueError, KeyError, TypeError):
            continue
    return sorted({u for u in urls if any(allowed(o, u) for o in scope['origins'])})[:12]


def probes(client, urls):
    checks = []
    for url in urls[:4]:
        replies = [client('GET', url), client('OPTIONS', url),
                   client('GET', url, {'Origin': 'https://patchriot.invalid'})]
        checks.append({'url': url, 'class': 'methods_and_cors',
                       'evidence_ids': [r['evidence']['id'] for r in replies if r.get('evidence', {}).get('id')],
                       'interpretation': 'Compare actual headers and controls. Browser exploitability requires browser evidence.'})
    return {'checks': checks}


def discovery(client, urls, execute=capture):
    """Small observed path list and a random missing-path control per origin."""
    results = []
    for origin in client.scope['origins']:
        paths = sorted({urlsplit(u).path.lstrip('/') for u in urls if allowed(origin, u)})
        paths = [p for p in paths if p and '\n' not in p][:6]
        variants = []
        for path in paths:
            if '.' not in path.rsplit('/', 1)[-1]:
                variants.extend([path.rstrip('/') + '/', path.rstrip('/') + '.json'])
        paths = list(dict.fromkeys(paths + variants))[:12]
        control = 'patchriot-missing-' + secrets.token_hex(10)
        control_reply = client('GET', origin + '/' + control)
        if not paths:
            results.append({'origin': origin, 'state': 'inapplicable', 'reason': 'no_observed_paths'})
            continue
        with tempfile.TemporaryDirectory(prefix='patchriot-discovery-') as directory:
            wordlist = Path(directory) / 'paths.txt'
            wordlist.write_text('\n'.join(paths + [control]) + '\n')
            with ScopeMirror(origin, client.deadline, fetch=client) as mirror:
                run = execute(['ffuf', '-w', str(wordlist), '-u', mirror.url + '/FUZZ',
                               '-t', '1', '-rate', '2', '-maxtime', '15', '-timeout', '5',
                               '-noninteractive', '-json', '-mc', 'all'], timeout=20)
            if run['failure'] or run['exit_code'] != 0:
                client.gaps.append('discovery_execution_incomplete')
        results.append({'origin': origin, 'paths': paths, 'control_evidence_id': control_reply.get('evidence', {}).get('id'),
                        'interpretation': 'Compare missing-path content before reporting an exposed endpoint.'})
    return {'discovery': results}


def zap(client, urls):
    """Passive checks plus a selected reflected-input rule on observed GET queries."""
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    key = secrets.token_hex(24)
    # Add-on extraction exceeds the container's 128 MiB /tmp limit. Use the
    # existing work allowance and remove the scanner directory on exit.
    with tempfile.TemporaryDirectory(prefix='patchriot-zap-', dir='/work') as home:
        argv = ['/opt/zap/zap.sh', '-daemon', '-silent', '-host', '127.0.0.1', '-port', str(port), '-dir', home,
                '-config', 'api.key=' + key, '-config', 'autoupdate.checkOnStart=false',
                '-config', 'autoupdate.downloadNewRelease=false', '-config', 'connection.timeoutInSecs=5']
        child = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 env={**os.environ, 'JAVA_OPTS': '-Xmx512m'}, start_new_session=True)
        def api(component, kind, action, **params):
            url = f'http://127.0.0.1:{port}/JSON/{component}/{kind}/{action}/?' + urlencode(params)
            try:
                with urlopen(Request(url, headers={'X-ZAP-API-Key': key}), timeout=10) as response:
                    value = json.load(response)
            except HTTPError as error:
                with error:
                    detail = json.loads(error.read(4096))
                raise ValueError('scanner_api_' + str(detail.get('code', 'error'))) from None
            if 'code' in value and value.get('code') != 'OK':
                raise ValueError('scanner_api_error')
            return value
        alerts = []
        try:
            ready = min(client.deadline, time.monotonic() + 45)
            while True:
                try:
                    if api('core', 'view', 'version')['version'] != ZAP_VERSION:
                        raise ValueError('scanner_version_mismatch')
                    break
                except OSError:
                    if child.poll() is not None or time.monotonic() >= ready:
                        raise TimeoutError('scanner_startup_timeout')
                    time.sleep(0.2)
            api('ascan', 'action', 'disableAllScanners')
            api('ascan', 'action', 'enableScanners', ids='40012')
            api('ascan', 'action', 'setOptionThreadPerHost', Integer=1)
            for origin in client.scope['origins']:
                with ScopeMirror(origin, client.deadline, fetch=client) as mirror:
                    selected = [u for u in urls if allowed(origin, u)][:4]
                    for url in selected:
                        parsed = urlsplit(url)
                        local = mirror.url + urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
                        api('core', 'action', 'accessUrl', url=local, followRedirects='false')
                        if parsed.query and client.scope.get('profile') in ('web_active_v1', 'web_active_v2'):
                            # ZAP queues its site-tree insertion after accessUrl returns.
                            # Retry only the explicit pre-start 'URL not found' result.
                            indexed_by = min(client.deadline, time.monotonic() + 5)
                            while True:
                                try:
                                    scan = api('ascan', 'action', 'scan', url=local, recurse='false', method='GET')['scan']
                                    break
                                except ValueError as error:
                                    if str(error) != 'scanner_api_url_not_found' or time.monotonic() >= indexed_by:
                                        raise
                                    time.sleep(0.1)
                            while time.monotonic() < client.deadline and client.calls < client.limit:
                                if api('ascan', 'view', 'status', scanId=scan)['status'] == '100':
                                    break
                                time.sleep(0.2)
                            else:
                                client.gaps.append('active_scan_incomplete')
                            api('ascan', 'action', 'stop', scanId=scan)
                    while time.monotonic() < client.deadline:
                        if api('pscan', 'view', 'recordsToScan')['recordsToScan'] == '0':
                            break
                        time.sleep(0.2)
                    else:
                        client.gaps.append('passive_scan_incomplete')
                    for alert in api('core', 'view', 'alerts', baseurl=mirror.url, start=0, count=40).get('alerts', []):
                        # Scanner payloads can echo target data. Retain only bounded labels
                        # and map the URL to the relay evidence for reviewer inspection.
                        path = urlsplit(alert.get('url', '')).path
                        refs = [e['id'] for e in client.records if urlsplit(e['url']).path == path]
                        alerts.append({'rule': str(alert.get('pluginId', ''))[:20],
                                       'title': str(alert.get('alert', ''))[:180],
                                       'evidence_ids': refs, 'support': 'needs_validation'})
        finally:
            import signal
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
        return {'alerts': alerts, 'limitations': ['Selected headers and decoded text only. Cookie, TLS and browser-context claims require original-context checks.']}


def schema_base(client, document, url, observed_urls):
    bases, declared = base_candidates(document, url, observed_urls)
    origin = urlsplit(url).scheme + '://' + urlsplit(url).netloc
    if not bases:
        return None, 'no_approved_schema_server'
    if declared:
        return bases[0], 'declared_server'
    if bases == [origin]:
        return origin, 'default_origin'
    # A schema under /api does not by itself prove the API lives there. Check a
    # read endpoint against a missing-path control; never follow a redirect to
    # HTTP, localhost or another host to make the schema appear usable.
    for base in bases:
        for path in base_probe_paths(document, base, observed_urls):
            if not client.can_start(2):
                return None, 'schema_base_unverified'
            reply = client('GET', base + path)
            code = reply.get('evidence', {}).get('status') or 0
            if not (200 <= code < 300 or code in (401, 403)) or reply.get('error'):
                continue
            try:
                json.loads(reply.get('body', ''))
            except ValueError:
                continue
            control = client('GET', base + '/patchriot-schema-missing-' + secrets.token_hex(6))
            other = control.get('evidence', {}).get('status')
            if other is not None and not control.get('error') and other != code:
                return base, 'verified_mount'
    return None, 'schema_base_unverified'


def schema_checks(client, urls, execute=capture):
    candidates = [u for u in urls if re.search(r'(openapi|swagger|api-docs|graphql)', urlsplit(u).path, re.I)]
    results, documents, candidates_seen = [], [], []
    if not candidates:
        return {'state': 'inapplicable', 'reason': 'no_observed_api_schema'}
    for index, url in enumerate(candidates[:2]):
        if not client.can_start(1):
            break
        graphql_mode = 'graphql' in urlsplit(url).path.lower()
        if graphql_mode:
            if 'POST' not in client.scope['methods'] or client.account == 'reference':
                candidates_seen.append({'url': url, 'state': 'deferred', 'reason': 'graphql_post_not_permitted'})
                continue
            query = execute([sys.executable, str(Path(__file__).with_name('schema_cases.py')), '--introspection-query'], timeout=5)
            if query['failure'] or query['exit_code'] != 0:
                client.gaps.append('graphql_introspection_unavailable')
                continue
            reply = client('POST', url, {'Content-Type': 'application/json'}, data=query['output'])
        else:
            reply = client('GET', url)
        status = reply.get('evidence', {}).get('status')
        if status in (404, 405):
            candidates_seen.append({'url': url, 'state': 'inapplicable', 'reason': 'no_schema_at_candidate'})
            continue
        if status is not None and not 200 <= status < 300:
            candidates_seen.append({'url': url, 'state': 'unavailable', 'status': status})
            continue
        if reply.get('body_truncated'):
            client.gaps.append('schema_truncated')
            continue
        try:
            schema = json.loads(reply.get('body', ''))
        except ValueError:
            candidates_seen.append({'url': url, 'state': 'inapplicable', 'reason': 'candidate_is_not_a_schema'})
            continue
        if not isinstance(schema, dict):
            client.gaps.append('schema_object_required')
            continue
        if not graphql_mode and not any(key in schema for key in ('openapi', 'swagger')):
            candidates_seen.append({'url': url, 'state': 'inapplicable', 'reason': 'candidate_is_not_a_schema'})
            continue
        base, base_source = (url, 'graphql_endpoint') if graphql_mode else schema_base(client, schema, url, urls)
        if base is None:
            client.gaps.append(base_source)
            candidates_seen.append({'url': url, 'state': 'unavailable', 'reason': base_source})
            continue
        slots = min(48, max(0, (client.limit - client.calls) // max(1, len(candidates[:2]) - index)))
        slots = min(slots, max(0, int((client.deadline - time.monotonic() - 1)
                                     / (max(.25, client.slowest_request_seconds) * 1.25))))
        if slots < 1:
            client.gaps.append('scanner_budget_reached')
            break
        with tempfile.TemporaryDirectory(prefix='patchriot-schema-') as directory:
            schema_path = Path(directory) / 'schema.json'
            schema_path.write_text(json.dumps(schema))
            observations_path = Path(directory) / 'observed.json'
            observations_path.write_text(json.dumps([e for e in client.observations
                if e['method'] == 'GET' and e['account'] == client.account]))
            generated = execute([sys.executable, str(Path(__file__).with_name('schema_cases.py')), str(schema_path), base,
                                 str(slots), ','.join(client.scope['methods']), str(observations_path)],
                                timeout=max(1, min(25, client.deadline - time.monotonic())))
            if generated['failure'] or generated['exit_code'] != 0:
                client.gaps.append('schema_generation_incomplete')
                continue
            cases = json.loads(generated['output'])
            before = len(results)
            for case in cases['cases']:
                if not client.can_start(1):
                    break
                response = client(case['method'], case['url'], case.get('headers'), data=case.get('data'))
                evidence = response.get('evidence', {})
                results.append({'evidence_id': evidence.get('id'), 'status': evidence.get('status'),
                                'server_error': (evidence.get('status') or 0) >= 500,
                                'generation_mode': case.get('generation_mode'), 'operation': case.get('operation'),
                                'source_evidence_id': case.get('source_evidence_id'),
                                'status_declared': str(evidence.get('status')) in case.get('expected_statuses', []) or 'default' in case.get('expected_statuses', []) or str(evidence.get('status', ''))[:1] + 'XX' in case.get('expected_statuses', [])})
            client.gaps.extend(cases['gaps'])
            client.gaps.extend(cases.get('sampling_limits', []))
            if cases['cases'] and not any(isinstance(row.get('status'), int) for row in results[before:]):
                client.gaps.append('schema_no_cases_executed')
            documents.append({'url': url, 'base_url': base, 'base_source': base_source,
                              **{k: cases.get(k) for k in ['operations_total', 'operations_eligible', 'operations_selected',
                                  'case_limit', 'generation_modes_unavailable', 'deferred_operations_count', 'deferred_operations', 'limitations']},
                              'generated_cases': len(cases['cases']), 'attempted_cases': len(results) - before,
                              'observed_baselines': sum(row.get('generation_mode') == 'observed' for row in results[before:]),
                              'executed_cases': sum(isinstance(row.get('status'), int) for row in results[before:]),
                              'operations_tested': len({row['operation'] for row in results[before:]
                                                       if isinstance(row.get('status'), int)}),
                              'read_operations_untested': max(0, cases.get('operations_eligible', 0) - len({
                                  row['operation'] for row in results[before:] if isinstance(row.get('status'), int)}))})
    if not documents and any(row.get('state') == 'unavailable' for row in candidates_seen):
        client.gaps.append('schema_unavailable')
    return {'cases': results, 'schemas': documents, 'candidates': candidates_seen,
            'interpretation': 'Sampled API operations, not exhaustive coverage. Server errors and schema anomalies require reproduction and demonstrated security impact.'}


def scanner_failure_reason(error):
    """Retain bounded scanner codes, never target text or credentials from exceptions."""
    reason = str(error)
    return reason if re.fullmatch(r'scanner_[a-z_]{1,60}', reason) else type(error).__name__


def run(scope, records, access=None, fetch=request, emit=lambda value: None, directory=Path('/work')):
    urls = observed_urls(scope, records)
    for path in sorted((directory / 'http-evidence').glob('*.json')):
        try:
            evidence = json.loads(path.read_text())
            url = evidence.get('url', '')
            if evidence.get('status') == 200 and re.search(r'(openapi|swagger|api-docs|graphql)', urlsplit(url).path, re.I) and any(allowed(origin, url) for origin in scope['origins']):
                urls.append(url)
        except (OSError, ValueError, TypeError):
            continue
    urls = list(dict.fromkeys(urls))[:16]
    contexts = [None]
    accounts = (access or {}).get('accounts') or [dict(account='testing', **{key: (access or {}).get(key) for key in ('verified', 'protected_url')})]
    for context in accounts:
        if context.get('verified') is not True:
            continue
        account = context.get('account')
        if account not in ('testing', 'reference'):
            continue
        contexts.append(account)
        protected = context.get('protected_url')
        if protected and any(allowed(o, protected) for o in scope['origins']):
            urls = list(dict.fromkeys(urls + [protected]))
    results = []
    for tool, version, function, seconds in (
        ('patchriot-probes', '1', probes, 30), ('ffuf', '2.1', discovery, 40),
        ('zap', ZAP_VERSION, zap, 100), ('schemathesis', SCHEMA_VERSION, schema_checks, 45),
    ):
        started, observed = time.monotonic(), int(time.time())
        if tool == 'ffuf':
            detected = capture(['ffuf', '-V'], timeout=3)
            match = re.search(r'\d+\.\d+(?:\.\d+)?', detected['output'])
            version = match.group() if match else 'unavailable'
        refs, details, gaps = [], [], []
        for account in ([None] if tool == 'ffuf' else contexts):
            client = Requests(scope, time.monotonic() + seconds, fetch, account)
            try:
                selected = urls
                if account is not None:
                    protected = [context['protected_url'] for context in accounts
                                 if context.get('account') == account and context.get('verified') and context.get('protected_url')]
                    selected = protected + [url for url in urls if re.search(r'(openapi|swagger|api-docs|graphql)', urlsplit(url).path, re.I)]
                detail = function(client, selected)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                reason = scanner_failure_reason(error)
                detail = {'state': 'blocked', 'reason': reason}
                client.gaps.append('scanner_execution_incomplete')
            refs.extend(e['id'] for e in client.records)
            gaps.extend(client.gaps)
            details.append({'account': account or 'anonymous', 'result': detail,
                            'requests': len(client.records), 'gaps': sorted(set(client.gaps))})
        failure = 'incomplete' if set(gaps) - SAMPLING_LIMITS else None
        receipt = record(tool, version, ['scoped', '--max-requests-per-context', '48'], started, observed,
                         refs, json.dumps({'contexts': details}), 0, failure)
        results.append(receipt)
        emit(receipt)
    return results


def follow_up(scope, records, engine, access, deadline, fetch=request,
              emit=lambda value: None, directory=Path('/work')):
    """Give the web scanner new recorded engine inputs within the report reserve.

    A model can discover and exercise inputs without a user-supplied schema.
    Only successful GET evidence supplies seeds; scanner payload generation
    remains in the selected rule and behind the same broker permissions.
    """
    # A failed optional preparation read must remain an explicit coverage gap,
    # not abort delivery of discovery evidence or assume signed-in access.
    if callable(access):
        started, observed = time.monotonic(), int(time.time())
        try:
            access = access()
            if not isinstance(access, dict):
                raise ValueError('invalid access response')
        except (OSError, ValueError, TypeError):
            result = record('zap', ZAP_VERSION, ['scoped', '--engine-discoveries'],
                started, observed, [], json.dumps({'phase': 'engine_discoveries',
                    'state': 'blocked', 'reason': 'access_state_unavailable',
                    'contexts': [], 'gaps': ['follow_up_access_unavailable']}),
                0, 'incomplete')
            emit(result)
            return result

    def seed(identifier):
        if type(identifier) is not int or identifier <= 0:
            return None
        try:
            item = json.loads((directory / 'http-evidence' / f'{identifier}.json').read_text())
            url = item.get('url', '')
            parsed = urlsplit(url)
            if (item.get('id') != identifier or item.get('method') != 'GET'
                    or item.get('login') or item.get('error') or item.get('status') != 200
                    or not any(allowed(origin, url) for origin in scope['origins'])
                    or 'redact' in url.lower() or len(url) > 2048):
                return None
            account = item.get('account', 'testing') if item.get('authenticated') else None
            names = tuple(sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=32)}))
            key = (account, parsed.scheme, parsed.netloc, parsed.path, names)
            return key, url
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    scanned = {value[0] for run in records if run.get('tool') == 'zap'
               for identifier in run.get('evidence_ids', []) if (value := seed(identifier))}
    verified = {None}
    if access.get('verified') and not access.get('accounts'):
        verified.add('testing')
    verified.update(account['account'] for account in access.get('accounts', [])
                    if account.get('verified') and account.get('account') in ('testing', 'reference'))
    selected = {}
    sources = []
    candidates = [(identifier, value) for identifier in engine.get('evidence_ids', [])
                  if (value := seed(identifier)) is not None]
    # Give input-bearing URLs priority over passive-only pages within the cap.
    candidates.sort(key=lambda candidate: not bool(urlsplit(candidate[1][1]).query))
    for identifier, value in candidates:
        key, url = value
        account = key[0]
        if key in scanned or account not in verified:
            continue
        urls = selected.setdefault(account, [])
        if len(urls) >= 4:
            continue
        scanned.add(key)
        urls.append(url)
        sources.append(identifier)

    started, observed = time.monotonic(), int(time.time())
    refs, contexts, gaps = [], [], []
    for account, urls in selected.items():
        if deadline - time.monotonic() < 45:
            gaps.append('follow_up_time_unavailable')
            break
        # Discovery has ended. Use the ordinary broker route, keeping the
        # engine's stopped route closed and preserving final-report time.
        client = Requests(scope, min(deadline, time.monotonic() + 100), fetch,
                          account, limit=48, discovery=False)
        try:
            detail = zap(client, urls)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            detail = {'state': 'blocked', 'reason': scanner_failure_reason(error)}
            client.gaps.append('scanner_execution_incomplete')
        refs.extend(e['id'] for e in client.records)
        gaps.extend(client.gaps)
        contexts.append({'account': account or 'anonymous', 'result': detail,
                         'requests': len(client.records), 'gaps': sorted(set(client.gaps))})
    detail = {'phase': 'engine_discoveries', 'source_evidence_ids': sources,
              'contexts': contexts, 'gaps': sorted(set(gaps))}
    if not selected:
        detail.update(state='inapplicable', reason='no_new_recorded_get_inputs')
    result = record('zap', ZAP_VERSION, ['scoped', '--engine-discoveries', '--max-requests-per-context', '48'],
                    started, observed, refs, json.dumps(detail), 0, 'incomplete' if gaps else None)
    emit(result)
    return result
