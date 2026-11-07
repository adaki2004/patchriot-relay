"""No provider credentials or public targets. The image smoke test is opt-in."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
from pathlib import Path
import tempfile
import threading
import time
import unittest
import subprocess
from concurrent.futures import ThreadPoolExecutor
import urllib.error
from types import SimpleNamespace
from unittest.mock import patch

import artex
from web_tools import ScopeMirror


SCOPE = {'origins': ['https://owned.example'], 'objective': 'Owned fixture only',
         'methods': ['GET', 'HEAD', 'OPTIONS'], 'tools': ['artex_engine_v1']}


class EngineTests(unittest.TestCase):
    def test_combined_investigation_uses_one_engine_and_two_isolated_contexts(self):
        from urllib.request import urlopen
        for use_private in (True, False):
            starts, calls = [], []
            def fetch(authenticated):
                def request(method, url, headers=None, **kwargs):
                    calls.append((authenticated, url))
                    return {'evidence': {'id': len(calls), 'status': 200 if authenticated else 401},
                            'body': 'private fixture' if authenticated else 'denied'}
                return request
            class FakeEngine:
                def __init__(self, *_): starts.append(1)
                def __enter__(self): return self
                def __exit__(self, *_): pass
                def assess(self, scope, targets, role, **kwargs):
                    for target in targets:
                        try: urlopen(target + '/private').read()
                        except urllib.error.HTTPError: pass
                    if use_private:
                        for target in scope['_authenticated_targets'].values():
                            urlopen(target + '/private').read()
                    return {'coverage_complete': True, 'stop_reason': 'done', 'findings': []}
            with tempfile.TemporaryDirectory() as folder, patch.object(artex, 'Engine', FakeEngine):
                scope = dict(SCOPE, authentication='session')
                receipt = artex.run(scope, 'investigator', time.monotonic() + 10, Path(folder),
                    fetch=fetch(False), authenticated_fetch=fetch(True),
                    access={'verified': True, 'protected_url': 'https://owned.example/private'})
                result = json.loads((Path(folder) / 'artex-results.json').read_text())
            self.assertEqual(starts, [1])
            self.assertEqual(result['access_mode'], 'anonymous_and_authenticated')
            self.assertEqual(result['anonymous_evidence_count'], 1)
            self.assertEqual(result['authenticated_evidence_count'], int(use_private))
            self.assertEqual(result['coverage_complete'], use_private)
            self.assertEqual(receipt['evidence_ids'], [1, 2] if use_private else [1])
            self.assertEqual(calls[0], (False, 'https://owned.example/private'))
            if use_private:
                self.assertEqual(calls[1], (True, 'https://owned.example/private'))

    def test_planner_gets_numeric_budget_finish_reserve_and_neutral_identity(self):
        body = artex.task_body(SCOPE, ['http://127.0.0.1:1234'], 1800, 'investigator',
                               {'engine_http_remaining': 1457, 'engine_model_calls_remaining': 400})
        self.assertIn('1457', body['goal'])
        self.assertIn('1800 seconds', body['goal'])
        self.assertIn('final 10 percent', body['goal'])
        self.assertIn('security-test@example.com', body['goal'])
        self.assertIn('at most one successful test per endpoint', body['goal'])
        self.assertNotIn('artex.test@', body['goal'])

    def test_oversized_engine_details_leave_a_complete_handoff_and_exact_local_file(self):
        details = {'engine': 'ARTEX', 'commit': artex.VERSION,
                   'stop_reason': 'time_budget', 'coverage_complete': False,
                   'failure': 'incomplete', 'target_mapping': {'https://owned.example': 'http://127.0.0.1:1234'},
                   'outcome': {str(i): {str(j): '🛡' * 500 for j in range(10)} for i in range(10)},
                   'findings': [{'summary': 'Owned unverified lead', 'details': 'x' * 40000}],
                   'commands': {'commands': [{'command': 'long command ' * 10000}]}}
        class FakeEngine:
            def __init__(self, *_args): pass
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def assess(self, *_args, **_kwargs): return details.copy()
        with tempfile.TemporaryDirectory() as folder, patch.object(artex, 'Engine', FakeEngine):
            receipt = artex.run(SCOPE, 'investigator', time.monotonic() + 2, Path(folder))
            saved = (Path(folder) / 'artex-results.json').read_text()
            self.assertEqual(json.loads(saved)['commands'], details['commands'])
            self.assertGreater(len(saved), 24 * 1024)
            self.assertFalse(receipt['output_truncated'])
            summary = json.loads(receipt['output_excerpt'])
            self.assertEqual(summary['stop_reason'], 'time_budget')
            self.assertEqual(summary['full_output_sha256'], hashlib.sha256(saved.encode()).hexdigest())
            self.assertEqual(summary['commands_returned'], 1)
            self.assertTrue(summary['details_summarized'])
            self.assertFalse(summary['coverage_complete'])
            self.assertEqual(receipt['failure'], 'incomplete')
            self.assertEqual(receipt['output_sha256'], hashlib.sha256(receipt['output_excerpt'].encode()).hexdigest())

    def test_exhausted_upstream_planner_stops_even_if_task_is_queued(self):
        self.assertTrue(artex.should_stop({'status': 'queued', 'llm_failover_state': 'chain_exhausted'}))
        self.assertTrue(artex.should_stop({'status': 'completed'}))
        self.assertFalse(artex.should_stop({'status': 'running'}))

    def test_missing_engine_and_deadline_are_visible_without_fake_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            record = artex.run(SCOPE, 'investigator', time.monotonic() - 1, path)
            self.assertEqual(record['failure'], 'timeout')
            self.assertEqual(record['evidence_ids'], [])
            self.assertFalse(json.loads((path / 'artex-results.json').read_text())['coverage_complete'])
            self.assertEqual(record['output_sha256'], hashlib.sha256(record['output_excerpt'].encode()).hexdigest())

    def test_partial_report_survives_and_stops_before_the_reviewer(self):
        models = []
        class FakeEngine:
            def __init__(self, _directory, _bridge, _deadline, model): models.append(model)
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def assess(self, scope, targets, role, stop=lambda: False, progress=lambda: 0):
                return {'engine': 'ARTEX', 'commit': artex.VERSION, 'stop_reason': 'model_budget',
                        'coverage_complete': False, 'findings': [], 'commands': []}
        with tempfile.TemporaryDirectory() as temp, patch.object(artex, 'Engine', FakeEngine):
            starts = []
            record = artex.run(SCOPE, 'investigator', time.monotonic() + 2, Path(temp), model='abliteration-abliterated-model-large-v2', emit=starts.append)
            self.assertEqual(len(starts), 1)
            self.assertEqual(starts[0]['failure'], 'incomplete')
            self.assertEqual(starts[0]['started_at'], record['started_at'])
            self.assertEqual(models, ['abliteration-abliterated-model-large-v2'])
            self.assertEqual(record['failure'], 'incomplete')
            self.assertEqual(record['exit_code'], 0)
            self.assertEqual(record['arguments'], ['/opt/artex/artex', 'https://owned.example'])
            self.assertEqual(json.loads(record['output_excerpt'])['stop_reason'], 'model_budget')

    def test_bridge_rejection_stops_discovery_without_waiting_for_the_deadline(self):
        calls = []
        class FakeClient:
            def call(self, path, body=None):
                calls.append((path, body))
                if path == '/api/tasks': return {'id': 7}
                if path == '/api/tasks/7': return {'status': 'running'}
                return {}
        engine = object.__new__(artex.Engine)
        engine.client, engine.deadline, engine.profile_id = FakeClient(), time.monotonic() + 600, 1
        result = engine.assess(SCOPE, ['http://127.0.0.1:1234'], 'investigator', stop=lambda: True)
        self.assertEqual(result['stop_reason'], 'model_request_rejected')
        self.assertFalse(result['coverage_complete'])
        self.assertIn(('/api/tasks/7/control', {'action': 'pause'}), calls)
        result = engine.assess(SCOPE, ['http://127.0.0.1:1234'], 'investigator',
                               stop=lambda: 'target_request_budget')
        self.assertEqual(result['stop_reason'], 'target_request_budget')
        self.assertFalse(result['coverage_complete'])

    def test_watchdog_ignores_heartbeats_preserves_leads_and_yields_to_completion(self):
        # A fake clock exercises the fifteen-minute wait without sleeping. A new
        # observation at minute fourteen extends it; task heartbeats alone do not.
        for progress_at, completed_at, expected_time, expected_reason in [
            (None, None, 900, 'no_engine_progress'),
            (840, None, 1740, 'no_engine_progress'),
            (None, 900, 900, 'completed'),
        ]:
            with self.subTest(progress_at=progress_at, completed_at=completed_at), tempfile.TemporaryDirectory() as temp:
                clock, calls = [0.0], []
                class FakeClient:
                    def call(self, path, body=None):
                        calls.append((path, body))
                        if path == '/api/tasks': return {'id': 7}
                        if path == '/api/tasks/7':
                            return {'status': 'completed' if completed_at is not None and clock[0] >= completed_at else 'running',
                                    'heartbeat': clock[0]}
                        if path.startswith('/api/exploration/findings'):
                            return [{'title': 'Owned fixture lead', 'verified': False}]
                        return {}
                def tick(_seconds): clock[0] += 60
                engine = object.__new__(artex.Engine)
                engine.client, engine.deadline, engine.profile_id = FakeClient(), 2700, 1
                engine.directory, engine.process = Path(temp), SimpleNamespace(poll=lambda: None)
                (engine.directory / 'process.log').write_text('')
                with patch.object(artex.time, 'monotonic', lambda: clock[0]), patch.object(artex.time, 'sleep', tick):
                    result = engine.assess(SCOPE, ['http://127.0.0.1:1234'], 'investigator',
                        progress=lambda: int(progress_at is not None and clock[0] >= progress_at))
                self.assertEqual(clock[0], expected_time)
                self.assertEqual(result['stop_reason'], expected_reason)
                self.assertEqual(result['coverage_complete'], completed_at is not None)
                self.assertEqual(result['findings'], [{'title': 'Owned fixture lead', 'verified': False}])
                self.assertEqual(('/api/tasks/7/control', {'action':'pause'}) in calls, completed_at is None)

    def test_offline_analysis_extends_watchdog_but_repeats_and_errors_do_not(self):
        for mode, expected_time, reason in [('analysis', 2100, 'done'),
                                            ('repeated', 1140, 'no_engine_progress'),
                                            ('error', 900, 'no_engine_progress')]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                clock = [0.0]
                class FakeClient:
                    def call(self, path, body=None):
                        if path == '/api/tasks': return {'id': 7}
                        if path == '/api/tasks/7':
                            return {'status': 'done' if clock[0] >= 2100 else 'running'}
                        if path.startswith('/api/commands'):
                            batch = int(clock[0] // 240) if mode == 'analysis' else 1
                            return {'commands': [] if clock[0] < 240 else [{
                                'id': clock[0], 'tool': 'Bash', 'command': 'inspect saved application files',
                                'output': 'analysis of file ' + str(batch), 'is_error': mode == 'error'}]}
                        return {}
                def tick(_seconds): clock[0] += 30
                engine = object.__new__(artex.Engine)
                engine.client, engine.deadline, engine.profile_id = FakeClient(), 2700, 1
                engine.directory, engine.process = Path(temp), SimpleNamespace(poll=lambda: None)
                (engine.directory / 'process.log').write_text('')
                with patch.object(artex.time, 'monotonic', lambda: clock[0]), patch.object(artex.time, 'sleep', tick):
                    result = engine.assess(SCOPE, ['http://127.0.0.1:1234'], 'investigator')
                self.assertEqual(clock[0], expected_time)
                self.assertEqual(result['stop_reason'], reason)
                self.assertEqual(result['distinct_target_observations'], 0)
                self.assertEqual(result['seconds_without_target_progress'], expected_time)
                self.assertEqual(result['coverage_complete'], mode == 'analysis')
        self.assertEqual(artex.command_observations({'commands': None}), set())

    def test_upstream_can_settle_before_hard_cutoff_without_upgrading_timeout(self):
        for terminal in ['done', 'timeout', None]:
            with self.subTest(terminal=terminal), tempfile.TemporaryDirectory() as temp:
                clock, calls, timeout = [0.0], [], []
                class FakeClient:
                    def call(self, path, body=None):
                        calls.append((path, body))
                        if path == '/api/tasks':
                            timeout.append(body['timeout_seconds'])
                            # Delayed startup plus a two-minute settlement pass.
                            clock[0] += 45
                            return {'id': 7}
                        if path == '/api/tasks/7':
                            settled = clock[0] >= 45 + timeout[0] + 120
                            return {'status': terminal if terminal and settled else 'running'}
                        return {}
                def tick(_seconds): clock[0] += 15
                engine = object.__new__(artex.Engine)
                engine.client, engine.deadline, engine.profile_id = FakeClient(), 1800, 1
                engine.directory, engine.process = Path(temp), SimpleNamespace(poll=lambda: None)
                (engine.directory / 'process.log').write_text('')
                with patch.object(artex.time, 'monotonic', lambda: clock[0]), patch.object(artex.time, 'sleep', tick):
                    result = engine.assess(SCOPE, ['http://127.0.0.1:1234'], 'investigator',
                                           progress=lambda: int(clock[0]))
                self.assertEqual(timeout, [1500])
                self.assertEqual(engine.deadline, 1800)
                self.assertEqual(result['stop_reason'], terminal or 'time_budget')
                self.assertEqual(result['coverage_complete'], terminal == 'done')
                self.assertEqual(clock[0], 1665 if terminal else 1800)
                self.assertEqual(('/api/tasks/7/control', {'action': 'pause'}) in calls, terminal is None)

    def test_late_collection_failure_preserves_outcome_and_other_findings(self):
        for failed in ['commands', 'findings', 'outcome']:
            with self.subTest(failed=failed):
                class FakeClient:
                    def call(self, path, body=None):
                        if path == '/api/tasks':
                            return {'id': 7}
                        if path == '/api/tasks/7':
                            return {'status': 'done'}
                        if failed in path:
                            raise ValueError('engine API response exceeds limit')
                        return {'saved': path}
                engine = object.__new__(artex.Engine)
                engine.client = FakeClient()
                engine.deadline = time.monotonic() + 600
                engine.profile_id = 1
                result = engine.assess(SCOPE, ['http://127.0.0.1:1234'], 'investigator')
                self.assertEqual(result['stop_reason'], 'done')
                self.assertEqual(result['collection_errors'], [failed])
                self.assertEqual(result['coverage_complete'], failed == 'commands')
                for key in ['commands', 'findings', 'outcome']:
                    self.assertEqual('saved' in result[key], key != failed)
                summary = json.loads(artex.receipt_summary(result, json.dumps(result)))
                self.assertEqual(summary['collection_errors'], [failed])

    def test_engine_usage_comes_from_broker_counter_differences(self):
        class FakeEngine:
            def __init__(self, *_args): pass
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def assess(self, *_args, **_kwargs):
                return {'engine': 'ARTEX', 'commit': artex.VERSION,
                        'coverage_complete': True, 'stop_reason': 'done'}
        before = {'http_remaining': 9000, 'model_calls_remaining': 2100,
                  'remaining_cost_allowance_microusd': 29000000}
        after = {'http_remaining': 8700, 'model_calls_remaining': 2010,
                 'remaining_cost_allowance_microusd': 27900000}
        for final in [after, {}, {**after, 'model_calls_remaining': 2200}]:
            with self.subTest(final=final), tempfile.TemporaryDirectory() as temp, \
                    patch.object(artex, 'Engine', FakeEngine), \
                    patch('report_finish.bridge', side_effect=[before.copy(), final.copy()]):
                receipt = artex.run(SCOPE, 'investigator', time.monotonic()+600, Path(temp))
                summary = json.loads(receipt['output_excerpt'])
                saved = json.loads((Path(temp)/'artex-results.json').read_text())
                if final == after:
                    expected = {'http_requests': 300, 'inference_calls': 90,
                                'cost_upper_microusd': 1100000}
                    self.assertEqual(summary['usage'], expected)
                    self.assertEqual(saved['usage'], expected)
                else:
                    self.assertNotIn('usage', summary)
                    self.assertNotIn('usage', saved)

    def test_engine_http_uses_the_discovery_route_and_other_probes_keep_their_route(self):
        import live_http
        seen = []
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, _limit): return b'{"evidence":{"status":200}}'
        def capture(request, **kwargs):
            seen.append(request.full_url)
            return Reply()
        with patch.dict(os.environ, {'PATCHRIOT_BRIDGE_URL':'http://127.0.0.1:8080'}), patch.object(live_http, 'urlopen', capture):
            live_http.request('GET', 'https://owned.example', discovery=True)
            live_http.request('GET', 'https://owned.example')
        self.assertEqual(seen, ['http://127.0.0.1:8080/patchriot/artex/http',
                                'http://127.0.0.1:8080/patchriot/http'])

    def test_engine_cannot_point_its_model_bridge_outside_container_loopback(self):
        for url in ['https://external.example', 'http://127.0.0.1:8/path', 'http://user@127.0.0.1:8',
                    'http://127.0.0.1:8?other=1', 'http://[::1]:8']:
            with self.assertRaises(ValueError):
                artex.Engine(Path('/unused'), url, time.monotonic() + 1).__enter__()


@unittest.skipUnless(os.environ.get('PATCHRIOT_ENGINE_SMOKE') == '1', 'requires the isolated agent image')
class ImageSmoke(unittest.TestCase):
    def test_real_engine_uses_mock_provider_and_owned_mirror_then_cleans_up(self):
        """Exercise the real planner/tools/database, not a fake engine class.

        Run in a network=none, non-root container with disposable /work. The
        scripted model is only an integration fixture, not a quality evaluation.
        """
        requested, seen_tools, calls = [], [], []
        def fixture(method, url, headers):
            requested.append((method, url))
            return {'body': 'OWNED FIXTURE RESPONSE', 'evidence': {'id': len(requested), 'status': 200,
                    'headers': {'content-type': 'text/plain'}}}

        class Model(BaseHTTPRequestHandler):
            plans = workers = 0
            def log_message(self, *_): pass
            def do_POST(self):
                self.close_connection = True
                length = int(self.headers.get('Content-Length', '0'))
                if length > 512 * 1024:
                    return self.send_error(413)
                body = json.loads(self.rfile.read(length))
                calls.append(self.path)
                names = [t['function']['name'] for t in body.get('tools', [])]
                seen_tools.extend(names)
                name, args = None, None
                if 'set_goals' in names:
                    type(self).plans += 1
                    if self.plans == 1:
                        name, args = 'set_goals', {'text': 'Read the owned fixture once and record the observed response.'}
                elif 'Bash' in names:
                    type(self).workers += 1
                    if self.workers == 1:
                        name, args = 'Bash', {'command': 'curl --max-time 2 -s ' + mirror.url + '/'}
                    elif self.workers == 2:
                        name, args = 'report_finding', {'vulnclass': 'fixture', 'severity': 'low',
                            'summary': 'Owned integration example, not a real vulnerability', 'evidence': 'OWNED FIXTURE RESPONSE'}
                    else:
                        self.send_response(429)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(b'{"error":"owned_smoke_budget"}')
                        return
                message = {'role': 'assistant', 'content': 'Owned fixture plan recorded.'}
                if name:
                    message['content'] = None
                    message['tool_calls'] = [{'id': 'call_' + str(len(calls)), 'type': 'function',
                        'function': {'name': name, 'arguments': json.dumps(args)}}]
                output = json.dumps({'id': 'owned-smoke', 'object': 'chat.completion', 'model': artex.MODEL,
                    'choices': [{'index': 0, 'message': message, 'finish_reason': 'tool_calls' if name else 'stop'}],
                    'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(output)))
                self.end_headers()
                self.wfile.write(output)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Model)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 30
            with ScopeMirror(SCOPE['origins'][0], deadline, fixture) as mirror:
                with artex.Engine(Path('/work/artex-state'), f'http://127.0.0.1:{server.server_port}', deadline) as engine:
                    # Check the shipped process boundary, not the engine's own
                    # tool approvals or target blacklist. No external target is
                    # contacted: the isolated namespace has only loopback.
                    self.assertNotEqual(os.getuid(), 0)
                    self.assertEqual({name for _, name in socket.if_nameindex()}, {'lo'})
                    status = Path('/proc/self/status').read_text()
                    self.assertRegex(status, r'(?m)^CapEff:\s+0+$')
                    self.assertRegex(status, r'(?m)^NoNewPrivs:\s+1$')
                    self.assertFalse(os.access('/opt/artex/artex', os.W_OK))
                    with socket.socket() as proxy:
                        proxy.settimeout(1)
                        self.assertNotEqual(proxy.connect_ex(('127.0.0.1', 8788)), 0,
                                            'The upstream recording proxy must stay disabled')
                    outcome = engine.assess(SCOPE, [mirror.url], 'investigator')
                    # Exercise shipped auth handlers without a connection flood,
                    # shell payload or an external target.
                    public = artex.Client()
                    self.assertTrue(public.call('/api/auth/status')['initialized'])
                    with self.assertRaises(urllib.error.HTTPError) as denied:
                        public.call('/api/auth/init', {'password': 'fixture-cannot-replace-admin'})
                    self.assertEqual(denied.exception.code, 403)
                    sql = [artex.POSTGRES + 'psql', '-h', '127.0.0.1', '-p', '15432',
                           '-U', 'patchriot', '-d', 'patchriot', '-v', 'ON_ERROR_STOP=1', '-c']
                    subprocess.run(sql + ['ALTER TABLE settings RENAME TO unavailable_settings'],
                                   check=True, capture_output=True, timeout=5)
                    try:
                        for path, body in [('/api/auth/status', None),
                                           ('/api/auth/init', {'password': 'fixture-cannot-replace-admin'}),
                                           ('/api/auth/login', {'username': 'ARTEX', 'password': 'fixture-invalid-login'})]:
                            with self.subTest(database_unavailable=path):
                                with self.assertRaises(urllib.error.HTTPError) as unavailable:
                                    public.call(path, body)
                                self.assertEqual(unavailable.exception.code, 503)
                    finally:
                        subprocess.run(sql + ['ALTER TABLE unavailable_settings RENAME TO settings'],
                                       check=True, capture_output=True, timeout=5)
                    self.assertTrue(public.call('/api/auth/status')['initialized'])
                    with self.assertRaises(urllib.error.HTTPError) as still_denied:
                        public.call('/api/auth/init', {'password': 'fixture-cannot-replace-admin'})
                    self.assertEqual(still_denied.exception.code, 403)
                    # Only this disposable fixture database: two initializers
                    # must not both obtain admin access or replace the winner.
                    subprocess.run(sql + ["DELETE FROM settings WHERE key='auth.password_hash'"],
                                   check=True, capture_output=True, timeout=5)
                    self.assertFalse(public.call('/api/auth/status')['initialized'])
                    barrier = threading.Barrier(2)
                    def initialize(number):
                        barrier.wait(timeout=5)
                        try:
                            public.call('/api/auth/init', {'password': 'fixture-race-password-' + str(number)})
                            return number, 200
                        except urllib.error.HTTPError as error:
                            return number, error.code
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        attempts = list(pool.map(initialize, (1, 2)))
                    self.assertEqual(sum(status == 200 for _, status in attempts), 1)
                    self.assertTrue(all(status in (200, 403, 409) for _, status in attempts))
                    for number, status in attempts:
                        login = {'username': 'ARTEX', 'password': 'fixture-race-password-' + str(number)}
                        if status == 200:
                            self.assertTrue(public.call('/api/auth/login', login)['token'])
                        else:
                            with self.assertRaises(urllib.error.HTTPError) as loser:
                                public.call('/api/auth/login', login)
                            self.assertEqual(loser.exception.code, 401)
                self.assertIsNotNone(engine.process.poll(), 'engine process must be stopped')
                self.assertIsNotNone(engine.pg.poll(), 'database process must be stopped')
            self.assertIn(('GET', 'https://owned.example/'), requested)
            self.assertIn('set_goals', seen_tools)
            self.assertIn('Bash', seen_tools)
            self.assertTrue(all(p == '/patchriot/artex/v1/chat/completions' for p in calls))
            self.assertFalse(outcome['coverage_complete'])
            self.assertIn(outcome['stop_reason'], ('time_budget', 'model_budget'))
            self.assertEqual(outcome['engine'], 'ARTEX')
            self.assertTrue(outcome['commands']['commands'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
