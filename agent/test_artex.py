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
from unittest.mock import patch

import artex
from web_tools import ScopeMirror


SCOPE = {'origins': ['https://owned.example'], 'objective': 'Owned fixture only',
         'methods': ['GET', 'HEAD', 'OPTIONS'], 'tools': ['artex_engine_v1']}


class EngineTests(unittest.TestCase):
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
            def assess(self, scope, targets, role):
                return {'engine': 'ARTEX', 'commit': artex.VERSION, 'stop_reason': 'model_budget',
                        'coverage_complete': False, 'findings': [], 'commands': []}
        with tempfile.TemporaryDirectory() as temp, patch.object(artex, 'Engine', FakeEngine):
            record = artex.run(SCOPE, 'investigator', time.monotonic() + 2, Path(temp), model='abliteration-abliterated-model-large-v2')
            self.assertEqual(models, ['abliteration-abliterated-model-large-v2'])
            self.assertEqual(record['failure'], 'incomplete')
            self.assertEqual(record['exit_code'], 0)
            self.assertEqual(record['arguments'], ['/opt/artex/artex', 'https://owned.example'])
            self.assertEqual(json.loads(record['output_excerpt'])['stop_reason'], 'model_budget')

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
