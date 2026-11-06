"""Owned HTTP fixtures only. No provider key or target network is used."""
import hashlib
import http.client
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import URLError

import web_tools as tools
import live_http
import ares_web


class WebToolsTests(unittest.TestCase):
    def test_new_evidence_ids_and_repeated_replies_do_not_fake_target_progress(self):
        calls = []
        def fixture(method, url, headers, **kwargs):
            calls.append(url)
            if url.endswith('/unavailable'): return {'error':'request_error'}
            return {'body':'changed' if len(calls) == 3 else 'same',
                    'evidence':{'id':len(calls), 'status':200, 'headers':{'x-request-id':str(len(calls))}}}
        with tools.ScopeMirror('https://owned.example', time.monotonic()+5, fixture) as mirror:
            for path, expected in [('/',1),('/',1),('/',2),('/other',3),('/unavailable',3)]:
                client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
                client.request('GET', path)
                response = client.getresponse(); response.read(); client.close()
                self.assertEqual(len(mirror.progress_keys), expected)
            self.assertEqual(mirror.refs, [1,2,3,4], 'Repeated evidence must remain available to the reviewer')

    def test_discovery_keeps_exact_redacted_records_after_the_http_budget_is_used(self):
        records = [
            {'id':25, 'method':'GET', 'url':'https://owned.example/private', 'status':401,
             'body_excerpt':'Sign in required', 'headers':{}, 'truncated':False},
            {'id':26, 'method':'GET', 'url':'https://owned.example/public', 'status':200,
             'body_excerpt':'Public content', 'headers':{}, 'truncated':True},
        ]
        replies = [io.BytesIO(json.dumps({'evidence':r, 'body':'full response not for the cache'}).encode()) for r in records]
        from urllib.error import HTTPError
        exhausted = HTTPError('http://bridge/patchriot/artex/http', 429, 'budget', {},
                              io.BytesIO(b'{"error":"engine_http_budget_reached"}'))
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(live_http, 'EVIDENCE_DIRECTORY', Path(temp) / 'http-evidence'), \
                patch.dict('os.environ', {'PATCHRIOT_BRIDGE_URL':'http://bridge'}), \
                patch.object(live_http, 'urlopen', side_effect=[*replies, exhausted]) as upstream:
            from functools import partial
            with tools.ScopeMirror('https://owned.example', time.monotonic()+5,
                                   partial(live_http.request, discovery=True)) as mirror:
                for path, status in [('/private',401),('/public',200),('/third',502)]:
                    client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
                    client.request('GET', path)
                    response = client.getresponse()
                    self.assertEqual(response.status, status)
                    response.read(); client.close()
                self.assertEqual(mirror.refs, [25,26])
            for record in records:
                saved = Path(temp) / 'http-evidence' / f"{record['id']}.json"
                self.assertEqual(json.loads(saved.read_text()), record)
                self.assertNotIn('full response not for the cache', saved.read_text())
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            self.assertEqual(upstream.call_count, 3)
            self.assertEqual(len(list((Path(temp) / 'http-evidence').iterdir())), 2)

    def test_unavailable_working_cache_keeps_the_broker_response_and_reports_the_gap(self):
        reply = {'evidence':{'id':7,'status':200}, 'body':'observed'}
        with patch.object(Path, 'mkdir', side_effect=OSError('fixture unavailable')):
            self.assertEqual(live_http.retain_evidence(reply), {
                'evidence':{'id':7,'status':200}, 'body':'observed',
                'evidence_cache_error':'unavailable'})
        self.assertNotIn('evidence_file', reply)
        for value in ('../outside', True, 0):
            self.assertEqual(live_http.retain_evidence({'evidence':{'id':value}}), {'evidence':{'id':value}})

    def test_links_stay_on_exact_origin_and_forms_are_only_recorded(self):
        parser = tools.Links('https://owned.example/', 'https://owned.example')
        parser.feed('''<a href="/docs#part">ok</a><script src="//other.example/app.js"></script>
        <a href="https://owned.example@other.example/">no</a><a href="javascript:alert(1)">no</a>
        <form method="POST" action="/delete"><input name="token"></form>''')
        self.assertEqual(parser.links, ['https://owned.example/docs'])
        self.assertFalse(parser.forms[0]['executed'])
        for url in ['https://owned.example:444/', 'https://127.0.0.1/', 'https://owned.example/\\bad',
                    'http://owned.example/', 'https://owned.example/\nnext', '//other.example/']:
            self.assertFalse(tools.allowed('https://owned.example', url), url)

    def fixture(self, method, url, headers=None, **_):
        self.requests.append((method, url, headers or {}))
        number = len(self.requests)
        return {'body':'<a href="/docs">Docs</a><a href="https://external.example/">Elsewhere</a>',
                'evidence':{'id':number, 'status':200, 'headers':{'content-type':'text/html'},
                            'body_sha256':'a' * 64}}

    def setUp(self):
        self.requests = []

    def test_crawl_bounds_requests_and_retains_actual_ids(self):
        record = tools.crawl('https://owned.example', time.monotonic() + 3, self.fixture)
        self.assertLessEqual(len(self.requests), tools.MAX_PAGES)
        self.assertTrue(all(r[1].startswith('https://owned.example/') for r in self.requests))
        self.assertEqual(record['evidence_ids'], list(range(1, len(self.requests) + 1)))
        self.assertEqual(record['exit_code'], 0)

    def test_transport_failure_is_not_successful_empty_coverage(self):
        def failed(*_):
            raise URLError('private details not for reports')
        run = tools.crawl('https://owned.example', time.monotonic() + 2, failed)
        self.assertEqual(run['failure'], 'request_error')
        self.assertNotEqual(run['exit_code'], 0)
        self.assertNotIn('private details', run['output_excerpt'])
        self.assertEqual(run['evidence_ids'], [])

    def test_scanner_mirror_cannot_tunnel_or_change_methods_or_hosts(self):
        with tools.ScopeMirror('https://owned.example', time.monotonic() + 5, self.fixture) as mirror:
            def req(method, path, headers=None):
                client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
                client.request(method, path, headers=headers or {})
                response = client.getresponse()
                response.read()
                client.close()
                return response.status
            self.assertEqual(req('GET', '/.git/config', {'Origin':'https://patchriot.invalid'}), 200)
            self.assertEqual(self.requests[0], ('GET','https://owned.example/.git/config', {'Origin':'https://patchriot.invalid'}))
            for method, path, headers in [
                ('CONNECT', 'internal:443', {}), ('POST', '/update', {}),
                ('GET', 'https://other.example/', {}), ('GET', '//other.example/', {}),
                ('GET', '/', {'Host':'other.example'}), ('GET', '/', {'Content-Length':'1'}),
            ]:
                self.assertGreaterEqual(req(method, path, headers), 400)
            self.assertEqual(len(self.requests), 1)
            self.assertEqual(mirror.refs, [1])

    def test_active_mirror_forwards_only_bounded_approved_bodies_and_same_origin_redirects(self):
        requests = []
        def fixture(method, url, headers=None, **kwargs):
            requests.append((method, url, kwargs))
            return {"body": "fixture", "evidence": {"id": 1, "status": 302, "headers": {"location": "https://owned.example/next"}}}
        with tools.ScopeMirror('https://owned.example', time.monotonic()+5, fixture, methods=['GET','POST']) as mirror:
            def post(body, content='application/json'):
                client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
                client.request('POST', '/test', body, {'Content-Type': content})
                reply = client.getresponse(); result = reply.status, reply.getheader('Location')
                reply.read(); client.close(); return result
            self.assertEqual(post('{"fixture":true}'), (302, '/next'))
            self.assertEqual(requests[0], ('POST', 'https://owned.example/test', {'data':'{"fixture":true}'}))
            self.assertEqual(post('x' * 16385)[0], 400)
            self.assertEqual(post('file upload', 'multipart/form-data')[0], 415)
            self.assertEqual(len(requests), 1)

    def test_broker_failure_does_not_look_like_a_success_to_scanner(self):
        with tools.ScopeMirror('https://owned.example', time.monotonic() + 5,
                               lambda *_: {'error':'scope_denied'}) as mirror:
            client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
            client.request('GET', '/')
            response = client.getresponse()
            self.assertEqual(response.status, 502)
            response.read()
            client.close()
            self.assertEqual(mirror.refs, [])

    def test_controls_replay_only_approved_cited_gets(self):
        prior = [{'assessment': {'findings':[{'evidence_ids':[1,2,3]}]}, 'evidence':[
            {'id':1, 'method':'GET', 'url':'https://owned.example/check', 'request_headers':{'Origin':'null'}},
            {'id':2, 'method':'GET', 'url':'https://elsewhere.example/private'},
            {'id':3, 'method':'POST', 'url':'https://owned.example/update'}]}]
        record = tools.controls('https://owned.example', time.monotonic() + 3, prior, self.fixture)
        self.assertEqual(len(self.requests), 4)
        self.assertEqual(self.requests[-1], ('GET','https://owned.example/check', {'Origin':'null'}))
        self.assertEqual(record['evidence_ids'], [1,2,3,4])

    def test_followups_do_not_repeat_scanners_or_lose_fresh_control_evidence(self):
        scope = {'origins': ['https://owned.example'], 'methods': ['GET', 'HEAD', 'OPTIONS']}
        previous = [{'role':'investigator', 'tool_runs':[
            {'tool':name, 'exit_code':0, 'failure':None}
            for name in ['patchriot-baseline','patchriot-crawl','nuclei','ares-web-surface']]}]
        for role in ['investigator', 'reproducer', 'challenger']:
            with tempfile.TemporaryDirectory() as temp, patch('baseline.run', return_value={'tool': 'baseline'}) as baseline, \
                    patch.object(tools, 'crawl', return_value={'tool': 'crawl'}) as crawl, \
                    patch.object(ares_web, 'run', return_value={'tool':'ares-web-surface'}) as surface, \
                    patch.object(tools, 'scanner', return_value={'tool': 'nuclei'}) as scanner, \
                    patch.object(tools, 'controls', return_value={'tool': 'controls'}) as controls:
                emitted = []
                result = tools.run(scope, previous, Path(temp), emitted.append, role=role)
                self.assertEqual(result['tool_runs'], emitted)
                self.assertEqual(controls.call_count, 1)
                for tool in (baseline, crawl, scanner, surface):
                    self.assertEqual(tool.call_count, int(role == 'investigator'))
                self.assertEqual(json.loads((Path(temp) / 'tool-results.json').read_text())['role'], role)

    def test_repeated_prior_claims_do_not_duplicate_requests_or_lose_auth_controls(self):
        calls = []
        def fetch(method, url, headers=None, authenticated=True):
            calls.append((url, authenticated))
            return {'evidence': {'id': len(calls), 'status': 200}}
        prior = {'assessment': {'findings': [{'evidence_ids': [1]}]}, 'evidence': [
            {'id': 1, 'method': 'GET', 'url': 'https://owned.example/private', 'authenticated': True}]}
        result = tools.controls('https://owned.example', time.monotonic() + 5, [prior, prior], fetch, '/private')
        self.assertEqual(calls.count(('https://owned.example/private', True)), 1)
        self.assertEqual(calls.count(('https://owned.example/private', False)), 1)
        self.assertEqual(len(calls), 5)
        self.assertEqual(result['evidence_ids'], [1, 2, 3, 4, 5])

    def test_subprocess_timeout_and_output_limit(self):
        timed = tools.capture([sys.executable, '-c', 'import time; time.sleep(3)'], timeout=.1)
        self.assertEqual(timed['failure'], 'timeout')
        self.assertLess(timed['duration_ms'], 1500)
        noisy = tools.capture([sys.executable, '-c', 'print("x" * 50000)'], limit=100)
        self.assertEqual(noisy['failure'], 'output_limit')
        self.assertEqual(len(noisy['output']), 100)

    def test_records_strip_terminal_escapes_and_hash_the_saved_text(self):
        record = tools.record('nuclei', '3.11.1', [], time.monotonic(), 1, [1,1], '\x1b[31mhello\x1b[0m\x00\n')
        self.assertEqual(record['output_excerpt'], 'hello\n')
        self.assertEqual(record['output_sha256'], hashlib.sha256(b'hello\n').hexdigest())
        self.assertEqual(record['evidence_ids'], [1])
        self.assertFalse(record['output_truncated'])
        record = tools.record('nuclei', '3.11.1', [], time.monotonic(), 1, [], 'é' * tools.MAX_OUTPUT)
        self.assertLessEqual(len(record['output_excerpt'].encode()), tools.MAX_OUTPUT)
        self.assertTrue(record['output_truncated'])

    def test_nuclei_is_pinned_to_curated_templates_and_loopback(self):
        calls = []
        def execute(argv, timeout):
            calls.append(argv)
            output = 'Nuclei Engine Version: v3.11.1' if '-version' in argv else ''
            return {'exit_code':0,'output':output,'failure':None,'duration_ms':1}
        record = tools.scanner('https://owned.example', time.monotonic() + 5, self.fixture, execute)
        command = calls[1]
        self.assertTrue(command[command.index('-u')+1].startswith('http://127.0.0.1:'))
        self.assertEqual(command[command.index('-t')+1], tools.TEMPLATES)
        self.assertTrue(all(flag in command for flag in ['-duc','-ni','-dr']))
        self.assertEqual(record['version'], '3.11.1')
        self.assertEqual(record['evidence_ids'], [])


if __name__ == '__main__':
    unittest.main()
