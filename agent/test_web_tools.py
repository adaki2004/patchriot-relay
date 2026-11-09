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
    def test_binary_body_is_unavailable_but_original_broker_evidence_is_preserved(self):
        record = {'id': 91, 'status': 200, 'headers': {
            'content-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'},
            'body_excerpt': 'PK\x03\x04\ufffd', 'body_sha256': 'original-hash'}
        with tempfile.TemporaryDirectory() as folder, patch.object(live_http, 'EVIDENCE_DIRECTORY', Path(folder)):
            result = live_http.text_response({'evidence': record, 'body': 'PK\x03\x04\ufffd'}, 'GET')
            self.assertEqual(result['body'], '')
            self.assertEqual(result['body_unavailable'], 'binary_response_not_supported')
            self.assertEqual(result['evidence'], record)
            self.assertEqual(json.loads((Path(folder) / '91.json').read_text()), record)

    def test_binary_mirror_returns_an_explicit_broker_gap_and_preserves_head_checks(self):
        def fixture(*args, **kwargs):
            return {'body': 'PK\x03\x04\ufffd', 'evidence': {'id': 7, 'status': 200,
                'headers': {'Content-Type': 'application/zip', 'content-disposition': 'attachment; filename=test.zip'},
                'authenticated': True, 'account': 'reference'}}
        with tools.ScopeMirror('https://owned.example', time.monotonic()+5, fixture) as mirror:
            for method in ('GET', 'HEAD'):
                client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
                client.request(method, '/download')
                response = client.getresponse(); body = response.read(); client.close()
                self.assertEqual(response.getheader('X-Patchriot-Evidence-Id'), '7')
                self.assertEqual(response.getheader('X-Patchriot-Authenticated'), 'true')
                if method == 'GET':
                    self.assertEqual(response.status, 502)
                    self.assertEqual(response.getheader('X-Patchriot-Relay-Error'), 'binary_response_not_supported')
                    self.assertEqual(response.getheader('Content-Type'), 'text/plain; charset=utf-8')
                    self.assertIsNone(response.getheader('Content-Disposition'))
                    self.assertNotIn(b'PK', body)
                else:
                    self.assertEqual(response.status, 200)
                    self.assertIsNone(response.getheader('X-Patchriot-Relay-Error'))
                    self.assertEqual(response.getheader('Content-Type'), 'application/zip')

    def test_text_json_xml_and_svg_are_not_mistaken_for_binary_downloads(self):
        for media, body in [('text/html', '<h1>hello</h1>'), ('application/javascript', 'const x=1;'),
                            ('application/vnd.api+json', '{"ok":true}'), ('application/problem+json', '{}'),
                            ('application/soap+xml', '<xml/>'), ('image/svg+xml', '<svg/>'),
                            ('application/octet-stream', '[core]\nrepositoryformatversion = 0\n'),
                            ('application/octet-stream', '{"ok":true}')]:
            self.assertFalse(live_http.binary_response({'body': body, 'evidence': {'headers': {'content-type': media}}}))
        for body in ('PK\x03\x04\ufffd', 'abc\0def', '%PDF-1.4'):
            self.assertTrue(live_http.binary_response({'body': body, 'evidence': {'headers': {}}}))
        # A binary download can be mislabeled as plain text by the application.
        self.assertTrue(live_http.binary_response({'body': 'PK\x03\x04\ufffd',
            'evidence': {'headers': {'content-type': 'text/plain; charset=utf-8'}}}))

    def test_mirror_exposes_broker_access_context_without_trusting_target_headers(self):
        cases = [({}, 'false', None),
                 ({'authenticated': True, 'account': 'testing'}, 'true', 'testing'),
                 ({'authenticated': True, 'account': 'reference'}, 'true', 'reference'),
                 ({'authenticated': True, 'account': 'invalid\r\nheader'}, 'true', None),
                 ({'id': None}, 'unknown', None)]
        for context, authenticated, account in cases:
            with self.subTest(context=context):
                def fixture(*args, **kwargs):
                    return {'body': 'fixture', 'evidence': {'id': 7, 'status': 200,
                        'headers': {'x-patchriot-authenticated': 'spoofed',
                                    'x-patchriot-account': 'spoofed'}, **context}}
                with tools.ScopeMirror('https://owned.example', time.monotonic()+5, fixture) as mirror:
                    client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
                    client.request('GET', '/')
                    response = client.getresponse(); response.read(); client.close()
                    self.assertEqual(response.getheader('X-Patchriot-Authenticated'), authenticated)
                    self.assertEqual(response.getheader('X-Patchriot-Account'), account)

    def test_crawl_discovers_literal_client_routes_without_executing_scripts(self):
        calls = []
        def fetch(method, url, headers=None, **kwargs):
            calls.append(url)
            body = '<script src="/app.js"></script>' if url.endswith('/') else "fetch('/api/items'); fetch('https://other.example/private')" if url.endswith('/app.js') else '{}'
            content = 'text/javascript' if url.endswith('.js') else 'text/html' if url.endswith('/') else 'application/json'
            return {'evidence': {'id': len(calls), 'status': 200, 'headers': {'content-type': content}}, 'body': body}
        tools.crawl('https://owned.example', time.monotonic() + 5, fetch)
        self.assertIn('https://owned.example/api/items', calls)
        self.assertTrue(all(url.startswith('https://owned.example/') for url in calls))

    def test_password_control_uses_private_replay_and_retains_evidence(self):
        reply = {'evidence': {'id': 42, 'status': 200}, 'body': '{"ok":true}'}
        with tempfile.TemporaryDirectory() as folder, \
                patch.dict('os.environ', {'PATCHRIOT_BRIDGE_URL': 'http://127.0.0.1:1234'}), \
                patch.object(live_http, 'default_account', return_value='testing'), \
                patch.object(live_http, 'EVIDENCE_DIRECTORY', Path(folder)), \
                patch.object(live_http, 'urlopen', return_value=io.BytesIO(json.dumps(reply).encode())) as upstream:
            result = live_http.verify_changed_password()
            request = upstream.call_args.args[0]
            self.assertEqual(request.full_url, 'http://127.0.0.1:1234/patchriot/password/verify')
            self.assertEqual(request.data, b'{}')
            self.assertEqual(json.loads((Path(folder) / '42.json').read_text()), reply['evidence'])
            self.assertEqual(result['evidence']['id'], 42)
        with patch.object(live_http, 'default_account', return_value='reference'), \
                patch.object(live_http, 'urlopen') as upstream:
            with self.assertRaises(ValueError):
                live_http.verify_changed_password()
            upstream.assert_not_called()

    def test_mirror_distinguishes_partial_bodies_and_broker_denials_from_target_responses(self):
        def fixture(method, url, headers, **kwargs):
            if url.endswith('/blocked'):
                return {'error':'account_credential_changes_not_permitted'}
            return {'body':'partial script', 'body_truncated':True,
                    'evidence':{'id':7,'status':200,'truncated':True,'headers':{
                        'content-type':'application/javascript',
                        'x-patchriot-body-truncated':'false',
                        'x-patchriot-relay-error':'spoofed_target_header'}}}
        with tools.ScopeMirror('https://owned.example', time.monotonic()+5, fixture) as mirror:
            client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
            client.request('GET', '/app.js')
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b'partial script')
            self.assertEqual(response.getheaders().count(('X-Patchriot-Body-Truncated','true')), 1)
            self.assertEqual(response.getheader('X-Patchriot-Body-Truncated'), 'true')
            self.assertEqual(response.getheader('X-Patchriot-Evidence-Id'), '7')
            self.assertIsNone(response.getheader('X-Patchriot-Relay-Error'))
            client.close()
            client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
            client.request('GET', '/blocked')
            response = client.getresponse(); response.read(); client.close()
            self.assertEqual(response.status, 502)
            self.assertEqual(response.getheader('X-Patchriot-Relay-Error'), 'account_credential_changes_not_permitted')
            self.assertIsNone(response.getheader('X-Patchriot-Evidence-Id'))
            self.assertEqual(mirror.refs, [7])

    def test_withheld_success_body_is_a_visible_transport_gap_not_target_success_or_progress(self):
        evidence = {'id': 42, 'status': 200, 'error': 'browser_json_too_wide',
                    'headers': {'content-type': 'application/json', 'x-patchriot-target-status': '201'}}
        def fixture(*args, **kwargs):
            return {'body': '', 'evidence': dict(evidence)}
        with tools.ScopeMirror('https://owned.example', time.monotonic()+5, fixture) as mirror:
            for path in ['/items?page=1', '/items?page=2']:
                client = http.client.HTTPConnection('127.0.0.1', mirror.server.server_port, timeout=2)
                client.request('GET', path)
                response = client.getresponse()
                self.assertEqual(response.status, 502)
                self.assertEqual(response.getheader('X-Patchriot-Target-Status'), '200')
                self.assertEqual(response.getheader('X-Patchriot-Relay-Error'), 'browser_json_too_wide')
                self.assertIn(b'not an empty target response', response.read())
                client.close()
            self.assertEqual(mirror.refs, [42, 42])
            self.assertFalse(mirror.progress_keys)
            self.assertEqual(mirror.transport_errors, {'browser_json_too_wide': 2})
            self.assertEqual(evidence['status'], 200)

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
        previous = [{'role':'investigator', 'evidence':[{'id':1,'status':200,'url':'https://owned.example/'}], 'tool_runs':[
            {'tool':name, 'exit_code':0, 'failure':None, 'evidence_ids':[1]}
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
