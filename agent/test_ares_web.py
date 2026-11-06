"""Owned HTTP fixtures for the ARES-derived adapter; no external target calls."""
import hashlib
import json
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import ares_web


class AresWebTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.replies = {}

    def fetch(self, method, url, headers=None, **options):
        self.calls.append((method, url, options))
        status, body, headers = self.replies.get(urlsplit(url).path, (404, 'Not found', {}))
        return {'body': body, 'evidence': {
            'id': len(self.calls), 'method': method, 'url': url, 'status': status,
            'headers': headers, 'body_sha256': hashlib.sha256(body.encode()).hexdigest(),
            'truncated': False,
        }}

    def run_tool(self, **kwargs):
        receipt = ares_web.run('https://owned.example', time.monotonic()+5, self.fetch, **kwargs)
        return receipt, json.loads(receipt['output_excerpt'])

    def test_records_actual_anonymous_requests_and_pinned_component(self):
        self.replies['/'] = (200, '<html>Public home</html>', {'server': 'nginx/1.24.0'})
        receipt, output = self.run_tool()
        self.assertEqual(receipt['tool'], 'ares-web-surface')
        self.assertIn(ares_web.COMMIT, receipt['version'])
        self.assertEqual(output['source'], ares_web.SOURCE)
        self.assertEqual(output['technology_hints'], ['nginx'])
        self.assertEqual(output['path_count'], 22)
        self.assertEqual(len(self.calls), 24)
        self.assertTrue(all(m == 'GET' and urlsplit(u).netloc == 'owned.example'
                            and opt == {'authenticated': False} for m, u, opt in self.calls))
        self.assertEqual(receipt['evidence_ids'], list(range(1,25)))
        self.assertIsNone(receipt['failure'])

    def test_login_pages_denials_redirects_and_spa_catchalls_are_not_exposure(self):
        home = '<html>Login or read the public documentation</html>'
        self.replies['/'] = (200, home, {})
        self.replies['/admin'] = (200, '<form>Admin login</form>', {})
        self.replies['/console'] = (403, 'Forbidden', {})
        self.replies['/grafana'] = (302, '', {'location': 'https://external.example/'})
        self.replies['/.git/HEAD'] = (200, home, {})
        _, output = self.run_tool()
        by_path = {p['path']: p for p in output['observations']}
        self.assertEqual(by_path['/admin']['state'], 'response_observed')
        self.assertEqual(by_path['/console']['state'], 'access_restricted')
        self.assertEqual(by_path['/grafana']['state'], 'redirect_not_followed')
        self.assertEqual(by_path['/.git/HEAD']['state'], 'same_as_home_or_missing_path')
        self.assertTrue(all(not p['content_signatures'] for p in by_path.values()))
        self.assertNotIn('severity', json.dumps(output))
        self.assertFalse(any('external.example' in url for _,url,_ in self.calls))

    def test_content_leads_keep_controls_without_copying_secret_values(self):
        self.replies['/'] = (200, 'Home', {})
        self.replies['/.git/HEAD'] = (200, 'ref: refs/heads/main\n', {})
        self.replies['/.env'] = (200, 'DB_PASSWORD=owned-fixture-only\n', {})
        self.replies['/api/swagger.json'] = (200, '{"openapi":"3.0.0","paths":{"/public":{}}}', {})
        self.replies['/actuator/env'] = (200, '{"propertySources":[{"value":"private-fixture"}]}', {})
        receipt, output = self.run_tool()
        leads = {p['path']: p for p in output['observations'] if p['content_signatures']}
        self.assertEqual(set(leads), {'/.git/HEAD','/.env','/api/swagger.json','/actuator/env'})
        for lead in leads.values():
            self.assertEqual(lead['state'], 'content_lead_needs_review')
            self.assertEqual(lead['control_evidence_id'], 2)
            self.assertIn(lead['evidence_id'], receipt['evidence_ids'])
        self.assertNotIn('owned-fixture-only', receipt['output_excerpt'])
        self.assertNotIn('private-fixture', receipt['output_excerpt'])

    def test_pattern_in_catchall_is_not_a_content_lead(self):
        def catchall(method, url, headers=None, **kwargs):
            self.replies[urlsplit(url).path] = (200, 'DB_PASSWORD=example-not-a-real-setting\n', {})
            return self.fetch(method, url, headers, **kwargs)
        receipt = ares_web.run('https://owned.example', time.monotonic()+5, catchall)
        output = json.loads(receipt['output_excerpt'])
        self.assertTrue(all(p['state'] == 'same_as_home_or_missing_path' for p in output['observations']))
        self.assertTrue(all(not p['content_signatures'] for p in output['observations']))

    def test_rate_limit_and_transport_failure_stop_without_empty_success(self):
        self.replies['/admin'] = (429, 'Back off', {})
        receipt, output = self.run_tool()
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(receipt['failure'], 'incomplete')
        self.assertEqual(output['stop_reason'], 'target_backoff')
        def failed(*args, **kwargs):
            raise OSError('sensitive transport detail')
        receipt = ares_web.run('https://owned.example', time.monotonic()+5, failed)
        self.assertEqual(receipt['failure'], 'request_error')
        self.assertEqual(receipt['evidence_ids'], [])
        self.assertNotIn('sensitive transport detail', receipt['output_excerpt'])

    def test_deadline_or_invalid_origin_makes_no_network_request(self):
        receipt = ares_web.run('https://owned.example', time.monotonic()-1, self.fetch)
        self.assertEqual(receipt['failure'], 'timeout')
        for origin in ('http://owned.example', 'https://owned.example/path', 'https://owned.example@other.example'):
            receipt = ares_web.run(origin, time.monotonic()+5, self.fetch)
            self.assertEqual(receipt['failure'], 'request_error')
        self.assertEqual(self.calls, [])

    def test_missing_control_cannot_confirm_exposure(self):
        root = self.fetch('GET','https://owned.example/')
        self.replies['/.git/HEAD'] = (200, 'ref: refs/heads/main\n', {})
        probe = self.fetch('GET', 'https://owned.example/.git/HEAD')
        observation = ares_web.observation('/.git/HEAD', probe, root, {'error':'unavailable'})
        self.assertEqual(observation['state'], 'missing_control')
        self.assertEqual(observation['content_signatures'], [])


if __name__ == '__main__':
    unittest.main()
