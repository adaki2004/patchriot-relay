import json
import os
from pathlib import Path
import tempfile
import time
import unittest

import coverage_ledger
import schema_cases
import scoped_scanners as scanners


SCHEMA = {'openapi': '3.0.3', 'info': {'title': 'Owned fixture', 'version': '1'},
          'paths': {'/items': {'get': {'parameters': [{'name': 'limit', 'in': 'query', 'schema': {'type': 'integer', 'minimum': 0, 'maximum': 3}}],
                                      'responses': {'200': {'description': 'Owned list'}}}}}}


class ScopedScannerTests(unittest.TestCase):
    def setUp(self):
        self.scope = {'origins': ['https://owned.example'], 'methods': ['GET', 'HEAD', 'OPTIONS'], 'profile': 'web_baseline_v1'}
        self.calls = []

    def fetch(self, method, url, headers=None, **kwargs):
        self.calls.append((method, url, headers, kwargs))
        body = json.dumps(SCHEMA) if url.endswith('openapi.json') else '<html><title>Owned fixture</title></html>'
        evidence = {'id': len(self.calls), 'method': method, 'url': url, 'status': 200, 'error': None,
                    'headers': {'content-type': 'application/json' if url.endswith('openapi.json') else 'text/html'},
                    'authenticated': kwargs.get('authenticated', False)}
        if evidence['authenticated']:
            evidence['account'] = kwargs['account']
        return {'evidence': evidence, 'body': body}

    def test_scope_and_budget_are_enforced_before_fetch(self):
        client = scanners.Requests(self.scope, time.monotonic() + 5, self.fetch, 'reference', limit=1)
        self.assertIn('error', client('POST', 'https://owned.example/'))
        self.assertIn('error', client('GET', 'https://other.example/'))
        self.assertEqual(client('GET', 'https://owned.example/')['evidence']['account'], 'reference')
        self.assertIn('error', client('GET', 'https://owned.example/'))
        self.assertEqual(len(self.calls), 1)

    def test_probes_retain_controls_and_account_context(self):
        client = scanners.Requests(self.scope, time.monotonic() + 5, self.fetch)
        result = scanners.probes(client, ['https://owned.example/'])
        self.assertEqual(result['checks'][0]['evidence_ids'], [1, 2, 3])
        self.assertTrue(all(not call[3]['authenticated'] for call in self.calls))

    def test_schema_external_references_are_rejected_before_loading(self):
        schema_cases.check_references(SCHEMA)
        for reference in ['https://other.example/schema', 'file:///etc/passwd', '/tmp/schema']:
            with self.assertRaises(ValueError):
                schema_cases.check_references({'schema': {'$ref': reference}})

    def test_coverage_requires_real_records_and_preserves_gaps(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            (directory / 'http-evidence').mkdir()
            evidence = self.fetch('GET', 'https://owned.example/')['evidence']
            (directory / 'http-evidence/1.json').write_text(json.dumps(evidence))
            run = coverage_ledger.build(self.scope, [], directory)
            data = json.loads(run['output_excerpt'])
            self.assertEqual(run['evidence_ids'], [1])
            self.assertEqual(sum(u['state'] == 'tested' for u in data['units']), 1)
            self.assertEqual(sum(u['state'] == 'deferred' for u in data['units']), 4)
            self.assertFalse(run['output_truncated'])

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_schema_generator_produces_bounded_cases_offline(self):
        result = schema_cases.generate(SCHEMA, 'https://owned.example')
        self.assertTrue(result['cases'])
        self.assertLessEqual(len(result['cases']), 12)
        self.assertTrue(all(c['method'] == 'GET' and c['url'].startswith('https://owned.example/items') for c in result['cases']))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_zap_runs_through_owned_broker_fixture(self):
        client = scanners.Requests(self.scope, time.monotonic() + 90, self.fetch, limit=12)
        result = scanners.zap(client, ['https://owned.example/'])
        self.assertIn('alerts', result)
        self.assertTrue(client.records)
        self.assertTrue(all(url.startswith('https://owned.example/') for _, url, _, _ in self.calls))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_ffuf_runs_bounded_observed_paths(self):
        client = scanners.Requests(self.scope, time.monotonic() + 30, self.fetch, limit=12)
        scanners.discovery(client, ['https://owned.example/known'])
        self.assertGreaterEqual(len(client.records), 2)
        self.assertLessEqual(len(client.records), 12)
        self.assertFalse(client.gaps)


if __name__ == '__main__':
    unittest.main()
