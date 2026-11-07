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
    def test_real_suite_uses_all_verified_contexts_and_one_public_discovery(self):
        scope = {**self.scope, 'authentication': 'session', 'account_policy': {'allow_password_changes': False}}
        access = {'accounts': [{'account': account, 'verified': True, 'protected_url': 'https://owned.example/private'}
                               for account in ('testing', 'reference')]}
        crawl = {'tool': 'patchriot-crawl', 'output_excerpt': json.dumps({'pages': [{'url': 'https://owned.example/openapi.json', 'status': 200}]})}
        emitted = []
        with tempfile.TemporaryDirectory() as folder:
            results = scanners.run(scope, [crawl], access, self.fetch, emitted.append, Path(folder))
        self.assertEqual(results, emitted)
        self.assertEqual([run['tool'] for run in results], ['patchriot-probes', 'ffuf', 'zap', 'schemathesis'])
        for run in results:
            self.assertIsNone(run['failure'], run['output_excerpt'])
            self.assertTrue(run['evidence_ids'])
            contexts = [item['account'] for item in json.loads(run['output_excerpt'])['contexts']]
            self.assertEqual(contexts, ['anonymous'] if run['tool'] == 'ffuf' else ['anonymous', 'testing', 'reference'])
        self.assertTrue(any(call[3]['account'] == 'reference' and call[3]['authenticated'] for call in self.calls))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_schema_generator_produces_bounded_cases_offline(self):
        result = schema_cases.generate(SCHEMA, 'https://owned.example')
        self.assertTrue(result['cases'])
        self.assertLessEqual(len(result['cases']), 12)
        self.assertTrue(all(c['method'] == 'GET' and c['url'].startswith('https://owned.example/items') for c in result['cases']))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_graphql_generator_excludes_mutations(self):
        from graphql import build_schema, introspection_from_schema
        schema = introspection_from_schema(build_schema('type Query { item(limit: Int): String } type Mutation { erase: String }'))
        result = schema_cases.generate(schema, 'https://owned.example/graphql')
        self.assertTrue(result['cases'])
        self.assertIn('graphql_mutation_requires_disposable_inputs', result['gaps'])
        self.assertTrue(all(case['url'] == 'https://owned.example/graphql' and case['method'] == 'POST' for case in result['cases']))
        self.assertTrue(all('erase' not in case['data'] for case in result['cases']))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_zap_runs_through_owned_broker_fixture(self):
        client = scanners.Requests(self.scope, time.monotonic() + 90, self.fetch, limit=12)
        result = scanners.zap(client, ['https://owned.example/'])
        self.assertIn('alerts', result)
        self.assertTrue(client.records)
        self.assertTrue(all(url.startswith('https://owned.example/') for _, url, _, _ in self.calls))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_zap_distinguishes_reflection_from_encoded_control(self):
        from html import escape
        from urllib.parse import parse_qs, urlsplit
        scope = {**self.scope, 'profile': 'web_active_v1'}
        for vulnerable in (True, False):
            def fetch(method, url, headers=None, **kwargs):
                reply = self.fetch(method, url, headers, **kwargs)
                value = parse_qs(urlsplit(url).query).get('q', [''])[0]
                reply['body'] = '<html><body>' + (value if vulnerable else escape(value)) + '</body></html>'
                return reply
            client = scanners.Requests(scope, time.monotonic() + 90, fetch, limit=64)
            result = scanners.zap(client, ['https://owned.example/search?q=fixture'])
            reflected = [alert for alert in result['alerts'] if alert['rule'] == '40012']
            self.assertEqual(bool(reflected), vulnerable)
            self.assertTrue(all(alert['evidence_ids'] for alert in reflected))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_ffuf_runs_bounded_observed_paths(self):
        client = scanners.Requests(self.scope, time.monotonic() + 30, self.fetch, limit=12)
        scanners.discovery(client, ['https://owned.example/known'])
        self.assertGreaterEqual(len(client.records), 2)
        self.assertLessEqual(len(client.records), 12)
        self.assertFalse(client.gaps)


if __name__ == '__main__':
    unittest.main()
