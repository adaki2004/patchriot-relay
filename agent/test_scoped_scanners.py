import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

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

    def test_working_examples_retain_context_and_fields_without_body_values(self):
        origin = self.scope['origins'][0]
        base = {'id': 10, 'method': 'GET', 'url': origin + '/api/items/42', 'status': 200}
        rows = [base, {**base, 'id': 11, 'authenticated': True, 'account': 'reference'},
                {**base, 'id': 12, 'method': 'POST', 'request_body_excerpt': '{"title":"private-value","count":2}'},
                {**base, 'id': 13, 'login': True}, {**base, 'url': origin + '/api/items/42?token=secret'},
                {**base, 'url': origin + '/auth/callback?code=secret'},
                {**base, 'url': origin + '/reset/42'}, {**base, 'url': 'https://elsewhere.example/api/items/42'},
                {**base, 'status': 403}, {**base, 'error': 'failed'}]
        examples = scanners.working_requests(self.scope, rows)
        self.assertEqual(len(examples), 3)
        post = next(e for e in examples if e['method'] == 'POST')
        self.assertEqual(post['body_fields'], ['title', 'count'])
        self.assertIn('existing_write_permission', post['replay'])
        self.assertNotIn('private-value', json.dumps(examples))
        self.assertEqual({e['account'] for e in examples}, {None, 'reference'})

    def test_schema_receives_only_working_gets_from_its_own_context(self):
        client = scanners.Requests(self.scope, time.monotonic() + 30, self.fetch, 'testing')
        client.observations = [{'method': method, 'account': account, 'url': 'https://owned.example/items/42', 'evidence_id': i}
            for i, (method, account) in enumerate([('GET', None), ('GET', 'testing'), ('GET', 'reference'), ('POST', 'testing')], 1)]
        def generate(argv, **kwargs):
            data = json.loads(Path(argv[6]).read_text())
            self.assertEqual([e['evidence_id'] for e in data], [2])
            return {'exit_code': 0, 'failure': None, 'output': '{"cases": [], "gaps": []}'}
        with patch.object(scanners, 'schema_base', return_value=('https://owned.example', 'declared_server')):
            scanners.schema_checks(client, ['https://owned.example/openapi.json'], execute=generate)

    def test_observed_operation_matches_mounts_and_keeps_the_exact_origin(self):
        operation = SimpleNamespace(method='get', path='/items/{id}')
        base = 'https://owned.example/api'
        for url, matches in [(base + '/items/42?limit=2', True),
            ('https://owned.example/items/42', False), ('https://other.example/api/items/42', False),
            (base + '/items/%2f', False), (base + '/items/42?token=private', False)]:
            value = schema_cases.observed_operation(operation, base, [{'method': 'GET', 'url': url}])
            self.assertEqual(value is not None, matches)
            if matches: self.assertEqual(value[1], {'id': '42'})

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

    def test_schema_bases_respect_declared_mounts_and_reject_external_servers(self):
        url = 'https://owned.example/api/openapi.json'
        for document, expected in [
            ({**SCHEMA, 'servers': [{'url': '/v2'}]}, ['https://owned.example/v2']),
            ({**SCHEMA, 'servers': [{'url': 'https://other.example/api'}]}, []),
            ({**SCHEMA, 'servers': [{'url': 'http://127.0.0.1/api'}]}, []),
            ({**SCHEMA, 'servers': [{'url': 'https://u:p@owned.example/api'}]}, []),
            ({'swagger': '2.0', 'basePath': '/api', 'host': 'owned.example'}, ['https://owned.example/api']),
            ({'swagger': '2.0', 'basePath': '/api', 'host': 'other.example'}, []),
            ({'swagger': '2.0', 'host': 'other.example'}, []),
        ]:
            with self.subTest(document=document):
                bases, declared = schema_cases.base_candidates(document, url, [])
                self.assertTrue(declared)
                self.assertEqual(bases, expected)

    def test_schema_mount_requires_an_api_response_and_missing_path_control(self):
        calls = []
        def fetch(method, url, headers=None, **kwargs):
            calls.append(url)
            code, body = (200, '{"items":[]}') if url == 'https://owned.example/api/items' else (404, '{"error":"missing"}')
            return {'body': body, 'evidence': {'id': len(calls), 'url': url, 'status': code}}
        client = scanners.Requests(self.scope, time.monotonic() + 20, fetch)
        base, source = scanners.schema_base(client, SCHEMA, 'https://owned.example/api/openapi.json',
                                            ['https://owned.example/api/items'])
        self.assertEqual((base, source), ('https://owned.example/api', 'verified_mount'))
        self.assertTrue(any('patchriot-schema-missing-' in url for url in calls))

    def test_json_catch_all_cannot_prove_a_schema_mount(self):
        client = scanners.Requests(self.scope, time.monotonic() + 20,
            lambda m, u, h=None, **kw: {'body': '{"ok":true}', 'evidence': {'id': 1, 'status': 200, 'url': u}})
        self.assertEqual(scanners.schema_base(client, SCHEMA, 'https://owned.example/api/openapi.json', []),
                         (None, 'schema_base_unverified'))

    def test_good_schema_survives_a_redirected_alternate_and_keeps_case_counts(self):
        document = {**SCHEMA, 'servers': [{'url': '/api'}]}
        def fetch(method, url, headers=None, **kwargs):
            value = self.fetch(method, url, headers, **kwargs)
            if url.endswith('/api/openapi.json'):
                value['body'] = json.dumps(document)
            elif url.endswith('/openapi.json'):
                value['evidence']['status'] = 301
                value['evidence']['headers']['location'] = 'http://127.0.0.1/schema'
            return value
        def generate(argv, **kwargs):
            self.assertEqual(argv[3], 'https://owned.example/api')
            self.assertGreater(int(argv[4]), 12)
            return {'exit_code': 0, 'failure': None, 'output': json.dumps({
                'cases': [{'method': 'GET', 'url': argv[3] + '/items', 'operation': 'GET /items'}],
                'gaps': [], 'sampling_limits': ['schema_case_sample_limit'],
                'operations_total': 51, 'operations_eligible': 30, 'operations_selected': 1,
                'deferred_operations_count': 21, 'deferred_operations': [{'operation': 'POST /items'}]})}
        client = scanners.Requests(self.scope, time.monotonic() + 60, fetch, limit=64)
        result = scanners.schema_checks(client, ['https://owned.example/api/openapi.json',
            'https://owned.example/openapi.json'], execute=generate)
        self.assertEqual(result['schemas'][0]['base_source'], 'declared_server')
        self.assertEqual(result['schemas'][0]['executed_cases'], 1)
        self.assertEqual(result['schemas'][0]['operations_total'], 51)
        self.assertEqual(set(client.gaps), {'schema_case_sample_limit'})
        self.assertTrue(all(method == 'GET' and url.startswith('https://owned.example/')
                            for method, url, _, _ in self.calls))

    def test_schema_with_only_unavailable_candidates_stays_incomplete(self):
        def fetch(method, url, headers=None, **kwargs):
            result = self.fetch(method, url, headers, **kwargs)
            result['evidence']['status'] = 503
            return result
        client = scanners.Requests(self.scope, time.monotonic() + 10, fetch)
        scanners.schema_checks(client, ['https://owned.example/openapi.json'], execute=Mock(side_effect=AssertionError()))
        self.assertIn('schema_unavailable', client.gaps)

    def test_reading_a_schema_without_executing_a_case_cannot_pass_as_a_sample(self):
        clock = [1000.0]
        def generate(argv, **kwargs):
            clock[0] = 1019.9
            return {'exit_code': 0, 'failure': None, 'output': json.dumps({
                'cases': [{'method': 'GET', 'url': 'https://owned.example/items', 'operation': 'GET /items'}],
                'gaps': [], 'operations_eligible': 1})}
        with patch('time.monotonic', lambda: clock[0]):
            client = scanners.Requests(self.scope, 1020.0, self.fetch)
            result = scanners.schema_checks(client, ['https://owned.example/openapi.json'], execute=generate)
        self.assertEqual(result['schemas'][0]['executed_cases'], 0)
        self.assertIn('schema_no_cases_executed', client.gaps)

    def test_schema_cannot_send_the_account_session_to_its_declared_external_server(self):
        def fetch(method, url, headers=None, **kwargs):
            result = self.fetch(method, url, headers, **kwargs)
            result['body'] = json.dumps({**SCHEMA, 'servers': [{'url': 'https://other.example/api'}]})
            return result
        client = scanners.Requests(self.scope, time.monotonic() + 10, fetch, 'testing')
        scanners.schema_checks(client, ['https://owned.example/api/openapi.json'], execute=Mock(side_effect=AssertionError()))
        self.assertIn('no_approved_schema_server', client.gaps)
        self.assertEqual(len(self.calls), 1)

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_mounted_schema_runs_reads_and_retains_the_write_handoff(self):
        document = {**SCHEMA, 'paths': {**SCHEMA['paths'],
            '/create': {'post': {'responses': {'201': {'description': 'Created'}}}}}}
        def fetch(method, url, headers=None, **kwargs):
            result = self.fetch(method, url, headers, **kwargs)
            if url.endswith('/api/openapi.json'):
                result['body'] = json.dumps(document)
            elif '/api/items' in url:
                result['body'] = '{"items":[]}'
            else:
                result['body'] = '{"error":"missing"}'
                result['evidence']['status'] = 404
            return result
        sc = {**self.scope, 'methods': ['GET', 'POST']}
        client = scanners.Requests(sc, time.monotonic() + 40, fetch, 'testing', limit=64)
        result = scanners.schema_checks(client, ['https://owned.example/api/openapi.json',
                                                'https://owned.example/api/items'])
        doc = result['schemas'][0]
        self.assertEqual(doc['base_url'], 'https://owned.example/api')
        self.assertEqual(doc['base_source'], 'verified_mount')
        self.assertEqual(doc['deferred_operations_count'], 1)
        self.assertGreater(doc['executed_cases'], 0)
        self.assertEqual(doc['operations_tested'], 1)
        self.assertEqual(client.gaps, [])
        self.assertTrue(all(method == 'GET' for method, _, _, _ in self.calls))

    def test_scanner_failures_keep_bounded_codes_and_withhold_arbitrary_details(self):
        for message, expected in [('scanner_api_internal_error', 'scanner_api_internal_error'),
                                  ('https://private.example/?token=secret', 'ValueError')]:
            with tempfile.TemporaryDirectory() as folder, patch.multiple(
                scanners, probes=Mock(side_effect=ValueError(message)),
                discovery=lambda *_: {}, zap=lambda *_: {}, schema_checks=lambda *_: {},
                capture=lambda *_, **__: {'output': 'ffuf 2.1.0'},
            ):
                results = scanners.run(self.scope, [], fetch=self.fetch, directory=Path(folder))
            detail = json.loads(results[0]['output_excerpt'])
            self.assertEqual(detail['contexts'][0]['result']['reason'], expected)
            self.assertEqual(results[0]['failure'], 'incomplete')

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

    def test_large_coverage_summary_is_not_a_failed_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            evidence_dir = directory / 'http-evidence'
            evidence_dir.mkdir()
            for identifier in range(1, 81):
                evidence = {'id': identifier, 'url': f'https://owned.example/item/{identifier}',
                            'method': 'GET', 'status': 200, 'error': None}
                (evidence_dir / f'{identifier}.json').write_text(json.dumps(evidence))
            run = coverage_ledger.build(self.scope, [], directory)
            data = json.loads(run['output_excerpt'])
            self.assertIsNone(run['failure'])
            self.assertEqual(run['exit_code'], 0)
            self.assertEqual(data['summary_state'], 'recorded')
            self.assertEqual(data['unit_counts'], {'tested': 80, 'deferred': 4})
            self.assertEqual(data['omitted_units'] + len(data['units']), 84)
            self.assertEqual(sum(u['state'] == 'deferred' for u in data['units']), 4)
            self.assertEqual(len(list(evidence_dir.glob('*.json'))), 80)

    def test_engine_handoff_preserves_context_and_skips_already_scanned_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            evidence_dir = directory / 'http-evidence'
            evidence_dir.mkdir()
            rows = [
                ('https://owned.example/search?q=first', None),
                ('https://owned.example/search?q=another', None),
                ('https://owned.example/search?q=private', 'reference'),
                ('https://owned.example/new?term=generated', None),
                ('https://owned.example/new?term=duplicate', None),
                ('https://owned.example/blocked', 'testing'),
            ]
            for identifier, (url, account) in enumerate(rows, 1):
                evidence_dir.joinpath(f'{identifier}.json').write_text(json.dumps({
                    'id': identifier, 'url': url, 'method': 'GET', 'status': 200,
                    'authenticated': account is not None, 'account': account}))
            visits = []
            def scanner(client, urls):
                visits.append((client.account, urls))
                for url in urls:
                    client('GET', url)
                return {'alerts': []}
            with patch.object(scanners, 'zap', scanner):
                result = scanners.follow_up(self.scope, [{'tool': 'zap', 'evidence_ids': [1]}],
                    {'evidence_ids': [2, 3, 4, 5, 6]},
                    {'accounts': [{'account': 'reference', 'verified': True}]},
                    time.monotonic() + 120, self.fetch, directory=directory)
            self.assertEqual(visits, [('reference', [rows[2][0]]), (None, [rows[3][0]])])
            self.assertEqual(json.loads(result['output_excerpt'])['source_evidence_ids'], [3, 4])
            self.assertEqual(len(result['evidence_ids']), 2)
            self.assertTrue(all(call[3]['discovery'] is False for call in self.calls))

    def test_follow_up_retains_safe_failure_reason_and_partial_requests(self):
        for message, expected in [('scanner_api_url_not_found', 'scanner_api_url_not_found'),
                                  ('private token=secret', 'ValueError')]:
            with tempfile.TemporaryDirectory() as folder:
                directory = Path(folder)
                (directory / 'http-evidence').mkdir()
                (directory / 'http-evidence/1.json').write_text(json.dumps({
                    'id': 1, 'url': 'https://owned.example/search?q=sample', 'method': 'GET', 'status': 200}))
                def fail(client, urls):
                    client('GET', urls[0])
                    raise ValueError(message)
                with patch.object(scanners, 'zap', fail):
                    run = scanners.follow_up(self.scope, [], {'evidence_ids':[1]}, {},
                        time.monotonic()+120, self.fetch, directory=directory)
                detail = json.loads(run['output_excerpt'])
                self.assertEqual(run['failure'], 'incomplete')
                self.assertEqual(detail['contexts'][0]['result']['reason'], expected)
                self.assertEqual(detail['contexts'][0]['requests'], 1)
                self.assertEqual(len(run['evidence_ids']), 1)
                self.assertNotIn('secret', run['output_excerpt'])

    def test_follow_up_access_failure_keeps_a_gap_without_scanning_or_exposing_errors(self):
        for failure in [TimeoutError('private token=secret'), ValueError('private account')]:
            with self.subTest(failure=type(failure).__name__):
                access, emit = Mock(side_effect=failure), Mock()
                with patch.object(scanners, 'zap') as scan:
                    run = scanners.follow_up(self.scope, [], {'evidence_ids': [1]}, access,
                        time.monotonic() + 120, self.fetch, emit=emit)
                access.assert_called_once_with()
                scan.assert_not_called()
                emit.assert_called_once_with(run)
                self.assertEqual(self.calls, [])
                self.assertEqual(run['failure'], 'incomplete')
                self.assertEqual(run['evidence_ids'], [])
                detail = json.loads(run['output_excerpt'])
                self.assertEqual(detail['gaps'], ['follow_up_access_unavailable'])
                self.assertNotIn('private', run['output_excerpt'])

    def test_follow_up_reads_fresh_access_once_before_selecting_inputs(self):
        access = Mock(return_value={'verified': False})
        with tempfile.TemporaryDirectory() as folder:
            run = scanners.follow_up(self.scope, [], {'evidence_ids': []}, access,
                time.monotonic() + 120, self.fetch, directory=Path(folder))
        access.assert_called_once_with()
        self.assertIsNone(run['failure'])
        self.assertEqual(json.loads(run['output_excerpt'])['state'], 'inapplicable')

    def test_engine_handoff_rejects_unavailable_or_unsafe_seeds_and_caps_work(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            evidence_dir = directory / 'http-evidence'
            evidence_dir.mkdir()
            base = {'method': 'GET', 'status': 200, 'url': 'https://owned.example/path'}
            invalid = [{'url': 'https://other.example/path'}, {'method': 'POST'},
                       {'status': 403}, {'error': 'unavailable'}, {'login': True},
                       {'url': 'https://owned.example/path?token=[REDACTED]'}, {'id': 999}]
            rows = invalid + [{'url': 'https://owned.example/static'}] + [
                {'url': f'https://owned.example/new{number}?q=sample'} for number in range(8)]
            for identifier, changes in enumerate(rows, 1):
                evidence_dir.joinpath(f'{identifier}.json').write_text(json.dumps({**base, 'id': identifier, **changes}))
            with patch.object(scanners, 'zap', return_value={}) as scanner:
                result = scanners.follow_up(self.scope, [], {'evidence_ids': ['../outside', 0, *range(1, len(rows) + 1)]},
                    {}, time.monotonic() + 120, self.fetch, directory=directory)
            self.assertEqual(scanner.call_count, 1)
            self.assertEqual(len(scanner.call_args.args[1]), 4)
            self.assertEqual(json.loads(result['output_excerpt'])['source_evidence_ids'], [9, 10, 11, 12])

    def test_engine_handoff_retains_time_gap_and_inapplicable_state(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            evidence_dir = directory / 'http-evidence'
            evidence_dir.mkdir()
            evidence_dir.joinpath('1.json').write_text(json.dumps({
                'id': 1, 'method': 'GET', 'status': 200, 'url': 'https://owned.example/new'}))
            with patch.object(scanners, 'zap') as scanner:
                result = scanners.follow_up(self.scope, [], {'evidence_ids': [1]}, {},
                    time.monotonic() + 10, self.fetch, directory=directory)
                absent = scanners.follow_up(self.scope, [], {'evidence_ids': [2]}, {},
                    time.monotonic() + 120, self.fetch, directory=directory)
            scanner.assert_not_called()
            self.assertEqual(result['failure'], 'incomplete')
            self.assertEqual(json.loads(result['output_excerpt'])['gaps'], ['follow_up_time_unavailable'])
            self.assertEqual(json.loads(absent['output_excerpt'])['reason'], 'no_new_recorded_get_inputs')

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
        self.assertLessEqual(len(result['cases']), 48)
        self.assertTrue(all(c['method'] == 'GET' and c['url'].startswith('https://owned.example/items') for c in result['cases']))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_schema_uses_observed_ids_and_retains_a_fresh_baseline(self):
        document = {**SCHEMA, 'paths': {'/items/{id}': {'get': {
            'parameters': [{'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'integer'}},
                           {'name': 'limit', 'in': 'query', 'required': True, 'schema': {'type': 'integer', 'minimum': 0, 'maximum': 3}}],
            'responses': {'200': {'description': 'Owned object'}}}}}}
        url = 'https://owned.example/api/items/42?limit=2'
        result = schema_cases.generate(document, 'https://owned.example/api', observations=[
            {'method': 'GET', 'url': url, 'evidence_id': 123}])
        self.assertEqual(result['cases'][0]['url'], url)
        self.assertEqual(result['cases'][0]['generation_mode'], 'observed')
        self.assertTrue(any(c['generation_mode'] == 'negative' for c in result['cases']))
        self.assertTrue(all(c['source_evidence_id'] == 123 for c in result['cases']))
        self.assertTrue(all('/items/42?' in c['url'] for c in result['cases']))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_schema_sample_covers_distinct_operations_and_preserves_post_for_agent_review(self):
        document = {**SCHEMA, 'paths': {f'/items/{i}': {'get': {'responses': {'200': {'description': 'Owned list'}}}}
                                         for i in range(51)}}
        document['paths']['/items'] = {'post': {'responses': {'201': {'description': 'Creates an item'}}}}
        result = schema_cases.generate(document, 'https://owned.example/api', max_cases=24, methods=['GET', 'POST'])
        self.assertEqual(len(result['cases']), 24)
        self.assertEqual(result['operations_selected'], 24)
        self.assertEqual(result['operations_eligible'], 51)
        self.assertEqual(result['deferred_operations_count'], 1)
        self.assertIn('schema_case_sample_limit', result['sampling_limits'])
        self.assertEqual(result['gaps'], [])
        self.assertTrue(all(case['method'] == 'GET' and '/api/items/' in case['url'] for case in result['cases']))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_operation_server_is_not_silently_rewritten_to_the_common_base(self):
        document = {**SCHEMA, 'paths': {**SCHEMA['paths'], '/elsewhere': {
            'get': {'servers': [{'url': 'https://other.example'}],
                    'responses': {'200': {'description': 'Different API'}}}}}}
        result = schema_cases.generate(document, 'https://owned.example/api')
        self.assertEqual(result['operations_eligible'], 1)
        self.assertEqual(result['deferred_operations_count'], 1)
        self.assertEqual(result['deferred_operations'][0]['reason'], 'operation_server_requires_agent_review')
        self.assertTrue(all('/api/items' in case['url'] for case in result['cases']))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_graphql_generator_excludes_mutations(self):
        from graphql import build_schema, introspection_from_schema
        schema = introspection_from_schema(build_schema('type Query { item(limit: Int): String } type Mutation { erase: String }'))
        result = schema_cases.generate(schema, 'https://owned.example/graphql')
        self.assertTrue(result['cases'])
        self.assertEqual(result['deferred_operations_count'], 1)
        self.assertEqual(result['deferred_operations'][0]['reason'], 'mutation_requires_agent_review')
        self.assertTrue(all(case['url'] == 'https://owned.example/graphql' and case['method'] == 'POST' for case in result['cases']))
        self.assertTrue(all('erase' not in case['data'] for case in result['cases']))

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE') == '1', 'requires built scanner image')
    def test_real_zap_runs_through_owned_broker_fixture(self):
        client = scanners.Requests(self.scope, time.monotonic() + 90, self.fetch, limit=12)
        before = set(Path('/work').glob('patchriot-zap-*'))
        result = scanners.zap(client, ['https://owned.example/'])
        self.assertEqual(set(Path('/work').glob('patchriot-zap-*')), before)
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
            with tempfile.TemporaryDirectory() as folder:
                directory = Path(folder)
                evidence_dir = directory / 'http-evidence'
                evidence_dir.mkdir()
                evidence_dir.joinpath('1000.json').write_text(json.dumps({
                    'id': 1000, 'method': 'GET', 'status': 200,
                    'url': 'https://owned.example/search?q=generated'}))
                receipt = scanners.follow_up(scope, [], {'evidence_ids': [1000]}, {},
                    time.monotonic() + 90, fetch, directory=directory)
            self.assertIsNone(receipt['failure'], receipt['output_excerpt'])
            result = json.loads(receipt['output_excerpt'])['contexts'][0]['result']
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
