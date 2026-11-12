"""Owned fixtures for the optional deep families; no network."""
import itertools
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import deep_checks as deep
import deep_extra as extra
from scoped_scanners import Requests

ORIGIN = 'https://owned.example'
IDS = itertools.count(1)


def scope(**overrides):
    value = {'origins': [ORIGIN], 'methods': ['GET', 'HEAD', 'OPTIONS'],
             'tools': ['scoped_discovery_v1', 'deep_checks_v1'], 'check_groups': ['public_deep']}
    value.update(overrides)
    return value


class Client(Requests):
    """Minimal stand-in for the recording request client."""

    def __init__(self, fetch, sc=None, account=None, limit=40):
        super().__init__(sc or scope(), time.monotonic() + 60, fetch, account, limit=limit)


def reply(url, code=200, body='', headers=None):
    return {'body': body, 'evidence': {'id': next(IDS), 'url': url, 'method': 'GET', 'status': code,
            'headers': headers or {}, 'error': None}}


class SurfaceTests(unittest.TestCase):
    def fetch(self, method, url, headers=None, **kwargs):
        if url.endswith('/app.js'):
            return reply(url, 200, 'fetch("/api/orders"); const token="abcdef0123456789abcdef";')  # gitleaks:allow -- synthetic token for exposed-key detection
        if 'missing' in url:
            return reply(url, 404, 'not found')
        if url.endswith('/api/orders'):
            return reply(url, 200, '{"orders":[]}')
        return reply(url, 200, '<script src="/app.js"></script><p>actuator</p>')

    def test_routes_need_the_missing_control_and_scripts_are_parsed(self):
        client = Client(self.fetch)
        detail = extra.surface(client, [ORIGIN + '/'])
        self.assertEqual(detail['missing_control_status'], 404)
        self.assertIn(ORIGIN + '/api/orders', detail['reachable_routes'])
        self.assertEqual(detail['scripts'], 1)
        self.assertIn('/actuator', detail['tech_paths'])
        self.assertGreaterEqual(detail['secret_shaped_strings'], 1)

    def test_a_route_without_a_control_is_not_reachable(self):
        client = Client(lambda m, u, h=None, **k: reply(u, 200, ''))
        detail = extra.surface(client, [ORIGIN + '/'])
        self.assertEqual(detail['reachable_routes'], [])
        self.assertEqual(client.gaps, [])

    def test_slow_surface_stops_before_its_next_probe_and_keeps_the_control(self):
        clock = [1000.0]
        calls = []
        def fetch(method, url, headers=None, **kwargs):
            clock[0] += 1.0
            calls.append(url)
            if 'missing' in url:
                return reply(url, 404, 'missing')
            return reply(url, body=' '.join('"/api/item%d"' % i for i in range(50)))
        with patch('time.monotonic', lambda: clock[0]):
            client = Requests(scope(), 1030.0, fetch, limit=48)
            detail = extra.surface(client, [ORIGIN + '/'])
        self.assertLess(clock[0], 1030.0)
        self.assertIn('missing', calls[0])
        self.assertGreater(detail['probed_routes'], 0)
        self.assertGreater(detail['deferred_routes'], 0)
        self.assertEqual(set(client.gaps), {'route_sample_limit'})

    def test_last_request_overrunning_deadline_cannot_be_a_success(self):
        clock = [1000.0]
        def fetch(method, url, headers=None, **kwargs):
            clock[0] += 35
            return reply(url, 404, 'late')
        with patch('time.monotonic', lambda: clock[0]):
            client = Requests(scope(), 1030.0, fetch, limit=48)
            extra.surface(client, [ORIGIN + '/'])
        self.assertIn('scanner_budget_reached', client.gaps)

    def test_surface_request_cap_is_a_sample_and_does_not_drop_control(self):
        client = Client(self.fetch, limit=6)
        detail = extra.surface(client, [ORIGIN + '/'])
        self.assertLessEqual(client.calls, 6)
        self.assertEqual(detail['missing_control_status'], 404)
        self.assertGreater(detail['probed_routes'], 0)
        self.assertIn('route_sample_limit', client.gaps)
        self.assertNotIn('scanner_budget_reached', client.gaps)

    def test_only_the_control_finishing_is_not_successful_surface_coverage(self):
        clock = [1000.0]
        def fetch(method, url, headers=None, **kwargs):
            clock[0] += 28
            return reply(url, 404, 'missing')
        with patch('time.monotonic', lambda: clock[0]):
            client = Requests(scope(), 1030.0, fetch, limit=48)
            detail = extra.surface(client, [ORIGIN + '/'])
        self.assertEqual(detail['probed_routes'], 0)
        self.assertIn('surface_no_routes_probed', client.gaps)


class BypassTests(unittest.TestCase):
    def test_protected_path_flip_is_reported_with_its_control(self):
        def fetch(method, url, headers=None, **kwargs):
            if '/admin' in url and not url.endswith(('admin/', 'admin.json')):
                return reply(url, 403, 'forbidden')
            if url.endswith(('admin/', 'admin.json')):
                return reply(url, 200, 'dashboard')
            return reply(url, 404, '')
        detail = extra.bypass(Client(fetch), [ORIGIN + '/admin'])
        self.assertEqual(detail['controls'][0]['status'], 403)
        self.assertTrue(any(row['control'] == 403 and row['status'] == 200 for row in detail['flipped']))


class HeaderTests(unittest.TestCase):
    def test_reflection_is_separated_from_cache_persistence(self):
        seen = {}

        def fetch(method, url, headers=None, **kwargs):
            if headers and extra.MARKER in headers.values():
                seen['cache'] = True
                return reply(url, 200, extra.MARKER)
            return reply(url, 200, extra.MARKER if seen.get('cache') else 'plain')
        detail = extra.headers(Client(fetch), [ORIGIN + '/'])
        self.assertTrue(detail['reflected'])
        self.assertTrue(detail['persisted'])

    def test_no_reflection_reports_nothing(self):
        detail = extra.headers(Client(lambda m, u, h=None, **k: reply(u, 200, 'plain')), [ORIGIN + '/'])
        self.assertEqual(detail['reflected'], [])


class InputTests(unittest.TestCase):
    def test_observed_parameter_reflection_is_a_lead(self):
        def fetch(method, url, headers=None, **kwargs):
            return reply(url, 200, 'found ' + extra.MARKER if extra.MARKER in url else 'list')
        detail = extra.inputs(Client(fetch), [ORIGIN + '/search?q=shoes'])
        self.assertTrue(any(row['kind'] == 'reflected' for row in detail['observed']))

    def test_file_parameters_also_get_a_traversal_probe(self):
        def fetch(method, url, headers=None, **kwargs):
            return reply(url, 500, 'error') if 'etc' in url else reply(url, 200, 'ok')
        detail = extra.inputs(Client(fetch), [ORIGIN + '/download?file=report'])
        self.assertTrue(any(row['kind'] == 'status_changed' for row in detail['observed']))


class CrossAccountTests(unittest.TestCase):
    def client(self, fetch=None, accounts=('testing', 'reference'), limit=40):
        client = Client(fetch or self.fetch, sc=scope(authentication='session',
            account_policy={'allow_password_changes': False}), limit=limit)
        client.verified_accounts = list(accounts)
        client.observations = [{'method': 'GET', 'url': ORIGIN + '/api/orders/' + str(i),
            'account': 'reference' if i == 2 else 'testing', 'evidence_id': i + 100} for i in (1, 2, 3)]
        return client

    def fetch(self, method, url, headers=None, account=None, authenticated=False, **kwargs):
        owner = 'reference' if url.endswith('/2') else 'testing'
        value = reply(url, 200 if authenticated and account == owner else 403,
            json.dumps({'id': url.rsplit('/', 1)[-1], 'owner': owner}))
        value['evidence'].update(authenticated=authenticated, account=account)
        return value

    def test_objects_are_repeated_in_the_original_context_with_fresh_comparison_ids(self):
        client = self.client()
        result = extra.cross_account(client, [ORIGIN + '/'])
        self.assertEqual(result['compared'], 3)
        self.assertEqual(client.calls, 12)
        self.assertEqual(len(client.records), 12)
        for row in result['rows']:
            self.assertTrue(row['baseline_stable'])
            self.assertTrue(row['ownership_requires_confirmation'])
            self.assertNotEqual(row['baseline_evidence_id'], row['repeat_evidence_id'])
            self.assertTrue(all(c['result'] == 'denied' for c in row['comparisons']))

    def test_public_shared_objects_are_leads_not_automatic_leaks(self):
        def fetch(method, url, headers=None, **kwargs):
            value = reply(url, body='{"id":1,"visibility":"public"}')
            value['evidence'].update(authenticated=kwargs['authenticated'], account=kwargs['account'])
            return value
        result = extra.cross_account(self.client(fetch), [])
        self.assertTrue(all(r['ownership_requires_confirmation'] for r in result['rows']))
        self.assertTrue(all(c['result'] == 'same_content' for r in result['rows'] for c in r['comparisons']))
        self.assertIn('distinct users', ' '.join(result['limitations']))

    def test_distinct_object_ids_are_not_normalized_into_the_same_body(self):
        def fetch(method, url, headers=None, **kwargs):
            value = reply(url, body='{"id":"' + ('aaaaaaaa-1234' if kwargs['account'] == 'testing' else 'bbbbbbbb-5678') + '"}')
            value['evidence'].update(authenticated=kwargs['authenticated'], account=kwargs['account'])
            return value
        result = extra.cross_account(self.client(fetch), [])
        self.assertEqual(result['rows'][0]['comparisons'][0]['result'], 'different_content')

    def test_unstable_html_truncated_and_redacted_responses_cannot_prove_a_match(self):
        for mode in ('unstable', 'html', 'truncated', 'redacted', 'empty', 'wrong_account'):
            count = [0]
            def fetch(method, url, headers=None, **kwargs):
                count[0] += 1
                value = reply(url, body=json.dumps({'id': count[0] if mode == 'unstable' else 1}))
                value['evidence'].update(authenticated=kwargs['authenticated'], account=kwargs['account'])
                if mode == 'html': value['body'] = '<html>generic shell</html>'
                if mode == 'truncated': value['body_truncated'] = True
                if mode == 'redacted': value['body'] = '{"id":"[REDACTED]"}'
                if mode == 'empty': value['body'] = '{}'
                if mode == 'wrong_account': value['evidence']['authenticated'] = False
                return value
            with self.subTest(mode=mode):
                result = extra.cross_account(self.client(fetch), [])
                self.assertTrue(all(not r['baseline_stable'] for r in result['rows']))
                self.assertTrue(all(c['result'] == 'inconclusive' for r in result['rows'] for c in r['comparisons']))

    def test_one_account_still_has_an_anonymous_control(self):
        client = self.client(accounts=('testing',))
        result = extra.cross_account(client, [])
        self.assertFalse(result['second_account_available'])
        self.assertEqual(result['compared'], 2)
        self.assertTrue(all([c['account'] for c in r['comparisons']] == ['anonymous'] for r in result['rows']))
        self.assertEqual(client.calls, 6)

    def test_shared_budget_reserves_a_complete_group_and_skips_unsafe_candidates(self):
        client = self.client(limit=6)
        client.observations.insert(0, {'method': 'GET', 'url': ORIGIN + '/api/orders/1?token=private', 'account': 'testing'})
        result = extra.cross_account(client, [])
        self.assertEqual(client.calls, 4)
        self.assertEqual(result['compared'], 1)
        self.assertIn('route_sample_limit', client.gaps)
        self.assertTrue(all('token=' not in e['url'] for e in client.records))

    def test_black_or_unverified_or_unobserved_accounts_are_not_queried(self):
        for setup in ('black', 'unverified', 'unobserved'):
            client = self.client()
            if setup == 'black': client.scope.pop('authentication')
            if setup == 'unverified': client.verified_accounts = []
            if setup == 'unobserved': client.observations = []
            self.assertIn('not_applicable', extra.cross_account(client, [ORIGIN + '/api/orders/1']))
            self.assertEqual(client.calls, 0)

    def test_transport_failures_and_expired_contexts_remain_visible(self):
        client = self.client(lambda *a, **kw: {'error': 'transport_error'})
        result = extra.cross_account(client, [])
        self.assertIn('transport_error', client.gaps)
        self.assertIn('account_comparison_context_unverified', client.gaps)
        self.assertTrue(all(not r['baseline_stable'] for r in result['rows']))

    def test_runs_once_on_the_anonymous_pass(self):
        client = self.client(); client.account = 'testing'
        self.assertIn('deferred', extra.cross_account(client, []))


class SuiteTests(unittest.TestCase):
    def test_unexpected_mid_comparison_timeout_is_still_incomplete(self):
        clock = [1000.0]
        with patch('time.monotonic', lambda: clock[0]), tempfile.TemporaryDirectory() as folder:
            def fetch(method, url, headers=None, **kwargs):
                clock[0] += 35.0
                return reply(url, body='late reply')
            result, _ = deep.run(scope(), [], {}, 1030.0, fetch=fetch,
                directory=Path(folder), deep=True,
                functions=[('patchriot-bypass', '1', extra.bypass, 30, 40)])
        summary = json.loads(result['output_excerpt'])
        self.assertFalse(summary['coverage_complete'])
        self.assertIn('scanner_budget_reached', summary['collection_errors'])

    def test_slow_replies_leave_complete_comparisons_and_explicit_sampling_limits(self):
        for function in (extra.bypass, extra.inputs):
            with self.subTest(family=function.__name__), tempfile.TemporaryDirectory() as folder:
                clock = [1000.0]
                calls = []

                def fetch(method, url, headers=None, **kwargs):
                    clock[0] += 2.0
                    calls.append(url)
                    value = reply(url, body='owned fixture')
                    value['evidence'].update(method=method,
                        authenticated=kwargs.get('authenticated', False), account=kwargs.get('account', 'testing'))
                    return value

                sc = scope(authentication='session', auth_check_path='/private')
                access = {'verified': True, 'protected_url': ORIGIN + '/private'}
                with patch('time.monotonic', lambda: clock[0]):
                    result, parts = deep.run(sc, [], access, 1060.0, fetch=fetch,
                        directory=Path(folder), deep=True,
                        functions=[('patchriot-' + function.__name__, '1', function, 60, 40)])
                summary = json.loads(result['output_excerpt'])
                self.assertTrue(summary['coverage_complete'], summary)
                self.assertLessEqual(clock[0], 1060.0)
                self.assertTrue(all(n > 0 for n in summary['account_evidence_counts'].values()))
                detail = json.loads(parts[0]['output_excerpt'])
                self.assertIn('route_sample_limit', detail['gaps'])
                self.assertNotIn('scanner_budget_reached', detail['gaps'])
                self.assertTrue(all(c['result']['sampled_urls'] > 0 for c in detail['contexts']))

    def test_deep_mode_uses_deep_families_and_its_own_receipts(self):
        calls = []

        def fetch(method, url, headers=None, **kwargs):
            calls.append(url)
            return reply(url, 404, '') if 'missing' in url else reply(url, 200, '<script src="/a.js"></script>')
        with tempfile.TemporaryDirectory() as folder:
            result, parts = deep.run(scope(), [], {}, time.monotonic() + 60, fetch=fetch,
                                     directory=Path(folder), deep=True)
            self.assertEqual((Path(folder) / 'deep-results.json').exists(), True)
            self.assertFalse((Path(folder) / 'discovery-results.json').exists())
        self.assertEqual(result['tool'], 'patchriot-deep')
        self.assertIn('--deep-suite', result['arguments'])
        self.assertEqual({p['tool'] for p in parts}, {name for name, *_ in extra.FAMILIES})
        self.assertEqual(json.loads(result['output_excerpt'])['engine'], 'Patchriot deep checks')
        self.assertIsNone(result['failure'], result['output_excerpt'])
        self.assertTrue(json.loads(result['output_excerpt'])['coverage_complete'])

    def test_full_families_fit_their_budgets_and_preserve_black_grey_and_paired_evidence(self):
        for account_count in (0, 1, 2):
            with self.subTest(accounts=account_count), tempfile.TemporaryDirectory() as folder:
                sc, access, calls = scope(), {}, []
                if account_count:
                    sc.update(authentication='session', auth_check_path='/api/orders/1')
                    access['accounts'] = [{'account': a, 'verified': True,
                        'protected_url': ORIGIN + '/api/orders/1'}
                        for a in ('testing', 'reference')[:account_count]]
                if account_count == 2:
                    sc['account_policy'] = {'allow_password_changes': False}
                def fetch(method, url, headers=None, **kwargs):
                    calls.append((method, url, kwargs.get('authenticated'), kwargs.get('account')))
                    value = reply(url, 404 if 'missing' in url else 200,
                        'not found' if 'missing' in url else '<a href="/api/orders/1">orders</a>')
                    value['evidence'].update(method=method,
                        authenticated=kwargs.get('authenticated', False), account=kwargs.get('account', 'testing'))
                    return value
                result, parts = deep.run(sc, [], access, time.monotonic() + 60,
                    fetch=fetch, directory=Path(folder), deep=True)
                summary = json.loads(result['output_excerpt'])
                self.assertIsNone(result['failure'], summary)
                self.assertTrue(summary['coverage_complete'])
                self.assertTrue(all(p['failure'] is None for p in parts))
                self.assertTrue(all(c[1].startswith(ORIGIN + '/') for c in calls))
                self.assertEqual(set(summary['account_evidence_counts']),
                    {'anonymous', *('testing', 'reference')[:account_count]})
                self.assertTrue(all(n > 0 for n in summary['account_evidence_counts'].values()))

    def test_expired_deadline_and_missing_requested_login_stay_incomplete(self):
        for expired in (False, True):
            with self.subTest(expired=expired), tempfile.TemporaryDirectory() as folder:
                sc = scope(authentication='session', auth_check_path='/private')
                result, _ = deep.run(sc, [], {}, time.monotonic() + (-1 if expired else 30),
                    fetch=lambda m, u, h=None, **kw: reply(u), directory=Path(folder), deep=True)
                summary = json.loads(result['output_excerpt'])
                self.assertEqual(result['failure'], 'incomplete')
                self.assertFalse(summary['coverage_complete'])
                self.assertIn('account_context_unverified:testing', summary['collection_errors'])

    def test_a_raising_family_stays_incomplete_and_keeps_prior_requests(self):
        def broken(client, urls):
            client('GET', ORIGIN + '/')
            raise OSError('boom')
        with tempfile.TemporaryDirectory() as folder:
            result, _ = deep.run(scope(), [], {}, time.monotonic() + 60,
                                 fetch=lambda m, u, h=None, **k: reply(u, 200, 'ok'),
                                 directory=Path(folder), deep=True,
                                 functions=[('patchriot-surface', '1', broken, 10, 4)])
        summary = json.loads(result['output_excerpt'])
        self.assertFalse(summary['coverage_complete'])
        self.assertEqual(result['failure'], 'incomplete')
        self.assertIn('scanner_execution_incomplete', summary['collection_errors'])


if __name__ == '__main__':
    unittest.main()
