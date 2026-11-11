"""Owned fixtures for the optional deep families; no network."""
import itertools
import json
from pathlib import Path
import tempfile
import time
import unittest

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


class Client:
    """Minimal stand-in for the recording request client."""

    def __init__(self, fetch, sc=None, account=None, limit=40):
        self.fetch, self.scope, self.account = fetch, sc or scope(), account
        self.deadline, self.limit, self.calls, self.records, self.gaps = time.monotonic() + 60, limit, 0, [], []

    def __call__(self, method, url, headers=None, **kwargs):
        self.calls += 1
        reply = self.fetch(method, url, headers, account=self.account, **kwargs)
        reply['evidence'].setdefault('id', len(self.records) + 1)
        self.records.append(reply['evidence'])
        return reply


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
    def sc(self):
        return scope(authentication='session', account_policy={'allow_password_changes': False})

    def fetch(self, method, url, headers=None, account=None, **kwargs):
        if url.endswith('/orders/2'):
            return reply(url, 200, '{"owner":"b"}') if account == 'reference' else reply(url, 403, 'no')
        if url.endswith('/orders/3'):
            return reply(url, 200, '{"owner":"a"}' if account != 'reference' else '{"owner":"b"}')
        return reply(url, 200, '{"owner":"a"}') if account != 'reference' else reply(url, 403, 'no')

    def test_denied_object_for_the_other_account_is_flagged(self):
        client = Client(self.fetch, sc=self.sc())
        detail = extra.cross_account(client, [ORIGIN + '/api/orders/1', ORIGIN + '/api/orders/2',
                                             ORIGIN + '/api/orders/3'])
        verdicts = {value for row in detail['rows'] for key, value in row.items()
                    if key in ('testing', 'reference', 'anonymous')}
        self.assertIn('denied_for_other', verdicts)
        self.assertIn('differs', verdicts)
        # The account clients' records are merged so receipts stay honest.
        self.assertGreaterEqual(len(client.records), 4)

    def test_black_box_does_not_claim_account_checks_or_fail_for_no_account(self):
        client = Client(self.fetch)
        detail = extra.cross_account(client, [ORIGIN + '/api/orders/1'])
        self.assertEqual(client.gaps, [])
        self.assertIn('not_applicable', detail)
        self.assertEqual(client.calls, 0)

    def test_authenticated_transport_failures_are_not_lost_when_merging_accounts(self):
        def fetch(method, url, headers=None, **kwargs):
            if kwargs.get('authenticated'):
                return {'error': 'transport_error'}
            return reply(url)
        client = Requests(self.sc(), time.monotonic() + 60, fetch, limit=40)
        extra.cross_account(client, [ORIGIN + '/api/orders/1'])
        self.assertIn('transport_error', client.gaps)

    def test_runs_once_on_the_anonymous_pass(self):
        client = Client(self.fetch, sc=self.sc(), account='testing')
        self.assertIn('deferred', extra.cross_account(client, [ORIGIN + '/api/orders/1']))


class SuiteTests(unittest.TestCase):
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
