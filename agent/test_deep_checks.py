"""Owned fixtures: public parity, identity isolation, scope and honest failures."""
import os
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import deep_checks as deep

class DiscoveryTests(unittest.TestCase):
    def test_signed_in_browser_records_reach_the_public_comparison_pass(self):
        scope = {'origins': ['https://owned.example'], 'methods': ['GET'], 'authentication': 'session'}
        access = {'verified': True, 'protected_url': 'https://owned.example/private'}
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder); (directory / 'http-evidence').mkdir()
            (directory / 'http-evidence' / '7.json').write_text(json.dumps({
                'id': 7, 'method': 'GET', 'url': 'https://owned.example/api/orders/42',
                'status': 200, 'authenticated': True, 'account': 'testing'}))
            def comparison(client, urls):
                self.assertEqual(client.verified_accounts, ['testing'])
                self.assertEqual(client.observations[0]['evidence_id'], 7)
                return {}
            deep.run(scope, [], access, time.monotonic() + 30, directory=directory,
                     functions=[('patchriot-cross-account', '1', comparison, 10, 4)])
            examples = json.loads((directory / 'working-requests.json').read_text())['examples']
            self.assertEqual(examples[0]['account'], 'testing')

    def exercise(self, grey=False, paired=False, broken=False):
        scope={'origins':['https://owned.example'],'methods':['GET','HEAD','OPTIONS'],
               'tools':['scoped_discovery_v1']}
        access={}
        if grey:
            scope.update(authentication='basic',auth_check_path='/private')
            access={'accounts':[{'account':'testing','verified':not broken,'protected_url':'https://owned.example/private'}]}
        if paired:
            scope['account_policy']={'testing':'preserve','reference':'preserve'}
            access['accounts'].append({'account':'reference','verified':True,'protected_url':'https://owned.example/private'})
        calls=[]
        def fetch(method,url,headers=None,**kw):
            calls.append((method,url,kw.get('authenticated'),kw.get('account')))
            return {'body':'<a href="/api/public">public</a><a href="https://elsewhere.example/steal">injection</a><a href="/reset">unsafe</a>',
                    'evidence':{'id':len(calls),'method':method,'url':url,'status':200,
                    'authenticated':kw.get('authenticated',False),'account':kw.get('account','testing')}}
        def probes(client,urls):
            for url in urls[:2]:client('GET',url)
            return {'observed':True}
        with tempfile.TemporaryDirectory() as folder:
            result,parts=deep.run(scope,[],access,time.monotonic()+60,fetch=fetch,directory=Path(folder),
                functions=[('patchriot-probes','1',deep.route_checks,20,32),('ffuf','fixture',probes,10,8)])
            summary=json.loads(result['output_excerpt'])
            self.assertEqual(json.loads((Path(folder)/'discovery-results.json').read_text())['coverage_complete'],summary['coverage_complete'])
        return result,parts,summary,calls

    def test_grey_preserves_the_entire_public_fixture_sequence(self):
        black=self.exercise();grey=self.exercise(grey=True)
        self.assertTrue(black[2]['coverage_complete']);self.assertTrue(grey[2]['coverage_complete'])
        self.assertEqual(black[3],[call for call in grey[3]if not call[2]])
        self.assertTrue(grey[2]['authenticated_evidence_count']>0)
        self.assertFalse(any('elsewhere' in c[1] or '/reset' in c[1]for c in grey[3]))

    def test_reference_context_is_separate_and_both_receive_public_checks(self):
        _,_,summary,calls=self.exercise(grey=True,paired=True)
        self.assertTrue(summary['coverage_complete'])
        self.assertEqual(set(summary['account_evidence_counts']),{'anonymous','testing','reference'})
        self.assertTrue(all(n>0 for n in summary['account_evidence_counts'].values()))
        self.assertEqual({c[3]for c in calls if c[2]},{'testing','reference'})

    def test_failed_login_keeps_public_work_but_never_passes_grey(self):
        result,_,summary,calls=self.exercise(grey=True,broken=True)
        self.assertFalse(summary['coverage_complete']);self.assertEqual(result['failure'],'incomplete')
        self.assertTrue(summary['anonymous_evidence_count']>0)
        self.assertTrue(all(not c[2]for c in calls))
        self.assertIn('account_context_unverified:testing',summary['collection_errors'])

    def test_nested_links_cannot_expand_scope_or_submit_a_form(self):
        scope={'origins':['https://owned.example']}
        text='<form action="https://other.example/login"></form><a href="/api/items">ok</a><a href="//owned.example.evil/a">bad</a>'
        self.assertEqual(deep.extracted(text,'https://owned.example/',scope),['https://owned.example/api/items'])
        self.assertIsNone(deep.scoped_url('https://u:p@owned.example/','https://owned.example',scope))

    def test_timeout_without_evidence_is_not_a_success(self):
        with tempfile.TemporaryDirectory() as folder:
            result,_=deep.run({'origins':['https://owned.example'],'methods':['GET']},[],{},time.monotonic()-1,
                fetch=lambda *a,**k:self.fail('deadline must prevent target request'),directory=Path(folder),
                functions=[('zap','fixture',lambda *a:self.fail('expired'),1,1)])
        self.assertEqual(result['failure'],'incomplete')
        self.assertFalse(json.loads(result['output_excerpt'])['coverage_complete'])

    def test_tool_failure_retains_successful_request_and_failure(self):
        def broken(client,urls):
            client('GET',urls[0]);raise OSError('fixture scanner failed')
        with tempfile.TemporaryDirectory() as folder:
            result,parts=deep.run({'origins':['https://owned.example'],'methods':['GET']},[],{},time.monotonic()+10,
                fetch=lambda m,u,h=None,**kw:{'evidence':{'id':1,'url':u,'method':m,'status':200}},
                directory=Path(folder),functions=[('zap','fixture',broken,1,1)])
        self.assertEqual(result['evidence_ids'],[1]);self.assertEqual(parts[0]['failure'],'incomplete')
        self.assertFalse(json.loads(result['output_excerpt'])['coverage_complete'])

    def test_expired_authenticated_context_is_not_a_grey_success(self):
        scope = {'origins': ['https://owned.example'], 'methods': ['GET'],
                 'authentication': 'basic', 'auth_check_path': '/private'}
        access = {'verified': True, 'protected_url': 'https://owned.example/private'}
        calls = []
        def fetch(method, url, headers=None, **kwargs):
            calls.append(url)
            return {'evidence': {'id': len(calls), 'url': url, 'method': method,
                'status': 401 if kwargs.get('authenticated') else 200,
                'authenticated': kwargs.get('authenticated', False)}}
        def probe(client, urls):
            client('GET', urls[0])
            return {}
        with tempfile.TemporaryDirectory() as folder:
            result, _ = deep.run(scope, [], access, time.monotonic() + 30,
                fetch=fetch, directory=Path(folder), functions=[('zap', 'fixture', probe, 5, 2)])
        summary = json.loads(result['output_excerpt'])
        self.assertFalse(summary['coverage_complete'])
        self.assertEqual(summary['authenticated_evidence_count'], 0)
        self.assertIn('access_context_untested:testing', summary['collection_errors'])

    def test_unselected_groups_are_not_scheduled(self):
        import live_review
        from workflow import Workflow
        scope={'origins':['https://owned.example'],'methods':['GET'],
               'tools':['scoped_discovery_v1'],'check_groups':['public_mapping']}
        plan=live_review.discovery_plan('investigator',scope,[])
        self.assertEqual([p['tool']for p in plan],['patchriot-crawl'])
        with tempfile.TemporaryDirectory() as folder:
            flow=Workflow(scope,plan,lambda _:None,Path(folder))
            self.assertEqual(flow.node('public_signatures')['state'],'not_applicable')
            self.assertEqual(flow.node('public_analysis')['state'],'not_applicable')
            self.assertEqual(flow.node('public_mapping')['state'],'pending')

    def test_grey_schema_checks_receive_the_public_schema_in_their_own_context(self):
        calls = []
        scope = {'origins': ['https://owned.example'], 'methods': ['GET'],
                 'authentication': 'session', 'auth_check_path': '/private'}
        def fetch(method, url, headers=None, **kwargs):
            calls.append((url, kwargs.get('account'), kwargs.get('authenticated')))
            return {'body': '{}', 'evidence': {'id': len(calls), 'method': method, 'url': url,
                'status': 200, 'authenticated': kwargs.get('authenticated', False),
                'account': kwargs.get('account')}}
        def schema(client, urls):
            self.assertIn('https://owned.example/api/openapi.json', urls)
            client('GET', 'https://owned.example/api/openapi.json')
            client.gaps.append('schema_case_sample_limit')
            return {'executed_cases': 1, 'deferred_operations_count': 50}
        with tempfile.TemporaryDirectory() as folder, patch.object(deep, 'schema_checks', schema):
            receipt, parts = deep.run(scope, [], {'verified': True, 'protected_url': 'https://owned.example/private'},
                time.monotonic() + 60, fetch=fetch, directory=Path(folder),
                functions=[('schemathesis', 'fixture', schema, 20, 20)])
        self.assertEqual([call[2] for call in calls], [False, True])
        self.assertIsNone(receipt['failure'])
        detail = json.loads(receipt['output_excerpt'])
        self.assertEqual(detail['sampling_limits'], ['schema_case_sample_limit'])
        self.assertTrue(any('sampled' in text for text in detail['limitations']))

    def test_family_weights_share_the_existing_deadline_without_extending_it(self):
        clock, slices = [1000.0], []
        scope = {'origins': ['https://owned.example'], 'methods': ['GET'],
                 'authentication': 'session', 'auth_check_path': '/private'}
        def fetch(method, url, headers=None, **kwargs):
            return {'body': '{}', 'evidence': {'id': len(slices) + 1, 'url': url, 'status': 200,
                'authenticated': kwargs.get('authenticated', False), 'account': kwargs.get('account')}}
        def family(client, urls):
            duration = client.deadline - clock[0]
            slices.append(duration)
            client('GET', urls[0])
            clock[0] += duration
            return {'state': 'recorded'}
        with tempfile.TemporaryDirectory() as folder, patch('time.monotonic', lambda: clock[0]):
            deep.run(scope, [], {'verified': True, 'protected_url': 'https://owned.example/private'},
                1060.0, fetch=fetch, directory=Path(folder),
                functions=[('long', 'fixture', family, 90, 48), ('short', 'fixture', family, 30, 24)])
        self.assertEqual(slices, [22.5, 22.5, 7.5, 7.5])
        self.assertEqual(clock[0], 1060.0)

    @unittest.skipUnless(os.environ.get('PATCHRIOT_SCANNER_FIXTURE')=='1','requires built scanner image')
    def test_actual_scanner_bundle_black_and_grey_finish_without_external_network(self):
        for authenticated in (False, True):
            with self.subTest(authenticated=authenticated), tempfile.TemporaryDirectory() as folder:
                scope={'origins':['https://owned.example'],'methods':['GET','HEAD','OPTIONS'],'tools':['scoped_discovery_v1']}
                access={}
                if authenticated:
                    scope.update(authentication='basic',auth_check_path='/private')
                    access={'verified':True,'protected_url':'https://owned.example/private'}
                calls=[]
                def fetch(method,url,headers=None,**kwargs):
                    calls.append((url,kwargs.get('authenticated')))
                    missing=any(x in url for x in ('openapi','swagger','missing','security.txt','robots'))
                    return {'body':'not found' if missing else '<html><title>Owned fixture</title><body>Fixture</body></html>',
                        'evidence':{'id':len(calls),'url':url,'method':method,'status':404 if missing else 200,
                            'authenticated':kwargs.get('authenticated',False),'account':kwargs.get('account','testing'),
                            'headers':{'content-type':'text/html'}}}
                result,parts=deep.run(scope,[],access,time.monotonic()+600,fetch=fetch,directory=Path(folder))
                self.assertEqual(result['failure'],None,result['output_excerpt'])
                self.assertEqual({p['tool']for p in parts},{'patchriot-probes','ffuf','schemathesis','zap'})
                self.assertTrue(all(url.startswith('https://owned.example/')for url,_ in calls))
                if authenticated:self.assertTrue(any(a for _,a in calls))

if __name__=='__main__':unittest.main()
