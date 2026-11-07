"""Owned synthetic fixtures; no model provider or target requests."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import baseline
import ares_web
import live_review
import web_tools
from workflow import Workflow, public_scope

class WorkflowTests(unittest.TestCase):
    def test_grey_runs_the_same_anonymous_public_pipeline_in_the_same_order(self):
        black = {'origins':['https://owned.example'],'methods':['GET','HEAD','OPTIONS'],
                 'tools':['artex_engine_v1'], 'objective':'Owned public fixture'}
        grey = dict(black, authentication='basic', auth_check_path='/private',
                    browser_login={'private':'fixture'}, session_login={'private':'fixture'},
                    wallet_login={'private':'fixture'}, objective='Signed-in work',
                    tools=['artex_engine_v1','browser_login_v1','authenticated_http_v1'])
        self.assertEqual(public_scope(black), public_scope(grey))
        traces = []
        for scope in (black, grey):
            trace=[]
            def request(method, url, headers=None, **kwargs):
                self.assertIs(kwargs.get('authenticated'), False)
                trace.append((method,url,kwargs))
                return {'evidence':{'id':len(trace),'status':200},'body':'fixture'}
            def tool(name):
                def run(origin, deadline, fetch, **kwargs):
                    fetch('GET', origin + '/' + name)
                    return {'tool':name,'exit_code':0,'evidence_ids':[len(trace)]}
                return run
            def base(scope, deadline, fetch, record):
                self.assertEqual(scope, public_scope(black))
                return tool('patchriot-baseline')(scope['origins'][0],deadline,fetch)
            with tempfile.TemporaryDirectory() as temp, patch.object(web_tools,'request',request), \
                    patch.object(baseline,'run',base), patch.object(web_tools,'crawl',tool('patchriot-crawl')), \
                    patch.object(web_tools,'scanner',tool('nuclei')), patch.object(ares_web,'run',tool('ares-web-surface')), \
                    patch.object(web_tools,'controls',lambda origin,deadline,previous,fetch: tool('controls')(origin,deadline,fetch)):
                events=[]
                flow=Workflow(scope,live_review.discovery_plan('investigator',scope,[]),events.append,Path(temp))
                report=web_tools.run(scope,[],directory=Path(temp),workflow=flow)
                self.assertEqual([r['tool'] for r in report['tool_runs']],
                    ['patchriot-baseline','patchriot-crawl','nuclei','ares-web-surface','controls'])
                self.assertEqual([n['state'] for n in flow.value['checks'][:4]],['recorded']*4)
            traces.append(trace)
        self.assertEqual(*traces)

    def test_reuse_rejects_authenticated_missing_or_other_origin_receipts(self):
        scope={'origins':['https://owned.example'],'tools':[]}
        good={'role':'investigator','evidence':[{'id':1,'status':200,'url':'https://owned.example/'}],
              'tool_runs':[{'tool':'nuclei','exit_code':0,'evidence_ids':[1]}]}
        def action(report):
            return next(p['action'] for p in live_review.discovery_plan('reproducer',scope,[report]) if p['tool']=='nuclei')
        self.assertEqual(action(good),'reuse')
        for key,value in [('authenticated',True),('login',True),('url','https://other.example/'),('status',None)]:
            bad=copy.deepcopy(good);bad['evidence'][0][key]=value
            self.assertEqual(action(bad),'recover')
        bad=copy.deepcopy(good);bad['tool_runs'][0]['evidence_ids']=[]
        self.assertEqual(action(bad),'recover')

    def test_combined_engine_reuse_requires_anonymous_evidence_too(self):
        scope = {'origins': ['https://owned.example'], 'tools': ['artex_engine_v1']}
        previous = {'role': 'investigator', 'evidence': [
            {'id': 1, 'status': 401, 'url': 'https://owned.example/private'},
            {'id': 2, 'status': 200, 'url': 'https://owned.example/private', 'authenticated': True}],
            'tool_runs': [{'tool': 'artex-engine', 'exit_code': 0, 'evidence_ids': [1, 2]}]}
        def action():
            return next(p['action'] for p in live_review.discovery_plan('reproducer', scope, [previous]) if p['tool'] == 'artex-engine')
        self.assertEqual(action(), 'reuse')
        previous['tool_runs'][0]['evidence_ids'] = [2]
        self.assertEqual(action(), 'recover')

    def test_failed_public_work_remains_incomplete_when_grey_nodes_exist(self):
        scope={'origins':['https://owned.example'],'tools':[],'authentication':'basic'}
        with tempfile.TemporaryDirectory() as temp:
            events=[];flow=Workflow(scope,[],events.append,Path(temp))
            flow.begin('nuclei');flow.finish('nuclei',[{'exit_code':1,'failure':'timeout','evidence_ids':[]}])
            self.assertEqual(flow.node('public_signatures')['state'],'incomplete')
            self.assertEqual(flow.node('authentication')['state'],'pending')
            self.assertEqual(json.loads((Path(temp)/'workflow.json').read_text()),events[-1])
            self.assertEqual(events[0]['checks'][2]['state'],'pending')
