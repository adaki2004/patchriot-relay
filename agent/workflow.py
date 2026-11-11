"""Fixed public work first; credentials add work and never replace that plan."""
import copy
import json
from pathlib import Path

TOOLS = {
    'patchriot-baseline': 'public_baseline', 'patchriot-crawl': 'public_mapping',
    'nuclei': 'public_signatures', 'ares-web-surface': 'public_fingerprints',
    'patchriot-discovery': 'public_analysis', 'patchriot-deep': 'public_deep',
    'patchriot-surface': 'public_deep', 'patchriot-bypass': 'public_deep',
    'patchriot-headers': 'public_deep', 'patchriot-inputs': 'public_deep',
    'patchriot-cross-account': 'public_deep',
}
IDS = ['public_baseline', 'public_mapping', 'public_signatures', 'public_fingerprints',
       'public_analysis', 'public_deep', 'authentication', 'authenticated_checks', 'evidence_review']


def public_scope(scope):
    result = {key: copy.deepcopy(value) for key, value in scope.items()
              if key not in ('authentication', 'auth_check_path', 'session_login', 'wallet_login', 'browser_login', 'account_policy')}
    result['tools'] = [t for t in scope.get('tools', []) if t in ('scoped_discovery_v1', 'deep_checks_v1', 'active_web_v1', 'active_web_v2')]
    result['objective'] = ('Map and assess the approved public surface using anonymous requests. '
        'Run the recorded public checklist, investigate concrete leads and compare controls. '
        'Use only the saved methods and origins. POST, when permitted, is limited to disposable test data. '
        'Do not sign in, register accounts, guess credentials, send purchases or funds, load test, '
        'persist access or contact other origins. Record missing coverage and uncertainty.')
    return result


class Workflow:
    def __init__(self, scope, plan, emit, directory=Path('/work')):
        self.emit, self.directory = emit, directory
        self.value = {'version': 2, 'checks': [dict(id=id, state='pending', evidence_count=0) for id in IDS]}
        groups = scope.get('check_groups')
        for node in self.value['checks']:
            if node['id'] in TOOLS.values() and (
                    node['id'] not in groups if groups is not None else node['id'] == 'public_deep'):
                node['state'] = 'not_applicable'
            if node['id'] in ('authentication', 'authenticated_checks') and not scope.get('authentication'):
                node['state'] = 'not_applicable'
            if node['id'] == 'public_analysis' and not any(t in scope.get('tools', []) for t in ('scoped_discovery_v1',)):
                node['state'] = 'not_applicable'
        for entry in plan:
            if entry['action'] == 'reuse':
                self.node(TOOLS[entry['tool']]).update(state='reused', source_role=entry['source_role'])
            elif entry['action'] in ('reuse_partial', 'unavailable'):
                self.node(TOOLS[entry['tool']])['state'] = 'incomplete'
        self.publish()

    def node(self, id):
        return next(node for node in self.value['checks'] if node['id'] == id)

    def publish(self):
        (self.directory / 'workflow.json').write_text(json.dumps(self.value))
        self.emit(copy.deepcopy(self.value))

    def begin(self, tool):
        self.node(TOOLS[tool]).update(state='running', evidence_count=0)
        self.publish()

    def finish(self, tool, records):
        node = self.node(TOOLS[tool])
        refs = {id for r in records for id in r.get('evidence_ids', [])}
        complete = records and refs and all(r.get('evidence_ids') and r.get('exit_code') == 0 and not r.get('failure') and not r.get('output_truncated') for r in records)
        node.update(state='recorded' if complete else 'incomplete', evidence_count=len(refs))
        self.publish()
