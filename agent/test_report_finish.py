import time
import unittest
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
import report_finish


class ReportFinishTests(unittest.TestCase):
    def test_one_repair_preserves_history_and_requires_relay_validation(self):
        original = {'completed': True, 'final_response': 'missing citations', 'messages': [{'role': 'assistant', 'content': 'original observations'}]}
        for accepted in [True, False]:
            calls, events, turns = [], [], []
            def call(path, body):
                calls.append((path, body))
                return {'valid': accepted and body['report'] == 'repaired', 'schema': {'required': ['findings']}}
            def run(prompt, conversation_history):
                turns.append(prompt)
                self.assertIn('Never invent IDs', prompt)
                self.assertEqual(agent.max_iterations, 3)
                self.assertLessEqual(agent.run_budget_seconds, 180)
                conversation_history[0]['content'] = 'changed copy'
                return {'completed': True, 'final_response': 'repaired'}
            agent = SimpleNamespace(max_iterations=600, run_budget_seconds=3600, run_conversation=run)
            result = report_finish.finish(agent, original, time.monotonic() + 300, call=call, emit=lambda **e: events.append(e))
            self.assertEqual(result['final_response'], 'repaired' if accepted else 'missing citations')
            self.assertEqual(original['messages'][0]['content'], 'original observations')
            self.assertEqual(len(turns), 1)
            self.assertTrue(calls[1][1]['repair'])
            self.assertEqual((agent.max_iterations, agent.run_budget_seconds), (600, 3600))
            self.assertEqual(events[-1]['repaired'], accepted)

    def test_valid_failed_or_expiring_runs_do_not_start_another_model_turn(self):
        for completed, valid, seconds in [(True, True, 300), (False, False, 300), (True, False, 2)]:
            original = {'completed': completed, 'final_response': 'saved', 'messages': []}
            def forbidden(*args, **kwargs): raise AssertionError('unexpected paid turn')
            agent = SimpleNamespace(run_conversation=forbidden)
            self.assertIs(report_finish.finish(agent, original, time.monotonic() + seconds,
                call=lambda *args: {'valid': valid}), original)

    def test_provider_failure_keeps_original_and_restores_runtime_limits(self):
        original = {'completed': True, 'final_response': 'saved partial', 'messages': []}
        def failed(*args, **kwargs): raise RuntimeError('provider unavailable')
        agent = SimpleNamespace(max_iterations=600, run_budget_seconds=3600, run_conversation=failed)
        self.assertIs(report_finish.finish(agent, original, time.monotonic() + 300,
            call=lambda *args: {'valid': False, 'schema': {}}), original)
        self.assertEqual((agent.max_iterations, agent.run_budget_seconds), (600, 3600))


@unittest.skipUnless(os.environ.get('PATCHRIOT_HERMES_SMOKE') == '1', 'requires pinned isolated Hermes')
class RepairRuntimeTests(unittest.TestCase):
    def test_real_hermes_can_resume_once_for_validated_report_repair(self):
        calls = []
        valid = json.dumps({'summary': 'Owned fixture check', 'findings': [], 'limitations': ['No live target tested']})
        class Model(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                calls.append(body)
                content = valid if len(calls) > 1 else '{"summary":"missing findings and limitations"}'
                reply = {'id': 'owned-fixture', 'object': 'chat.completion', 'created': 1, 'model': 'owned-fixture',
                    'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': content}, 'finish_reason': 'stop'}],
                    'usage': {'prompt_tokens': 10, 'completion_tokens': 20, 'total_tokens': 30}}
                raw = json.dumps(reply).encode()
                self.send_response(200); self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Model)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        script = '''import json,sys,time
from run_agent import AIAgent
import report_finish
agent=AIAgent(model='owned-fixture',provider='custom',api_mode='chat_completions',base_url=sys.argv[1]+'/v1',
    api_key='local-fixture',enabled_toolsets=[],max_iterations=600,run_budget_seconds=240,max_tokens=2048,
    quiet_mode=True,skip_context_files=True,skip_memory=True,skip_background_review=True,checkpoints_enabled=False)
try:
    original=agent.run_conversation('Return an owned fixture report. No tools or target.')
    def validate(path,body):
        return {'valid':body['report']==sys.argv[2], 'schema':{'required':['summary','findings','limitations']}}
    repaired=report_finish.finish(agent,original,time.monotonic()+120,call=validate)
    assert repaired['final_response']==sys.argv[2], repaired
    assert agent.max_iterations==600
finally: agent.close()
'''
        try:
            with tempfile.TemporaryDirectory() as home:
                env = {'PATH': os.environ['PATH'], 'HOME': home, 'HERMES_HOME': home,
                       'PYTHONPATH': '/opt/hermes:/tests', 'PYTHONDONTWRITEBYTECODE': '1'}
                done = subprocess.run([sys.executable, '-c', script, f'http://127.0.0.1:{server.server_port}', valid],
                                      env=env, capture_output=True, text=True, timeout=60)
                self.assertEqual(done.returncode, 0, done.stderr[-3000:] + done.stdout[-1000:])
                self.assertEqual(len(calls), 2)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
