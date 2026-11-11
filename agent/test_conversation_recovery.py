import copy
import json
import time
import unittest
from unittest.mock import Mock, patch
import conversation_recovery as recovery


class ConversationRecoveryTests(unittest.TestCase):
    def failure(self):
        return {'completed': False, 'failed': True, 'compression_exhausted': True,
                'turn_exit_reason': 'context_compression_exhausted',
                'failure_reason': 'context_overflow', 'messages': [{'content': 'large transcript'}]}

    def test_one_fresh_continuation_uses_existing_budget_and_validates_disclosed_report(self):
        failed = self.failure(); original = copy.deepcopy(failed)
        agent = Mock(); agent.run_conversation.return_value = {'completed': True, 'failed': False,
            'final_response': json.dumps({'summary':'Saved checks reviewed', 'findings':[], 'limitations':['No cross-account proof']})}
        factory = Mock(return_value=agent); call = Mock(return_value={'valid':True})
        result = recovery.recover(failed, 'Approved role', time.monotonic()+300, factory, call=call)
        self.assertTrue(result['completed']); self.assertFalse(result['failed'])
        self.assertEqual(failed, original)
        seconds, turns = factory.call_args.args
        self.assertLessEqual(seconds,235); self.assertEqual(turns,29)
        self.assertEqual(agent.run_conversation.call_count,1)
        self.assertFalse(agent.run_conversation.call_args.kwargs, 'Never replay the overflowing history')
        self.assertNotIn('large transcript',agent.run_conversation.call_args.args[0])
        self.assertIn(recovery.LIMITATION,json.loads(result['final_response'])['limitations'])
        self.assertEqual(json.loads(call.call_args.args[1]['report'])['findings'],[])
        agent.close.assert_called_once()

    def test_failed_or_invalid_continuation_preserves_original_failure_without_looping(self):
        for resumed in [self.failure(), {'completed':True,'final_response':'not JSON'},
                        {'completed':True,'final_response':json.dumps({'summary':'x','findings':[],'limitations':['x']*8})}]:
            failed=self.failure();agent=Mock();agent.run_conversation.return_value=resumed
            factory=Mock(return_value=agent)
            result=recovery.recover(failed,'Approved role',time.monotonic()+500,factory,call=Mock(return_value={'valid':True}))
            self.assertIs(result,failed);factory.assert_called_once();agent.close.assert_called_once()

    def test_no_restart_for_provider_failure_success_or_target_text(self):
        for result in [{'completed':True,'final_response':'context_overflow'},
                       {'failed':True,'failure_reason':'provider_unavailable'},
                       {**self.failure(),'compression_exhausted':False}]:
            factory=Mock()
            self.assertIs(recovery.recover(result,'role',time.monotonic()+500,factory),result)
            factory.assert_not_called()
        factory=Mock();failed=self.failure()
        self.assertIs(recovery.recover(failed,'role',time.monotonic()+20,factory),failed)
        factory.assert_not_called()

    def test_broker_rejection_cannot_be_relabelled_as_recovered(self):
        agent=Mock();agent.run_conversation.return_value={'completed':True,'final_response':json.dumps({'summary':'x','findings':[],'limitations':[]})}
        failed=self.failure()
        calls=Mock(side_effect=[{'valid':True},{'valid':False}])
        self.assertIs(recovery.recover(failed,'role',time.monotonic()+500,Mock(return_value=agent),call=calls),failed)
        agent.close.assert_called_once()

    def test_formatting_repair_shares_the_continuation_deadline(self):
        resumed={'completed':True,'final_response':json.dumps({'summary':'x','findings':[],'limitations':[]})}
        agent=Mock();agent.run_conversation.return_value=resumed;factory=Mock(return_value=agent)
        with patch.object(recovery.time,'monotonic',return_value=100), patch.object(recovery.report_finish,'finish',return_value=resumed)as finish:
            recovery.recover(self.failure(),'role',900,factory,call=Mock(return_value={'valid':True}))
        factory.assert_called_once_with(555,29)
        self.assertEqual(finish.call_args.args[2],700, 'Repair must stay inside the same ten minutes')


if __name__ == '__main__':
    unittest.main()
