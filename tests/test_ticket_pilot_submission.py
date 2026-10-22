"""Simulated sends, native signed outboxes and fabricated two-node evidence only."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

import test_ticket_pilot_binding as harness
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_ticket_observer as native
import ticket_pilot_binding as binding
import ticket_pilot_private as private
import ticket_pilot_submission as submission


class SubmissionTests(unittest.TestCase):
    def setUp(self):
        self.h = harness.PilotBindingTests(); self.h.setUp()
        self.transport = submission.SimulatedTransport()
        self.c = self.open(create=True); self.h.c = self.c; self.c.recover()

    def open(self,create=False,**kwargs):
        h = self.h
        c = submission.Controller(h.secret/'submission-component',h.secret/'submission-authority/service.sqlite',
            h.claims,h.review,lambda:h.clock[0],observations=kwargs.pop('observations',h.pair),
            transport=kwargs.pop('transport',self.transport),create=create,reviewer=h.reviewer,worker=h.worker,**kwargs)
        h.controllers.append(c); return c

    def tearDown(self): self.h.tearDown()

    def prepare(self):
        self.h.preflight(); self.h.prepare_issue()

    def issued(self):
        self.prepare(); self.c.submit_simulated('issue'); self.h.clock[0]=101
        rpc=deepcopy(self.h.state()['issue_record']['signed_rpc'])
        rpc['verboseData']=dict(transactionId=self.h.state()['issue_record']['transaction_id'])
        for t in self.h.pair.trackers:
            t.apply(native.fixture_scan(3,[4,5,6],transactions={4:[rpc]}),101)
            t.apply_utxos(self.h.utxos(t,'terminal',before=6),101)
        self.c.reconcile_observations()

    def terminal(self,branch='consume'):
        self.issued(); self.c.choose(branch)
        self.c.prepare('terminal',self.h.entry('terminal'),self.h.keys['ticket'])

    def observe_terminal(self,branch='consume'):
        rpc = deepcopy(self.h.state()['terminal_record']['signed_rpc'])
        rpc['verboseData'] = dict(transactionId=self.h.state()['terminal_record']['transaction_id'])
        self.h.clock[0] = 102
        for t in self.h.pair.trackers:
            t.apply(native.fixture_scan(6,[7,8,9],transactions={7:[rpc]}),102)
            t.apply_utxos(self.h.utxos(t,'terminal',before=9,found=False),102)
        self.c.reconcile_observations()

    def attempts(self):
        return json.loads(self.c._submission.db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()[0])['state']

    def test_saved_outbox_required_before_attempt(self):
        self.h.preflight()
        with self.assertRaises(private.Error): self.c.submit_simulated('issue')
        self.assertIsNone(self.attempts()['issue']['intent']); self.assertFalse(self.transport.calls)

    def test_exact_native_outbox_sent_once_without_key_or_signer(self):
        self.prepare(); record = self.h.state()['issue_record']
        with patch.object(private,'load_key') as key,patch.object(self.h.worker,'prepare') as signer:
            result = self.c.submit_simulated('issue')
            key.assert_not_called(); signer.assert_not_called()
        self.assertEqual(self.transport.calls,[dict(transaction_id=record['transaction_id'],signed_rpc=record['signed_rpc'])])
        self.assertEqual(result['submissions']['issue']['reply'],'REPORTED_ACCEPTED')
        self.assertEqual(result['mode'],submission.MODE); self.assertEqual(result['live_broadcasts'],0)
        self.assertNotIn('signed_rpc',private.canonical(result).decode())
        for path in self.h.keys.values(): self.assertNotIn(path.read_text(),private.canonical(result).decode())
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('issue')
        self.assertEqual(len(self.transport.calls),1)

    def test_intent_is_saved_before_effect(self):
        self.prepare(); send = self.transport.send
        def check(txid,rpc):
            self.assertEqual(self.attempts()['issue']['intent']['transaction_id'],txid)
            self.assertIsNone(self.attempts()['issue']['reply'])
            return send(txid,rpc)
        with patch.object(self.transport,'send',side_effect=check): self.c.submit_simulated('issue')

    def test_timeout_after_effect_never_retries(self):
        self.prepare(); send = self.transport.send
        def lost(txid,rpc): send(txid,rpc); raise TimeoutError('simulated lost reply')
        with patch.object(self.transport,'send',side_effect=lost): self.c.submit_simulated('issue')
        self.assertEqual(self.attempts()['issue']['reply'],'UNKNOWN')
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('issue')
        self.assertEqual(len(self.transport.calls),1)

    def test_rejected_reply_is_not_permission_to_retry(self):
        self.prepare()
        with patch.object(self.transport,'send',return_value=dict(transaction_id=self.h.state()['issue_record']['transaction_id'],accepted=False)):
            self.c.submit_simulated('issue')
        self.assertEqual(self.attempts()['issue']['reply'],'REPORTED_REJECTED')
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('issue')

    def test_wrong_id_or_malformed_reply_is_unknown(self):
        self.prepare()
        with patch.object(self.transport,'send',return_value=dict(transaction_id='00'*32,accepted=True)):
            self.c.submit_simulated('issue')
        self.assertEqual(self.attempts()['issue']['reply'],'UNKNOWN')

    def test_boolean_reply_must_be_exact(self):
        self.prepare()
        with patch.object(self.transport,'send',return_value=dict(transaction_id=self.h.state()['issue_record']['transaction_id'],accepted=1)):
            self.c.submit_simulated('issue')
        self.assertEqual(self.attempts()['issue']['reply'],'UNKNOWN')

    def test_stale_source_blocks_before_intent(self):
        self.prepare(); self.h.clock[0] = 106
        with self.assertRaises(private.Error): self.c.submit_simulated('issue')
        self.assertIsNone(self.attempts()['issue']['intent']); self.assertFalse(self.transport.calls)

    def test_changed_positive_entry_blocks_saved_outbox(self):
        self.prepare()
        for t in self.h.pair.trackers:
            t.apply_source_utxos(self.h.utxos(t,daa=124),100)
        with self.assertRaises(private.Error): self.c.submit_simulated('issue')
        self.assertIsNone(self.attempts()['issue']['intent']); self.assertFalse(self.transport.calls)

    def test_expiry_after_reservation_leaves_uncertain_attempt(self):
        self.prepare()
        self.c.hook=lambda s:self.h.clock.__setitem__(0,106) if s=='submission:reserved' else None
        with self.assertRaises(private.Error): self.c.submit_simulated('issue')
        self.assertIsNotNone(self.attempts()['issue']['intent']); self.assertFalse(self.transport.calls)
        self.c.hook=lambda _:None
        for t in self.h.pair.trackers:
            t.apply(native.fixture_scan(3),106); t.apply_source_utxos(self.h.utxos(t),106)
        self.c.reconcile_observations()
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('issue')

    def test_reorg_after_reservation_blocks_effect_and_preserves_intent(self):
        self.prepare()
        def hook(stage):
            if stage=='submission:reserved': self.h.b.apply(native.fixture_scan(3,[4],removed=[3,2,1]),100)
        self.c.hook=hook
        with self.assertRaises(private.Error): self.c.submit_simulated('issue')
        self.assertIsNotNone(self.attempts()['issue']['intent']); self.assertFalse(self.transport.calls)

    def test_reopen_after_reservation_fences_old_writer_before_send(self):
        self.prepare()
        self.c.hook=lambda s:self.open() if s=='submission:reserved' else None
        with self.assertRaises(private.Error): self.c.submit_simulated('issue')
        self.assertFalse(self.transport.calls)

    def test_slow_transport_identity_read_is_followed_by_fresh_gate(self):
        self.prepare(); check=self.transport.check; count=[0]
        def slow():
            check(); count[0]+=1
            if count[0]==3: self.h.clock[0]=106
        with patch.object(self.transport,'check',side_effect=slow):
            with self.assertRaises(private.Error): self.c.submit_simulated('issue')
        self.assertFalse(self.transport.calls)

    def test_change_after_final_sample_can_precede_effect_counterexample(self):
        self.prepare(); send=self.transport.send
        def reorg(txid,rpc): self.h.b.unavailable(); return send(txid,rpc)
        with patch.object(self.transport,'send',side_effect=reorg): self.c.submit_simulated('issue')
        self.assertEqual(len(self.transport.calls),1)
        with self.assertRaises(private.Error): self.c.reconcile_submission('issue')

    def test_accepted_reply_is_not_confirmation(self):
        self.prepare(); self.c.submit_simulated('issue')
        result=self.c.reconcile_submission('issue')
        self.assertFalse(result['current_exact_observed']); self.assertFalse(result['retry_allowed'])
        self.assertEqual(result['scope'],'REVOCABLE_TRUSTED_NODE_OBSERVATION')

    def test_exact_issuance_reconciles_without_new_effect(self):
        self.issued(); saved=self.attempts()
        with patch.object(self.transport,'send') as send,patch.object(self.h.worker,'prepare') as signer:
            self.assertTrue(self.c.reconcile_submission('issue')['current_exact_observed'])
            send.assert_not_called(); signer.assert_not_called()
        self.assertEqual(saved,self.attempts())

    def test_observed_acceptance_without_local_intent_is_not_reconciled(self):
        self.h.issued()
        with self.assertRaises(private.Error): self.c.reconcile_submission('issue')
        self.assertIsNone(self.attempts()['issue']['intent'])

    def test_terminal_attempt_requires_issue_attempt(self):
        self.h.terminal()
        with self.assertRaises(private.Error): self.c.submit_simulated('terminal')
        self.assertIsNone(self.attempts()['terminal']['intent'])

    def test_stale_terminal_view_blocks_before_terminal_intent(self):
        self.terminal(); self.h.clock[0]=107
        with self.assertRaises(private.Error): self.c.submit_simulated('terminal')
        self.assertIsNone(self.attempts()['terminal']['intent'])
        self.assertEqual(len(self.transport.calls),1)

    def test_consumption_and_issue_observed_after_ticket_spent(self):
        self.terminal(); self.c.submit_simulated('terminal'); self.observe_terminal()
        self.assertTrue(self.c.reconcile_submission('terminal')['current_exact_observed'])
        self.assertTrue(self.c.reconcile_submission('issue')['current_exact_observed'])
        self.assertEqual(len(self.transport.calls),2)

    def test_refund_observation_and_permanent_branch(self):
        self.terminal('refund'); self.c.submit_simulated('terminal'); self.observe_terminal('refund')
        self.assertTrue(self.c.reconcile_submission('terminal')['current_exact_observed'])
        with self.assertRaises(private.Error): self.c.choose('consume')

    def test_opposite_terminal_observation_does_not_confirm_selected_branch(self):
        self.terminal(); self.c.submit_simulated('terminal')
        # No alternate signature: observers deliberately trust node acceptance of unsigned RPC.
        rpc=deepcopy(next(x for x in self.h.review['review']['transactions'] if x['action']=='refund')['unsigned_rpc'])
        rpc['verboseData']=dict(transactionId=self.h.a.pins['refund']['transaction_id'])
        self.h.clock[0]=102
        for t in self.h.pair.trackers:
            t.apply(native.fixture_scan(6,[7,8,9],transactions={7:[rpc]}),102)
            t.apply_utxos(self.h.utxos(t,'terminal',before=9,found=False),102)
        self.c.reconcile_observations()
        self.assertFalse(self.c.reconcile_submission('terminal')['current_exact_observed'])

    def test_reorg_revokes_observation_preserving_attempt_outbox_and_branch(self):
        self.terminal(); self.c.submit_simulated('terminal'); self.observe_terminal()
        saved=self.c.status()
        for t in self.h.pair.trackers:
            t.apply(native.fixture_scan(9,removed=[9,8,7],target=6),102)
            t.apply_utxos(self.h.utxos(t,'terminal',before=6),102)
        self.c.reconcile_observations()
        self.assertFalse(self.c.reconcile_submission('terminal')['current_exact_observed'])
        self.assertEqual(saved,self.c.status())
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('terminal')

    def test_recovery_keeps_outbox_without_keys_and_requires_new_scans(self):
        self.prepare(); self.c.submit_simulated('issue'); saved=self.c.status()
        for path in self.h.keys.values(): path.unlink()
        self.c=self.open(); self.h.c=self.c; self.c.recover()
        self.assertEqual(saved,self.c.status())
        with self.assertRaises(private.Error): self.c.reconcile_submission('issue')
        for t in self.h.pair.trackers:
            t.apply(native.fixture_scan(3),100); t.apply_source_utxos(self.h.utxos(t),100)
        self.c.reconcile_observations()
        self.assertFalse(self.c.reconcile_submission('issue')['current_exact_observed'])
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('issue')
        self.assertEqual(len(self.transport.calls),1)

    def test_lost_reply_before_save_recovers_intent_and_never_sends_again(self):
        self.prepare()
        def hook(stage):
            if stage=='submission:returned': raise SystemExit('simulated crash')
        self.c.hook=hook
        with self.assertRaises(SystemExit): self.c.submit_simulated('issue')
        self.c=self.open(); self.h.c=self.c; self.c.recover()
        self.assertIsNotNone(self.attempts()['issue']['intent']); self.assertIsNone(self.attempts()['issue']['reply'])
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('issue')
        self.assertEqual(len(self.transport.calls),1)

    def test_actual_process_death_after_intent_commit_recovers_no_retry(self):
        self.prepare()
        # Fork retains configured test handles; child exits after component COMMIT before checkpoint.
        pid=os.fork()
        if pid==0:
            self.c.hook=lambda stage:os._exit(73) if stage=='p0-submission:saved' else None
            self.c.submit_simulated('issue'); os._exit(74)
        _,status=os.waitpid(pid,0); self.assertEqual(os.waitstatus_to_exitcode(status),73)
        with self.assertRaises(private.RecoveryRequired): self.c.status()
        self.c=self.open(); self.h.c=self.c; self.c.recover()
        self.assertIsNotNone(self.attempts()['issue']['intent'])
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('issue')
        self.assertFalse(self.transport.calls)

    def test_actual_process_death_after_effect_recovers_without_second_effect(self):
        self.prepare(); marker=self.h.root/'simulated-effect'
        pid=os.fork()
        if pid==0:
            def effect(txid,rpc):
                with marker.open('a') as f:
                    f.write(txid+'\n'); f.flush(); os.fsync(f.fileno())
                return dict(transaction_id=txid,accepted=True)
            self.transport.send=effect
            self.c.hook=lambda stage:os._exit(75) if stage=='submission:returned' else None
            self.c.submit_simulated('issue'); os._exit(76)
        _,status=os.waitpid(pid,0); self.assertEqual(os.waitstatus_to_exitcode(status),75)
        self.c=self.open(); self.h.c=self.c; self.c.recover()
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('issue')
        self.assertEqual(marker.read_text().splitlines(),[self.h.state()['issue_record']['transaction_id']])

    def test_lost_reply_checkpoint_recovers_same_result(self):
        self.prepare(); saves=[0]
        def hook(stage):
            if stage=='p0-submission:saved':
                saves[0]+=1
                if saves[0]==2: raise RuntimeError('lost checkpoint acknowledgment')
        self.c.hook=hook
        with self.assertRaises(RuntimeError): self.c.submit_simulated('issue')
        with self.assertRaises(private.RecoveryRequired): self.c.status()
        self.c=self.open(); self.h.c=self.c; self.c.recover()
        self.assertEqual(self.attempts()['issue']['reply'],'REPORTED_ACCEPTED')
        with self.assertRaises(private.RecoveryRequired): self.c.submit_simulated('issue')
        self.assertEqual(len(self.transport.calls),1)

    def test_private_outbox_restore_is_detected_before_submission_recovery(self):
        backup=self.h.root/'old-private.sqlite'; shutil.copy2(self.c.root/'pilot.sqlite',backup)
        self.prepare(); self.c.submit_simulated('issue'); self.c.close()
        shutil.copy2(backup,self.c.root/'pilot.sqlite'); self.c=self.open(); self.h.c=self.c
        with self.assertRaises(private.IntegrityError): self.c.recover()
        self.assertEqual(len(self.transport.calls),1)

    def test_joint_trusted_store_restore_can_repeat_effect_counterexample(self):
        self.prepare()
        paths=[self.c.root/'pilot.sqlite',self.c.root/'submission.sqlite',
               self.h.secret/'submission-authority/service.sqlite',self.h.claims]
        snapshots=[p.read_bytes() for p in paths]
        self.c.submit_simulated('issue'); self.c.close()
        for p,raw in zip(paths,snapshots): p.write_bytes(raw)
        self.c=self.open(); self.h.c=self.c; self.c.recover()
        for t in self.h.pair.trackers:
            t.apply(native.fixture_scan(3),100); t.apply_source_utxos(self.h.utxos(t),100)
        self.c.reconcile_observations(); self.c.submit_simulated('issue')
        self.assertEqual(len(self.transport.calls),2)
        self.assertEqual(self.transport.calls[0],self.transport.calls[1])

    def test_restored_submission_store_behind_checkpoint_halts(self):
        self.prepare(); backup=self.h.root/'old.sqlite'
        shutil.copy2(self.c.root/'submission.sqlite',backup)
        self.c.submit_simulated('issue'); self.c.close()
        shutil.copy2(backup,self.c.root/'submission.sqlite')
        self.c=self.open(); self.h.c=self.c
        with self.assertRaises(private.IntegrityError): self.c.recover()
        self.assertEqual(self.c._authority.db.execute('SELECT halted FROM meta').fetchone(),(1,))

    def test_record_tampering_blocks_transport(self):
        self.prepare(); db=self.c._journal.db
        raw=json.loads(db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()[0])
        raw['state']['issue_record']['signed_rpc']['mass']+=1
        db.execute('UPDATE events SET body=? WHERE seq=(SELECT MAX(seq) FROM events)',(json.dumps(raw),))
        with self.assertRaises(private.IntegrityError): self.c.submit_simulated('issue')
        self.assertFalse(self.transport.calls)

    def test_transport_policy_mutation_latches_halt(self):
        self.transport.name='replacement'
        with self.assertRaises(private.IntegrityError): self.c.status()
        self.assertEqual(self.c._authority.db.execute('SELECT halted FROM meta').fetchone(),(1,))

    def test_bound_preparation_cannot_open_submission_policy(self):
        with self.assertRaises(private.IntegrityError):
            binding.Controller(self.c.root,self.h.secret/'submission-authority/service.sqlite',self.h.claims,
                self.h.review,lambda:100,observations=self.h.pair,reviewer=self.h.reviewer,worker=self.h.worker)

    def test_reopen_requires_identical_simulated_transport_policy(self):
        with self.assertRaises(private.IntegrityError): self.open(transport=submission.SimulatedTransport('other'))

    def test_live_or_subclass_transport_rejected_before_store_creation(self):
        class Alternate(submission.SimulatedTransport): pass
        for candidate in (object(),Alternate()):
            with self.assertRaises(private.Error): self.open(transport=candidate)

    def test_missing_submission_store_is_never_recreated(self):
        self.c.close(); (self.c.root/'submission.sqlite').unlink()
        with self.assertRaises((private.Error,FileNotFoundError)): self.open()

    def test_reconciliation_staleness_blocks_even_with_historical_reply(self):
        self.issued(); self.h.clock[0]=107
        with self.assertRaises(private.Error): self.c.reconcile_submission('issue')
        self.assertEqual(self.attempts()['issue']['reply'],'REPORTED_ACCEPTED')
