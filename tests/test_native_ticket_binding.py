"""Actual fixture controller + native projections over fabricated accepted scans."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_ticket_binding as b
c,o=b.c,b.o


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.issue=o.fixture_pins()['issue']['plan'];self.worker=c.Worker();self.now=100
        self.pair=b.fixture_pair(self.root/'observations',self.issue,self.worker)
        self.control=self.open(create=True);self.control.recover();self.node=c.FakeNode()

    def open(self,create=False,pair=None):
        return b.Controller(self.root/'component',self.root/'independent/authority.sqlite',
                            self.issue,lambda:self.now,observations=self.pair if pair is None else pair,worker=self.worker,create=create)

    def tearDown(self):
        self.control.close()
        for t in self.pair.trackers:t.close()
        self.tmp.cleanup()

    def scan_issue(self,start=0,added=(1,2,3),at=None):
        at=self.now if at is None else at
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(start,added,transactions={added[0]:[o.fixture_rpc(t.summaries['issue'])]}),at)
            t.apply_utxos(o.fixture_utxos(t.summaries,before=added[0]),at)

    def issued(self):
        info=self.control.prepare('issue');self.control.submit_fake('issue',self.node)
        self.scan_issue();self.assertTrue(self.control.observe_native('issue'));return info

    def chosen(self):
        self.issued();self.control.choose(self.pair.plans['consume'])

    def terminal_scan(self,action='consume'):
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(3,[4,5,6],transactions={4:[o.fixture_rpc(t.summaries[action])]}),self.now)

    def record(self,phase):
        row=self.control._journal.db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        return json.loads(row[0])['state'][phase+'_record']

    def restart(self):
        self.control.close();self.control=self.open();self.control.recover()

    def test_demo_uses_real_boundary_without_live_calls(self):
        result=b.demo();self.assertEqual(result['mode'],b.MODE)
        self.assertTrue(result['reorg_blocks_new_effect']);self.assertTrue(result['permanent_state_preserved'])
        self.assertEqual((result['real_rpc_calls'],result['broadcasts'],result['content_keys']),(0,0,0))

    def test_unsigned_pins_do_not_prepare_alternative_outboxes(self):
        with patch.object(self.worker,'prepare',side_effect=AssertionError('must not sign')):
            other=b.fixture_pair(self.root/'other-views',self.issue,self.worker)
        try:
            self.assertTrue(all(s['unsigned_pin'] for s in other.trackers[0].summaries.values()))
            self.assertNotIn('vm_verified',other.trackers[0].summaries['consume'])
            self.assertIsNone(self.record('terminal'))
        finally:
            for t in other.trackers:t.close()

    def test_current_exact_unspent_views_enable_branch_and_preparation(self):
        self.chosen();info=self.control.prepare('terminal')
        self.assertEqual(info['transaction_id'],self.pair.trackers[0].pins['consume']['transaction_id'])
        self.assertEqual(self.control.status()['charge']['count'],1)

    def test_no_durable_intent_cannot_be_reconciled(self):
        self.control.prepare('issue');self.scan_issue()
        with self.assertRaises(c.ModelError):self.control.observe_native('issue')
        with self.assertRaises(c.ModelError):self.control.choose(self.pair.plans['consume'])

    def test_fresh_fake_maps_cannot_bypass_binding(self):
        info=self.control.prepare('issue');self.control.submit_fake('issue',self.node)
        second=c.FakeNode();second.accept(info)
        with self.assertRaises(c.ModelError):self.control.observe_fake('issue',self.node,second)
        self.control.samples['issue']=(100,True)
        with self.assertRaises(c.ModelError):self.control.choose(self.pair.plans['consume'])

    def test_copied_status_dictionary_is_not_accepted(self):
        with self.assertRaises(c.ModelError):b.Pair({'state':'ISSUED_UNSPENT_OBSERVED'},self.pair.trackers[0])
        with self.assertRaises(c.ModelError):self.open(pair={})

    def test_one_node_or_missing_utxo_cannot_choose(self):
        self.control.prepare('issue');self.control.submit_fake('issue',self.node)
        first=self.pair.trackers[0]
        first.apply(o.fixture_scan(0,[1,2,3],transactions={1:[o.fixture_rpc(first.summaries['issue'])]}),100)
        first.apply_utxos(o.fixture_utxos(first.summaries),100)
        self.assertFalse(self.control.observe_native('issue'))
        second=self.pair.trackers[1]
        second.apply(o.fixture_scan(0,[1,2,3],transactions={1:[o.fixture_rpc(second.summaries['issue'])]}),100)
        self.assertFalse(self.control.observe_native('issue'))
        with self.assertRaises(c.ModelError):self.control.choose(self.pair.plans['consume'])
        second.apply_utxos(o.fixture_utxos(second.summaries),100)
        self.assertTrue(self.control.observe_native('issue'))

    def test_depth_and_backlog_must_clear_before_choice(self):
        self.control.prepare('issue');self.control.submit_fake('issue',self.node)
        self.scan_issue(added=(1,));self.assertFalse(self.control.observe_native('issue'))
        for t in self.pair.trackers:t.apply(o.fixture_scan(1,[2,3],target=99),100)
        self.assertFalse(self.control.observe_native('issue'))
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(3,target=3),100);t.apply_utxos(o.fixture_utxos(t.summaries),100)
        self.assertTrue(self.control.observe_native('issue'))

    def test_reorg_without_explicit_reobserve_stops_new_signing(self):
        self.chosen();before=self.control.status()
        t=self.pair.trackers[0];t.apply(o.fixture_scan(3,removed=[3,2,1],target=0),100)
        with patch.object(self.worker,'prepare',side_effect=AssertionError('must not sign')):
            with self.assertRaises(c.ModelError):self.control.prepare('terminal')
        self.assertEqual(self.control.status(),before)

    def test_reorg_keeps_exact_saved_outbox_branch_and_charge(self):
        self.chosen();self.control.prepare('terminal');before=self.control.status();raw=self.record('terminal')
        for t in self.pair.trackers:t.apply(o.fixture_scan(3,removed=[3,2,1],target=0),100)
        self.assertFalse(self.control.observe_native('issue'))
        with self.assertRaises(c.ModelError):self.control.submit_fake('terminal',self.node)
        with self.assertRaises(c.ModelError):self.control.choose(self.pair.plans['refund'])
        self.assertEqual(self.control.status(),before);self.assertEqual(self.record('terminal'),raw)
        with patch.object(self.worker,'prepare',side_effect=AssertionError('recovery must not sign')):
            self.control.prepare('terminal')
        self.assertEqual(self.node.calls,1)

    def test_stale_observation_blocks_even_after_successful_reconciliation(self):
        self.chosen();self.now=106
        with self.assertRaises(c.ModelError):self.control.prepare('terminal')
        self.assertEqual(self.control.status()['charge']['count'],1)

        # Even a read that started on time must finish within the age limit.
        self.now=111
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(3),111);t.apply_utxos(o.fixture_utxos(t.summaries),111)
        self.assertTrue(self.control.observe_native('issue'))
        combined=o.combined
        def slow(*args):
            result=combined(*args);self.now=117
            return result
        with patch.object(o,'combined',side_effect=slow):
            with self.assertRaises(c.ModelError):self.control.prepare('terminal')
        self.assertIsNone(self.record('terminal'))
        # A short read can cross the original deadline while still fresh.
        self.now=179
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(3),179);t.apply_utxos(o.fixture_utxos(t.summaries),179)
        self.assertTrue(self.control.observe_native('issue'))
        def crosses_deadline(*args):
            result=combined(*args);self.now=180
            return result
        with patch.object(o,'combined',side_effect=crosses_deadline):
            with self.assertRaises(c.ModelError):self.control.prepare('terminal')
        self.assertIsNone(self.record('terminal'))

    def test_failed_scan_cannot_reuse_old_positive_state(self):
        self.chosen();t=self.pair.trackers[0]
        with self.assertRaises(o.ObservationError):t.apply({},100)
        with self.assertRaises(c.ModelError):self.control.prepare('terminal')

    def test_controller_restart_requires_new_scans_and_reconciliation(self):
        self.chosen();before=self.control.status();self.restart()
        with self.assertRaises(c.ModelError):self.control.prepare('terminal')
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(3),100);t.apply_utxos(o.fixture_utxos(t.summaries),100)
        with self.assertRaises(c.ModelError):self.control.prepare('terminal')
        self.assertTrue(self.control.observe_native('issue'));self.control.prepare('terminal')
        self.assertEqual(self.control.status()['charge'],before['charge'])

    def test_observer_reopen_invalidates_cached_controller_sample(self):
        self.chosen();old=self.pair.trackers[0];new=o.TicketTracker(old.path,old.summaries,old.endpoint,
                old.bootstrap,reader=old.reader,min_successors=old.depth,max_age=old.max_age)
        old.close();self.pair.trackers=(new,self.pair.trackers[1])
        new.apply(o.fixture_scan(3),100);new.apply_utxos(o.fixture_utxos(new.summaries),100)
        with self.assertRaises(c.ModelError):self.control.prepare('terminal')
        self.assertTrue(self.control.observe_native('issue'));self.control.prepare('terminal')

    def test_different_context_is_rejected_before_branch_choice(self):
        self.issued();plan=deepcopy(self.pair.plans['consume']);plan['admission']['request_digest']='66'*32
        with self.assertRaises(c.ModelError):self.control.choose(plan)
        self.assertIsNone(self.control.status()['branch'])

    def test_expiry_still_blocks_new_signing_without_refunding_charge(self):
        self.chosen();self.now=200
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(3),200);t.apply_utxos(o.fixture_utxos(t.summaries),200)
        self.assertTrue(self.control.observe_native('issue'))
        with self.assertRaises(c.ModelError):self.control.prepare('terminal')
        with self.assertRaises(c.ModelError):self.control.choose(self.pair.plans['refund'])
        self.assertEqual(self.control.status()['charge']['count'],1)

    def test_unused_expired_refund_has_no_consume_charge(self):
        self.issued();self.now=200
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(3),200);t.apply_utxos(o.fixture_utxos(t.summaries),200)
        self.assertTrue(self.control.observe_native('issue'))
        self.control.choose(self.pair.plans['refund']);self.control.prepare('terminal')
        self.control.submit_fake('terminal',self.node);self.terminal_scan('refund')
        self.assertTrue(self.control.observe_native('terminal'))
        self.assertEqual(self.control.status()['branch'],'refund');self.assertIsNone(self.control.status()['charge'])

    def test_terminal_reconciliation_requires_its_own_intent(self):
        self.chosen();self.control.prepare('terminal');self.terminal_scan()
        with self.assertRaises(c.ModelError):self.control.observe_native('terminal')
        self.assertEqual(self.control.status()['terminal_attempt'],'NONE')

    def test_consumption_reconciles_then_reorg_never_retries_or_changes_branch(self):
        self.chosen();self.control.prepare('terminal');self.control.submit_fake('terminal',self.node)
        self.terminal_scan();self.assertTrue(self.control.observe_native('terminal'));before=self.control.status()
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(6,removed=[6,5,4],target=3),100)
            t.apply_utxos(o.fixture_utxos(t.summaries,before=3),100)
        self.assertFalse(self.control.observe_native('terminal'))
        self.assertTrue(self.control.observe_native('issue'))
        self.assertEqual(self.control.submit_fake('terminal',self.node),'RECONCILE_ONLY')
        self.assertEqual(self.control.status(),before);self.assertEqual(self.node.calls,2)

    def test_opposite_terminal_observation_does_not_reconcile_saved_consume(self):
        self.chosen();self.control.prepare('terminal');self.control.submit_fake('terminal',self.node)
        self.terminal_scan('refund');self.assertFalse(self.control.observe_native('terminal'))
        self.assertEqual(self.control.status()['terminal_attempt'],'STARTED')
        with self.assertRaises(c.ModelError):self.control.choose(self.pair.plans['refund'])

    def test_lost_fake_reply_reconciles_from_scans_without_resubmission(self):
        self.chosen();self.control.prepare('terminal');self.node.lose_reply=True
        with self.assertRaises(c.ModelError):self.control.submit_fake('terminal',self.node)
        before=self.node.calls;self.restart();self.terminal_scan()
        self.assertTrue(self.control.observe_native('terminal'))
        self.assertEqual(self.control.submit_fake('terminal',self.node),'RECONCILE_ONLY')
        self.assertEqual(self.node.calls,before)

    def test_chain_change_between_intent_and_final_lease_blocks_effect(self):
        self.chosen();self.control.prepare('terminal')
        def hook(stage):
            if stage=='terminal-intent:acknowledged':
                for t in self.pair.trackers:t.apply(o.fixture_scan(3,removed=[3,2,1],target=0),100)
        self.control.hook=hook
        with self.assertRaises(c.ModelError):self.control.submit_fake('terminal',self.node)
        self.assertEqual(self.node.calls,1);self.assertEqual(self.control.status()['terminal_attempt'],'STARTED')
        self.control.hook=lambda _:None
        self.assertEqual(self.control.submit_fake('terminal',self.node),'RECONCILE_ONLY')

    def test_bound_database_cannot_reopen_as_legacy_fake_controller(self):
        self.chosen();self.control.close()
        with self.assertRaises(c.IntegrityError):
            c.Controller(self.root/'component',self.root/'independent/authority.sqlite',
                         self.issue,lambda:100,worker=self.worker)
        self.control=self.open();self.control.recover()

    def test_changed_policy_or_endpoint_cannot_reopen_original_stores(self):
        self.chosen();self.control.close();other=b.fixture_pair(self.root/'other',self.issue,self.worker,min_successors=3)
        try:
            with self.assertRaises(c.IntegrityError):self.open(pair=other)
        finally:
            for t in other.trackers:t.close()
        self.control=self.open();self.control.recover()

    def test_mutated_pins_are_not_shared_with_pinned_snapshot(self):
        self.issued();self.pair.trackers[0].pins['issue']['payload']='00'
        with self.assertRaises(c.IntegrityError):self.control.choose(self.pair.plans['consume'])

    def test_replaced_pair_identity_is_rejected(self):
        self.chosen();self.pair.id='00'*32
        with self.assertRaises(c.IntegrityError):self.control.prepare('terminal')

    def test_component_restore_behind_authority_still_halts(self):
        self.issued();backup=self.root/'backup';shutil.copytree(self.root/'component',backup)
        self.control.choose(self.pair.plans['consume']);self.control.close()
        shutil.rmtree(self.root/'component');shutil.copytree(backup,self.root/'component')
        self.control=self.open()
        with self.assertRaises(c.IntegrityError):self.control.recover()

    def test_observer_paths_cannot_share_controller_backup_or_authority_directory(self):
        t=self.pair.trackers[0];original=t.path
        try:
            for path in [self.root/'component/observer.sqlite',self.root/'independent/observer.sqlite']:
                t.path=path.resolve();pair=b.Pair(*self.pair.trackers)
                with self.assertRaises(c.ModelError):self.open(pair=pair)
        finally:t.path=original

    def test_public_status_never_exposes_saved_native_bytes(self):
        self.chosen();self.control.prepare('terminal')
        raw=json.dumps(self.control.status());signed=json.loads(self.record('terminal'))
        self.assertNotIn(signed['transaction']['inputs'][0]['signatureScript'],raw)
        self.assertNotIn('signature',raw)

    def test_same_host_and_same_database_are_rejected(self):
        a,d=self.pair.trackers
        with self.assertRaises(c.ModelError):b.Pair(a,a)
        host=d.host;d.host=a.host
        try:
            with self.assertRaises(c.ModelError):b.Pair(a,d)
        finally:d.host=host

    def test_unknown_native_ticket_spend_blocks_preparation(self):
        self.chosen();plan=deepcopy(self.pair.plans['consume']);plan['admission']['request_digest']='77'*32
        unknown=self.worker.pin(plan)
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(3,[4,5,6],transactions={4:[o.fixture_rpc(unknown)]}),100)
        with self.assertRaises(c.ModelError):self.control.prepare('terminal')
        self.assertEqual(self.control.status()['branch'],'consume')
        self.assertEqual(self.control.status()['charge']['count'],1)

    def test_native_id_projection_does_not_replace_full_saved_outbox_checks(self):
        self.control.prepare('issue');raw=self.record('issue');self.control.submit_fake('issue',self.node)
        tx=o.fixture_rpc(self.pair.trackers[0].summaries['issue'])
        tx['inputs'][0]['signatureScript']='abcd';tx['inputs'][0]['computeBudget']=101
        tx['storageMass']=99
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[tx]}),100)
            t.apply_utxos(o.fixture_utxos(t.summaries),100)
        self.assertTrue(self.control.observe_native('issue'))
        self.assertEqual(self.record('issue'),raw)
        # Contextual native acceptance is trusted; this synthetic RPC body is not VM proof.
        self.assertNotIn('signature',json.dumps(self.control.status()))

    def test_observation_store_restore_cannot_rewind_service_history(self):
        self.issued();backup=self.root/'observer-backup';shutil.copytree(self.root/'observations',backup)
        self.control.choose(self.pair.plans['consume']);self.control.prepare('terminal')
        self.control.submit_fake('terminal',self.node);self.terminal_scan()
        self.assertTrue(self.control.observe_native('terminal'));before=self.control.status()
        self.control.close()
        for t in self.pair.trackers:t.close()
        shutil.rmtree(self.root/'observations');shutil.copytree(backup,self.root/'observations')
        self.pair=b.fixture_pair(self.root/'observations',self.issue,self.worker)
        self.control=self.open();self.control.recover()
        for t in self.pair.trackers:
            t.apply(o.fixture_scan(3),100);t.apply_utxos(o.fixture_utxos(t.summaries),100)
        self.assertTrue(self.control.observe_native('issue'))
        self.assertEqual(self.control.status(),before)
        self.assertEqual(self.control.submit_fake('terminal',self.node),'RECONCILE_ONLY')
        with self.assertRaises(c.ModelError):self.control.choose(self.pair.plans['refund'])

    def test_chain_change_after_last_sample_is_explicit_nonatomic_counterexample(self):
        self.chosen();self.control.prepare('terminal')
        def hook(stage):
            if stage=='terminal:before_effect':
                for t in self.pair.trackers:t.apply(o.fixture_scan(3,removed=[3,2,1],target=0),100)
        self.control.hook=hook;self.control.submit_fake('terminal',self.node)
        self.assertEqual(self.node.calls,2)
        self.assertEqual(self.control.status()['terminal_attempt'],'STARTED')
        self.assertFalse(self.control.observe_native('terminal'))
        self.assertEqual(self.control.status()['charge']['count'],1)
