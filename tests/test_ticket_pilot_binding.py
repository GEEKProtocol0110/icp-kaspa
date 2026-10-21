"""P0 signing gates with synthetic node pages and temporary unfunded keys."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_ticket_observer as native
import ticket_pilot_observer as observer
import ticket_pilot_private as private
import ticket_pilot_binding as binding
from ticket_pilot_review import Reviewer, fixture_plan


class PilotBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.secret=self.root/'private';self.secret.mkdir(mode=0o700)
        self.obs=self.root/'observations';self.obs.mkdir()
        self.keys={};self.plan=fixture_plan()
        self.plan.update(purpose='operator-unsigned-review',run_nonce='55'*32)
        self.plan['source']['transaction_id']='22'*32
        for role in ('funding','ticket','return'):
            key=ec.generate_private_key(ec.SECP256K1())
            self.plan[role+'_key']=key.public_key().public_numbers().x.to_bytes(32,'big').hex()
            path=self.secret/(role+'.key');path.write_text(key.private_numbers().private_value.to_bytes(32,'big').hex());path.chmod(0o600)
            self.keys[role]=path
        self.reviewer=Reviewer();self.worker=private.Worker();self.review=self.reviewer.make(self.plan)
        self.clock=[100];self.trackers=[];self.controllers=[]
        self.a=self.tracker('a');self.b=self.tracker('b');self.pair=binding.Pair(self.a,self.b)
        self.claims=self.secret/'authority/claims.sqlite';private.Controller.create_claims(self.claims)
        self.c=self.open(create=True);self.c.recover()

    def tracker(self,name):
        endpoint=f'wss://{name}.invalid/kaspa/testnet-10/wrpc/borsh'
        t=observer.Tracker(self.obs/(name+'.sqlite'),self.review,endpoint,native.fake_id(0),
                           reader=native.Reader(endpoint),reviewer=self.reviewer,min_successors=2,max_age=30)
        self.trackers.append(t);return t

    def open(self,create=False,**kwargs):
        c=binding.Controller(self.secret/'component',self.secret/'authority/service.sqlite',self.claims,
            self.review,lambda:self.clock[0],observations=kwargs.pop('observations',self.pair),
            create=create,reviewer=self.reviewer,worker=self.worker,**kwargs)
        self.controllers.append(c);return c

    def tearDown(self):
        for c in self.controllers:c.close()
        for t in self.trackers:t.close()
        self.tmp.cleanup()

    def entry(self,phase='issue',daa=123):
        return dict(amount=24_000_000 if phase=='issue' else 12_000_000,
                    scriptPublicKey='000020'+self.plan['funding_key' if phase=='issue' else 'ticket_key']+'ac',
                    blockDaaScore=daa,isCoinbase=False,covenantId=None)

    def utxos(self,t,phase='issue',before=3,found=True,daa=123):
        point=t.source if phase=='issue' else t.ticket
        return dict(node=native.fixture_scan(0)['node'],publicKey=t.funding_key if phase=='issue' else t.ticket_key,
                    **{'from':native.fake_id(before)},target=native.fake_id(before),
                    utxos=[dict(outpoint=dict(transactionId=point[0],index=point[1]),utxoEntry=self.entry(phase,daa))] if found else [])

    def preflight(self,reconcile=True):
        for t in self.pair.trackers:
            t.apply(native.fixture_scan(0,[1,2,3]),self.clock[0]);t.apply_source_utxos(self.utxos(t),self.clock[0])
        if reconcile:self.c.reconcile_observations()

    def prepare_issue(self):return self.c.prepare('issue',self.entry(),self.keys['funding'])

    def state(self):
        return json.loads(self.c._journal.db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()[0])['state']

    def issued(self):
        self.preflight();self.prepare_issue();self.clock[0]=101
        rpc=deepcopy(self.state()['issue_record']['signed_rpc'])
        rpc['verboseData']=dict(transactionId=self.state()['issue_record']['transaction_id'])
        for t in self.pair.trackers:
            t.apply(native.fixture_scan(3,[4,5,6],transactions={4:[rpc]}),101)
            t.apply_utxos(self.utxos(t,'terminal',before=6),101)
        self.c.reconcile_observations()

    def terminal(self,branch='consume'):
        self.issued();self.c.choose(branch)
        return self.c.prepare('terminal',self.entry('terminal'),self.keys['ticket'])

    def refresh_issued(self):
        for t in self.pair.trackers:
            t.apply(native.fixture_scan(6),self.clock[0]);t.apply_utxos(self.utxos(t,'terminal',before=6),self.clock[0])
        self.c.reconcile_observations()

    def test_new_work_requires_reconciled_handles_before_key_access(self):
        self.preflight(False)
        with patch.object(private,'load_key') as key,patch.object(self.worker,'prepare') as signer:
            with self.assertRaises(private.Error):self.prepare_issue()
            key.assert_not_called();signer.assert_not_called()
        self.assertFalse(self.state()['issue_started'])

    def test_matching_source_allows_exact_native_issue_and_private_status(self):
        self.preflight();result=self.prepare_issue()
        self.assertEqual(result['mode'],binding.MODE);self.assertEqual(result['broadcasts'],0)
        self.assertEqual(result['status_scope'],'HISTORICAL_OUTBOX_NOT_CURRENT_CHAIN_PROOF')
        self.assertTrue(self.worker.verify(self.state()['issue_record'])['vm_verified'])
        self.assertNotIn('signed_rpc',private.canonical(result).decode())
        for path in self.keys.values():self.assertNotIn(path.read_text(),private.canonical(result).decode())

    def test_stale_source_blocks_before_reservation_or_source_claim(self):
        self.preflight();self.clock[0]=106
        with patch.object(private,'load_key') as key:
            with self.assertRaises(private.Error):self.prepare_issue()
            key.assert_not_called()
        self.assertFalse(self.state()['issue_started'])
        self.assertEqual(self.c._claims.execute('SELECT COUNT(*) FROM claims').fetchone()[0],0)

    def test_signing_entry_must_match_complete_current_metadata(self):
        self.preflight()
        for key,bad in [('blockDaaScore',124),('amount',True),('scriptPublicKey','000051')]:
            entry=self.entry();entry[key]=bad
            with self.assertRaises(private.Error):self.c.prepare('issue',entry,self.keys['funding'])
            self.assertFalse(self.state()['issue_started'])
        for invalid in (None,{},0,True):
            with self.assertRaises(private.Error):self.c.prepare('issue',invalid,self.keys['funding'])
            self.assertFalse(self.state()['issue_started'])

    def test_node_disagreement_missing_utxo_or_unavailable_view_blocks(self):
        self.preflight()
        for kind in ('different','absent','unavailable'):
            if kind=='unavailable':self.b.unavailable()
            else:self.b.apply_source_utxos(self.utxos(self.b,found=kind!='absent',daa=124 if kind=='different' else 123),100)
            with self.assertRaises(private.Error):self.prepare_issue()
            self.assertFalse(self.state()['issue_started'])

    def test_copied_positive_status_cannot_replace_current_trackers(self):
        self.preflight();copied=observer.combined(self.a,self.b,100)
        self.b.unavailable()
        self.assertEqual(copied['state'],'TWO_NODE_SOURCE_UNSPENT_OBSERVED')
        with self.assertRaises(private.Error):self.prepare_issue()
        with self.assertRaises(private.Error):binding.Pair(copied,copied)

    def test_issuance_must_be_currently_observed_before_new_branch(self):
        self.preflight();self.prepare_issue()
        with self.assertRaises(private.Error):self.c.choose('consume')
        self.assertIsNone(self.state()['branch'])

    def test_consume_preparation_after_exact_issue_observation(self):
        result=self.terminal('consume')
        self.assertEqual(result['branch'],'consume');self.assertIsNotNone(self.state()['terminal_record'])

    def test_refund_preparation_after_exact_issue_observation(self):
        result=self.terminal('refund')
        self.assertEqual(result['branch'],'refund');self.assertIsNotNone(self.state()['terminal_record'])

    def test_terminal_entry_mismatch_blocks_without_new_reservation(self):
        self.issued();self.c.choose('consume');entry=self.entry('terminal',124)
        with self.assertRaises(private.Error):self.c.prepare('terminal',entry,self.keys['ticket'])
        self.assertFalse(self.state()['terminal_started'])

    def test_new_branch_requires_fresh_positive_ticket_metadata(self):
        self.issued();self.b.apply_utxos(self.utxos(self.b,'terminal',before=6,found=False),101)
        with self.assertRaises(private.Error):self.c.choose('refund')
        self.assertIsNone(self.state()['branch'])

    def test_expiry_after_intent_blocks_key_access_and_never_retries(self):
        self.preflight()
        self.c.hook=lambda stage:self.clock.__setitem__(0,106) if stage=='signing:reserved' else None
        with patch.object(private,'load_key') as key:
            with self.assertRaises(private.Error):self.prepare_issue()
            key.assert_not_called()
        self.assertTrue(self.state()['issue_started']);self.assertIsNone(self.state()['issue_record'])
        self.c.hook=lambda _:None
        for t in self.pair.trackers:
            t.apply(native.fixture_scan(3),106);t.apply_source_utxos(self.utxos(t),106)
        self.c.reconcile_observations()
        with self.assertRaises(private.RecoveryRequired):self.prepare_issue()

    def test_reorg_between_reservation_and_signing_blocks_new_signature(self):
        self.preflight()
        def hook(stage):
            if stage=='signing:reserved':self.b.apply(native.fixture_scan(3,[4],removed=[3,2,1]),100)
        self.c.hook=hook
        with patch.object(self.worker,'prepare') as signer:
            with self.assertRaises(private.Error):self.prepare_issue()
            signer.assert_not_called()
        self.assertTrue(self.state()['issue_started']);self.assertIsNone(self.state()['issue_record'])

    def test_key_read_delay_is_rechecked_before_native_signing(self):
        self.preflight();load=private.load_key
        def slow(path):
            secret=load(path);self.clock[0]=106;return secret
        with patch.object(private,'load_key',side_effect=slow),patch.object(self.worker,'prepare') as signer:
            with self.assertRaises(private.Error):self.prepare_issue()
            signer.assert_not_called()
        self.assertIsNone(self.state()['issue_record'])

    def test_saved_record_verification_delay_cannot_use_lease_entry_time(self):
        self.issued();verify=self.worker.verify
        def slow(record):
            result=verify(record);self.clock[0]=107;return result
        with patch.object(self.worker,'verify',side_effect=slow):
            with self.assertRaises(private.Error):self.c.choose('consume')
        self.assertIsNone(self.state()['branch'])

    def test_observer_read_delay_is_checked_at_completion(self):
        self.preflight();status=self.a.status
        def slow(now):
            result=status(now);self.clock[0]=106;return result
        with patch.object(self.a,'status',side_effect=slow),patch.object(private,'load_key') as key:
            with self.assertRaises(private.Error):self.prepare_issue()
            key.assert_not_called()
        self.assertFalse(self.state()['issue_started'])
        # Final handle/configuration reads can also take time before reservation.
        for t in self.pair.trackers:
            t.apply(native.fixture_scan(3),106);t.apply_source_utxos(self.utxos(t),106)
        self.c.reconcile_observations();sessions=self.pair.sessions;calls=[0]
        def slow_sessions():
            result=sessions();calls[0]+=1
            if calls[0]==3:self.clock[0]=112
            return result
        with patch.object(self.pair,'sessions',side_effect=slow_sessions):
            with self.assertRaises(private.Error):self.prepare_issue()
        self.assertFalse(self.state()['issue_started'])

    def test_positive_utxo_age_has_stricter_bound_than_tracker_policy(self):
        self.preflight();old=[deepcopy(t.source_sample) for t in self.pair.trackers];self.clock[0]=106
        for t,sample in zip(self.pair.trackers,old):
            t.apply(native.fixture_scan(3),106);t.source_sample=sample
        with self.assertRaises(private.Error):self.prepare_issue()
        self.assertFalse(self.state()['issue_started'])

    def test_change_after_final_sample_can_still_precede_signature(self):
        # Explicit non-atomicity counterexample, never advertised as prevention.
        self.preflight();prepare=self.worker.prepare
        def changed(*args):
            self.b.unavailable();return prepare(*args)
        with patch.object(self.worker,'prepare',side_effect=changed):self.prepare_issue()
        self.assertIsNotNone(self.state()['issue_record'])
        self.assertEqual(self.b.status(100)['state'],'SCAN_REQUIRED')

    def test_reorg_does_not_rewind_permanent_branch_or_saved_terminal(self):
        self.terminal('consume');saved=deepcopy(self.state())
        for t in self.pair.trackers:t.apply(native.fixture_scan(6,[7],removed=[6,5,4]),101)
        with self.assertRaises(private.Error):self.c.choose('refund')
        self.c.prepare('terminal',{},self.root/'missing.key')
        self.assertEqual(self.state(),saved)

    def test_recovery_reuses_exact_saved_outbox_with_no_observer_or_key(self):
        self.preflight();self.prepare_issue();saved=deepcopy(self.state()['issue_record'])
        self.c=self.open();self.c.recover()
        with patch.object(private,'load_key') as key,patch.object(self.worker,'prepare') as signer:
            self.c.prepare('issue',{},self.root/'missing.key');key.assert_not_called();signer.assert_not_called()
        self.assertEqual(self.state()['issue_record'],saved)
        with self.assertRaises(private.Error):self.c.choose('consume')

    def test_recovery_requires_new_scan_and_explicit_reconciliation(self):
        self.issued();self.c=self.open();self.c.recover()
        self.assertEqual(self.a.status(101)['state'],'SCAN_REQUIRED')
        for t in self.pair.trackers:
            t.apply(native.fixture_scan(6),101);t.apply_utxos(self.utxos(t,'terminal',before=6),101)
        with self.assertRaises(private.Error):self.c.choose('consume')
        self.c.reconcile_observations();self.c.choose('consume')
        self.assertEqual(self.state()['branch'],'consume')

    def test_observer_reopen_requires_new_handles_and_reconciliation(self):
        self.preflight();new=self.tracker('a')
        with self.assertRaises(private.Error):self.prepare_issue()
        self.pair.trackers=(new,self.b)  # Same pinned descriptor; a new session is not eligibility.
        for t in self.pair.trackers:
            t.apply(native.fixture_scan(3),100);t.apply_source_utxos(self.utxos(t),100)
        with self.assertRaises(private.Error):self.prepare_issue()
        self.c.reconcile_observations();self.prepare_issue()

    def test_changed_pair_descriptor_or_identity_halts_controller(self):
        self.preflight();self.pair.freshness=6
        with self.assertRaises(private.IntegrityError):self.prepare_issue()
        self.pair.freshness=5
        with self.assertRaises(private.Error):self.c.status()

    def test_public_review_and_pair_must_match_before_store_creation(self):
        bad=deepcopy(self.review);bad['receipt_hash']='00'*32
        root=self.secret/'uncreated'
        with self.assertRaises(private.Error):
            binding.Controller(root,self.secret/'other/authority.sqlite',self.claims,bad,lambda:100,observations=self.pair,create=True)
        self.assertFalse(root.exists())

    def test_observer_backups_must_be_separate_from_private_stores(self):
        with self.assertRaises(private.Error):
            binding.Controller(self.secret/'uncreated',self.obs/'authority.sqlite',self.claims,self.review,lambda:100,observations=self.pair,create=True)
        self.assertFalse((self.obs/'authority.sqlite').exists())

    def test_offline_controller_cannot_open_observation_bound_policy(self):
        with self.assertRaises(private.IntegrityError):
            private.Controller(self.secret/'component',self.secret/'authority/service.sqlite',self.claims,self.review,lambda:100)

    def test_bound_controller_cannot_relabel_an_offline_journal(self):
        root=self.secret/'offline';authority=self.secret/'offline-authority/state.sqlite'
        c=private.Controller(root,authority,self.claims,self.review,lambda:100,create=True)
        c.close()
        with self.assertRaises(private.IntegrityError):
            binding.Controller(root,authority,self.claims,self.review,lambda:100,observations=self.pair)

    def test_source_claim_remains_exclusive_across_controller_variants(self):
        self.preflight();self.prepare_issue()
        c=private.Controller(self.secret/'offline',self.secret/'offline-authority/state.sqlite',self.claims,self.review,lambda:100,create=True)
        try:
            c.recover()
            with self.assertRaises(private.IntegrityError):c.prepare('issue',self.entry(),self.keys['funding'])
        finally:c.close()

    def test_lost_branch_ack_preserves_choice_after_recovery(self):
        self.issued()
        def hook(stage):
            if stage=='p0-private:saved':raise RuntimeError('simulated lost acknowledgment')
        self.c.hook=hook
        with self.assertRaises(RuntimeError):self.c.choose('refund')
        self.c=self.open();self.c.recover();self.refresh_issued()
        with self.assertRaises(private.Error):self.c.choose('consume')
        self.assertEqual(self.state()['branch'],'refund')

    def test_unknown_terminal_signing_outcome_keeps_branch_and_never_retries(self):
        self.issued();self.c.choose('consume');prepare=self.worker.prepare
        def lost(*args):prepare(*args);raise private.RecoveryRequired('simulated lost signer reply')
        with patch.object(self.worker,'prepare',side_effect=lost):
            with self.assertRaises(private.RecoveryRequired):self.c.prepare('terminal',self.entry('terminal'),self.keys['ticket'])
        self.c=self.open();self.c.recover();self.refresh_issued()
        with self.assertRaises(private.RecoveryRequired):self.c.prepare('terminal',self.entry('terminal'),self.keys['ticket'])
        self.assertEqual(self.state()['branch'],'consume');self.assertIsNone(self.state()['terminal_record'])

    def test_restored_component_cannot_use_fresh_observations_to_erase_history(self):
        snapshot=self.root/'old.sqlite';shutil.copy2(self.secret/'component/pilot.sqlite',snapshot)
        self.preflight();self.prepare_issue();self.c.close();self.controllers.remove(self.c)
        shutil.copy2(snapshot,self.secret/'component/pilot.sqlite');self.c=self.open()
        with self.assertRaises(private.IntegrityError):self.c.recover()

    def test_pair_type_and_freshness_are_closed(self):
        for freshness in (True,0,31):
            with self.assertRaises(private.Error):binding.Pair(self.a,self.b,freshness=freshness)
        with self.assertRaises(private.Error):binding.Pair(self.a,self.a)
        self.pair.id='00'*32
        with self.assertRaises(private.IntegrityError):self.pair.check()
