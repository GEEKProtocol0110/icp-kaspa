"""Synthetic accepted-chain/UTXO scans validated by the actual native projector."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_ticket_observer as o


class TicketObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.pins=o.fixture_pins(); self.reader=o.Reader()
        self.endpoint='wss://first.invalid/kaspa/testnet-10/wrpc/borsh'
        self.t=self.open(); self.issue=o.fixture_rpc(self.pins['issue'])
        self.consume=o.fixture_rpc(self.pins['consume']); self.refund=o.fixture_rpc(self.pins['refund'])

    def open(self, **kwargs):
        return o.TicketTracker(self.root/'one.sqlite', self.pins,self.endpoint,o.fake_id(0),reader=self.reader,
                              **dict(min_successors=2,max_age=10,**kwargs))

    def tearDown(self):
        self.t.close();self.tmp.cleanup()

    def issued(self, depth=3, at=100):
        self.t.apply(o.fixture_scan(0,list(range(1,depth+1)),transactions={1:[self.issue]}),at)
        self.t.apply_utxos(o.fixture_utxos(self.pins),at)

    def consumed(self):
        self.issued();self.t.apply(o.fixture_scan(3,[4,5,6],transactions={4:[self.consume]}),101)

    def state(self, now=100):return self.t.status(now)['state']

    def test_native_projection_matches_all_public_fixture_pins(self):
        for s in self.pins.values():self.assertEqual(self.reader.project(o.fixture_rpc(s)),o.expected(s))

    def test_demo_is_synthetic_and_distinguishes_all_three_states(self):
        data=o.demo();self.assertEqual(data['mode'],'SYNTHETIC_TICKET_SCANS_NO_RPC_NO_FUNDS')
        self.assertEqual((data['rpc_calls'],data['broadcasts'],data['signatures_created']),(0,0,0))
        self.assertIn('CONSUMPTION',data['snapshots'][1]['state']);self.assertIn('REFUND',data['snapshots'][2]['state'])

    def test_new_tracker_requires_scan(self):self.assertEqual(self.state(),'SCAN_REQUIRED')

    def test_issue_requires_successors_and_positive_exact_utxo(self):
        self.issued(1);self.assertEqual(self.state(),'WAITING_SUCCESSORS')
        self.t.apply(o.fixture_scan(1,[2,3]),101);self.assertEqual(self.state(101),'UTXO_SAMPLE_REQUIRED')
        self.t.apply_utxos(o.fixture_utxos(self.pins),101);self.assertEqual(self.state(101),'ISSUED_UNSPENT_OBSERVED')

    def test_consumption_requires_its_own_successor_depth(self):
        self.issued();self.t.apply(o.fixture_scan(3,[4],transactions={4:[self.consume]}),101)
        self.assertEqual(self.state(101),'WAITING_SUCCESSORS')
        self.t.apply(o.fixture_scan(4,[5,6]),102);self.assertEqual(self.state(102),'CONSUMPTION_OBSERVED')

    def test_refund_never_becomes_consumption(self):
        self.issued();self.t.apply(o.fixture_scan(3,[4,5,6],transactions={4:[self.refund]}),101)
        self.assertEqual(self.state(101),'REFUND_OBSERVED')

    def test_two_distinct_matching_nodes_are_required(self):
        self.issued();other=o.TicketTracker(self.root/'two.sqlite',self.pins,
            'wss://second.invalid/kaspa/testnet-10/wrpc/borsh',o.fake_id(0),reader=self.reader,min_successors=2,max_age=10)
        try:
            self.assertEqual(o.combined(self.t,other,100)['state'],'TWO_NODE_GATE_BLOCKED')
            other.apply(o.fixture_scan(0,[1,2,3],transactions={1:[self.issue]}),100)
            other.apply_utxos(o.fixture_utxos(self.pins),100)
            self.assertEqual(o.combined(self.t,other,100)['state'],'TWO_NODE_ISSUED_UNSPENT_OBSERVED')
            with self.assertRaises(o.ObservationError):o.combined(self.t,self.t,100)
        finally:other.close()

    def test_same_host_alias_and_changed_pin_policy_are_refused(self):
        other=o.TicketTracker(self.root/'two.sqlite',self.pins,self.endpoint,o.fake_id(0),reader=self.reader,min_successors=3)
        try:
            with self.assertRaises(o.ObservationError):o.combined(self.t,other,100)
        finally:other.close()

    def test_copied_id_cannot_hide_payload_output_or_input_mutation(self):
        for n in range(3):
            tx=deepcopy(self.issue)
            if n==0:tx['payload']='00'
            elif n==1:tx['outputs'][0]['value']-=1
            else:tx['inputs'][0]['previousOutpoint']['index']=1
            with self.assertRaises(o.ObservationError):self.t.apply(o.fixture_scan(0,[1],transactions={1:[tx]}),100)
            self.assertEqual(self.t.tip,o.fake_id(0));self.assertEqual(self.state(),'SCAN_REQUIRED')

    def test_live_utxo_amount_script_coinbase_and_covenant_must_match(self):
        self.issued()
        for key,bad in [('amount',1),('scriptPublicKey','000051'),('isCoinbase',True),('covenantId','11'*32)]:
            u=o.fixture_utxos(self.pins);u['utxos'][0]['utxoEntry'][key]=bad
            with self.assertRaises(o.ObservationError):self.t.apply_utxos(u,100)
            self.assertEqual(self.state(),'UTXO_SAMPLE_REQUIRED')

    def test_absence_of_spend_is_not_positive_utxo_evidence(self):
        self.issued();self.t.apply_utxos(o.fixture_utxos(self.pins,found=False),100)
        self.assertEqual(self.state(),'TICKET_NOT_UNSPENT')

    def test_wrong_utxo_query_key_is_refused(self):
        self.issued();u=o.fixture_utxos(self.pins);u['publicKey']='33'*32
        with self.assertRaises(o.ObservationError):self.t.apply_utxos(u,100)

    def test_duplicate_live_utxo_rows_are_refused(self):
        self.issued();u=o.fixture_utxos(self.pins);u['utxos']*=2
        with self.assertRaises(o.ObservationError):self.t.apply_utxos(u,100)

    def test_utxo_sample_must_reference_current_tracked_branch(self):
        self.issued();self.t.apply_utxos(o.fixture_utxos(self.pins,before=999),100)
        self.assertEqual(self.state(),'UTXO_SAMPLE_REQUIRED')
        self.t.apply_utxos(o.fixture_utxos(self.pins,before=3,after=1),100)
        self.assertEqual(self.state(),'UTXO_SAMPLE_REQUIRED')

    def test_utxo_sample_predating_creation_cannot_authorize_unspent_state(self):
        self.issued();self.t.apply_utxos(o.fixture_utxos(self.pins,before=0,after=1),100)
        self.assertEqual(self.state(),'UTXO_SAMPLE_PREDATES_ISSUE')

    def test_reorg_undoes_consumption_and_requires_new_utxo_sample(self):
        self.consumed();self.assertEqual(self.state(101),'CONSUMPTION_OBSERVED')
        self.t.apply(o.fixture_scan(6,[7],removed=[6,5,4]),102)
        self.assertEqual(self.state(102),'UTXO_SAMPLE_REQUIRED')
        self.t.apply_utxos(o.fixture_utxos(self.pins),102)
        self.assertEqual(self.state(102),'ISSUED_UNSPENT_OBSERVED')

    def test_reorg_removes_issuance_and_reacceptance_resets_depth(self):
        self.issued();self.t.apply(o.fixture_scan(3,[4],removed=[3,2,1]),101)
        self.assertEqual(self.state(101),'ISSUE_NOT_FOUND')
        self.t.apply(o.fixture_scan(4,[5],transactions={5:[self.issue]}),102)
        self.assertEqual(self.state(102),'WAITING_SUCCESSORS')

    def test_successor_rollback_revokes_depth_without_daa_substitution(self):
        self.issued();page=o.fixture_scan(3,removed=[3],target=2);page['node']['virtualDaaScore']+=1_000_000
        self.t.apply(page,101);self.assertEqual(self.state(101),'WAITING_SUCCESSORS')

    def test_wrong_removal_order_is_atomic_and_invalidates_cache(self):
        self.issued()
        with self.assertRaises(o.ObservationError):self.t.apply(o.fixture_scan(3,removed=[2,3],target=1),101)
        self.assertEqual(self.t.tip,o.fake_id(3));self.assertEqual(self.state(101),'SCAN_REQUIRED')

    def test_bootstrap_crossing_is_not_silently_reconciled(self):
        self.issued()
        with self.assertRaises(o.ObservationError):self.t.apply(o.fixture_scan(3,removed=[3,2,1,0],target=0),101)
        self.assertEqual(self.t.tip,o.fake_id(3))

    def test_stale_and_backward_clock_block_status(self):
        self.issued();self.assertEqual(self.state(111),'STALE')
        with self.assertRaises(o.ObservationError):self.state(110)
        with self.assertRaises(o.ObservationError):self.state(112)

    def test_reopen_requires_fresh_scan_and_utxo(self):
        self.issued();self.t.close();self.t=self.open();self.assertEqual(self.state(),'SCAN_REQUIRED')
        self.t.apply(o.fixture_scan(3),100);self.assertEqual(self.state(),'UTXO_SAMPLE_REQUIRED')
        self.t.apply_utxos(o.fixture_utxos(self.pins),100);self.assertEqual(self.state(),'ISSUED_UNSPENT_OBSERVED')

    def test_new_handle_invalidates_older_handle(self):
        self.issued();other=self.open()
        try:
            with self.assertRaises(o.ObservationError):self.state()
            self.assertEqual(other.status(100)['state'],'SCAN_REQUIRED')
        finally:other.close()
        # A handle opened while native parsing runs also fences the old commit.
        self.t.close();self.t=self.open();newer=[];project=self.reader.project
        def supersede(tx):
            newer.append(self.open())
            return project(tx)
        try:
            with patch.object(self.reader,'project',side_effect=supersede):
                with self.assertRaises(o.ObservationError):
                    self.t.apply(o.fixture_scan(3,[4,5,6],transactions={4:[self.consume]}),101)
            self.assertEqual(newer[0].tip,o.fake_id(3))
            self.assertEqual(newer[0].status(101)['state'],'SCAN_REQUIRED')
        finally:
            for tracker in newer:tracker.close()

    def test_backlog_blocks_positive_state(self):
        self.t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[self.issue]},target=99),100)
        self.t.apply_utxos(o.fixture_utxos(self.pins),100);self.assertEqual(self.state(),'CHAIN_BACKLOG')

    def test_duplicate_transactions_and_blocks_are_refused(self):
        for page in [o.fixture_scan(0,[1,1]),o.fixture_scan(0,[1],transactions={1:[self.issue,self.issue]})]:
            with self.assertRaises(o.ObservationError):self.t.apply(page,100)
        self.assertEqual(self.t.tip,o.fake_id(0))

    def test_missing_accepted_data_or_bad_network_invalidates_status(self):
        self.issued()
        for change in ('network','lists','transactions'):
            p=o.fixture_scan(3,[4])
            if change=='network':p['node']['networkId']='mainnet'
            elif change=='lists':p['changes']['chainBlockAcceptedTransactions']=[]
            else:p['changes']['chainBlockAcceptedTransactions'][0]['acceptedTransactions']=None
            with self.assertRaises(o.ObservationError):self.t.apply(p,101)
            self.assertEqual(self.state(101),'SCAN_REQUIRED')

    def test_read_only_poll_orders_samples_without_backwards_clock(self):
        native=o.Reader(self.endpoint)
        with patch.object(native,'utxos',return_value=o.fixture_utxos(self.pins)),patch.object(native,'scan',return_value=o.fixture_scan(0,[1,2,3],transactions={1:[self.issue]})):
            times=iter([100,101,102])
            self.assertEqual(self.t.poll(native,lambda:next(times))['state'],'ISSUED_UNSPENT_OBSERVED')

    def test_failed_rpc_poll_cannot_reuse_cached_status(self):
        self.issued();native=o.Reader(self.endpoint)
        with patch.object(native,'utxos',side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):self.t.poll(native,lambda:100)
        self.assertEqual(self.state(),'SCAN_REQUIRED')

    def test_positive_utxo_before_spend_is_nonatomic_historical_sample(self):
        self.consumed();self.t.apply_utxos(o.fixture_utxos(self.pins,before=1),101)
        self.assertEqual(self.state(101),'CONSUMPTION_OBSERVED')

    def test_positive_utxo_after_spend_is_inconsistent(self):
        self.consumed();self.t.apply_utxos(o.fixture_utxos(self.pins,before=6),101)
        self.assertEqual(self.state(101),'INCONSISTENT_UTXO_VIEW')

    def native_other(self, action):
        # Test fixture generation only. The observer never imports/calls this worker.
        from native_ticket_controller import Worker
        worker=Worker();p=deepcopy(self.pins['issue']['plan'])
        if action=='funding':p['context']['intent_nonce']='33'*32
        else:p=worker.terminal(p,'consume');p['admission']['request_digest']='33'*32
        record=json.loads(worker.prepare(p));tx=record['transaction'];ident=tx.pop('id')
        for i in tx['inputs']:i.update(sigOpCount=0,verboseData=None)
        for output in tx['outputs']:output['verboseData']=None
        tx['verboseData']=dict(transactionId=ident)
        return tx

    def test_unknown_native_ticket_spend_is_a_blocker(self):
        self.issued();self.t.apply(o.fixture_scan(3,[4,5,6],transactions={4:[self.native_other('ticket')]}),101)
        self.assertEqual(self.state(101),'UNEXPECTED_TICKET_SPEND')

    def test_unknown_native_funding_spend_is_a_blocker(self):
        self.t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[self.native_other('funding')]}),100)
        self.assertEqual(self.state(),'UNEXPECTED_FUNDING_SPEND')

    def test_conflicting_terminal_acceptance_rolls_back_entire_page(self):
        self.issued()
        with self.assertRaises(o.ObservationError):self.t.apply(o.fixture_scan(3,[4],transactions={4:[self.consume,self.refund]}),101)
        self.assertEqual(self.t.tip,o.fake_id(3));self.assertEqual(self.state(101),'SCAN_REQUIRED')

    def test_same_block_child_before_parent_uses_dependency_order(self):
        self.t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[self.consume,self.issue]}),100)
        self.assertEqual(self.state(),'CONSUMPTION_OBSERVED')

    def test_configuration_pins_and_caller_owned_data_are_preserved(self):
        self.pins['issue']['payload']='00'
        self.issued();self.assertEqual(self.state(),'ISSUED_UNSPENT_OBSERVED')
        with self.assertRaises(o.ObservationError):self.open()

    def test_non_id_fields_do_not_invalidate_semantic_observation(self):
        tx=deepcopy(self.issue);tx['inputs'][0]['signatureScript']='abcd';tx['inputs'][0]['computeBudget']=101;tx['storageMass']=1
        self.t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[tx]}),100)
        self.t.apply_utxos(o.fixture_utxos(self.pins),100);self.assertEqual(self.state(),'ISSUED_UNSPENT_OBSERVED')

    def test_chain_observation_after_grant_expiry_is_not_new_permission(self):
        self.issued(at=200);self.assertEqual(self.state(200),'ISSUED_UNSPENT_OBSERVED')

    def test_duplicate_json_fields_and_endpoint_credentials_are_refused(self):
        with self.assertRaises(o.ObservationError):o.decode('{"a":1,"a":2}')
        for endpoint in ['ws://node/kaspa/testnet-10/wrpc/borsh','wss://user:secret@node/kaspa/testnet-10/wrpc/borsh']:
            with self.assertRaises(o.ObservationError):o.endpoint_host(endpoint)
