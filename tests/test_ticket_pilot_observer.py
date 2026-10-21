"""P0 trusted-node state with fabricated RPC pages; no network or signer calls."""
from copy import deepcopy
import contextlib
import io
import json
import sqlite3
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_ticket_observer as o
import ticket_pilot_observer as p
from ticket_pilot_review import Reviewer, fixture_plan


class PilotObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.reviewer=Reviewer();self.plan=fixture_plan()
        self.plan.update(purpose='operator-unsigned-review',run_nonce='55'*32)
        self.plan['source'].update(transaction_id='22'*32,index=7)
        for role in ('funding_key','ticket_key','return_key'):
            self.plan[role]=ec.generate_private_key(ec.SECP256K1()).public_key().public_numbers().x.to_bytes(32,'big').hex()
        self.review=self.reviewer.make(self.plan)
        self.rpcs={}
        for tx in self.review['review']['transactions']:
            body=deepcopy(tx['unsigned_rpc']);body['verboseData']={'transactionId':tx['transaction_id']}
            self.rpcs[tx['action']]=body
        self.trackers=[];self.t=self.open('first');self.u=self.open('second')

    def tearDown(self):
        for t in self.trackers:t.close()
        self.tmp.cleanup()

    def open(self,name,review=None,**kwargs):
        endpoint=kwargs.pop('endpoint',f'wss://{name}.invalid/kaspa/testnet-10/wrpc/borsh')
        reader=kwargs.pop('reader',o.Reader(endpoint))
        t=p.Tracker(self.root/(name+'.sqlite'),review or self.review,endpoint,o.fake_id(0),reader=reader,
                    reviewer=self.reviewer,**dict({'min_successors':2,'max_age':10},**kwargs))
        self.trackers.append(t);return t

    def utxos(self,t,source=False,found=True,before=3,after=None,daa=100):
        key=t.funding_key if source else t.ticket_key
        point=t.source if source else t.ticket
        output=t.source_output if source else t.pins['issue']['outputs'][0]
        return dict(node=o.fixture_scan(0)['node'],publicKey=key,
            **{'from':o.fake_id(before)},target=o.fake_id(before if after is None else after),
            utxos=[dict(outpoint=dict(transactionId=point[0],index=point[1]),
                utxoEntry=dict(amount=output['value'],scriptPublicKey='0000'+output['script'],
                               blockDaaScore=daa,isCoinbase=False,covenantId=None))] if found else [])

    def preflight(self,t=None,at=100):
        t=t or self.t;t.apply(o.fixture_scan(0,[1,2,3]),at)
        t.apply_source_utxos(self.utxos(t,source=True),at)

    def issued(self,t=None,at=100):
        t=t or self.t;t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[self.rpcs['issue']]}),at)
        t.apply_utxos(self.utxos(t),at)

    def terminal(self,t,action,at=101):
        t.apply(o.fixture_scan(3,[4,5,6],transactions={4:[self.rpcs[action]]}),at)

    def state(self,t=None,now=100):return (t or self.t).status(now)['state']

    def test_unsigned_review_produces_exact_p0_pins_without_signing(self):
        for action,rpc in self.rpcs.items():
            self.assertEqual(self.t.pins[action],self.t.reader.project_p0(rpc))
            self.assertEqual(self.t.pins[action]['inputs'][0]['compute_budget'],100)
            self.assertEqual(self.t.pins[action]['storage_mass'],rpc['storageMass'])
            self.assertEqual(rpc['inputs'][0]['signatureScript'],'')
        self.assertEqual(self.t.status(100)['mode'],p.MODE)

    def test_fixture_review_and_relabeling_are_rejected(self):
        with self.assertRaises(ValueError):self.open('fixture',self.reviewer.make(fixture_plan()))
        bad=deepcopy(self.review);bad['plan']['purpose']='public-fixture-never-fund'
        with self.assertRaises(ValueError):self.open('relabel',bad)

    def test_source_preflight_needs_fresh_chain_and_positive_exact_utxo(self):
        self.t.apply_source_utxos(self.utxos(self.t,source=True,before=0),100)
        self.assertEqual(self.state(),'SCAN_REQUIRED')
        self.t.apply(o.fixture_scan(0,[1,2,3]),100);self.assertEqual(self.state(),'SOURCE_SAMPLE_REQUIRED')
        self.t.apply_source_utxos(self.utxos(self.t,source=True,found=False),100)
        self.assertEqual(self.state(),'SOURCE_NOT_UNSPENT')
        self.t.apply_source_utxos(self.utxos(self.t,source=True),100)
        self.assertEqual(self.state(),'SOURCE_UNSPENT_OBSERVED')

    def test_source_amount_script_coinbase_covenant_and_daa_are_checked(self):
        self.preflight()
        for key,value in [('amount',1),('amount',True),('scriptPublicKey','000051'),
                          ('isCoinbase',True),('covenantId','11'*32),('blockDaaScore',True),
                          ('blockDaaScore',467579701)]:
            sample=self.utxos(self.t,source=True);sample['utxos'][0]['utxoEntry'][key]=value
            with self.assertRaises(p.Error):self.t.apply_source_utxos(sample,100)
            self.assertEqual(self.state(),'SOURCE_SAMPLE_REQUIRED')

    def test_source_exact_outpoint_index_query_and_duplicate_rows(self):
        self.preflight();sample=self.utxos(self.t,source=True)
        sample['utxos'][0]['outpoint']['index']=0
        self.t.apply_source_utxos(sample,100);self.assertEqual(self.state(),'SOURCE_NOT_UNSPENT')
        for change in ('query','duplicate'):
            sample=self.utxos(self.t,source=True)
            if change=='query':sample['publicKey']=self.t.ticket_key
            else:sample['utxos']*=2
            with self.assertRaises(p.Error):self.t.apply_source_utxos(sample,100)

    def test_source_samples_must_be_on_current_branch_in_order(self):
        self.preflight()
        for before,after in [(999,999),(3,1)]:
            self.t.apply_source_utxos(self.utxos(self.t,source=True,before=before,after=after),100)
            self.assertEqual(self.state(),'SOURCE_SAMPLE_REQUIRED')

    def test_two_hosts_agree_on_full_positive_source_entry(self):
        self.preflight(self.t);self.preflight(self.u)
        self.assertEqual(p.combined(self.t,self.u,100)['state'],'TWO_NODE_SOURCE_UNSPENT_OBSERVED')
        self.u.apply_source_utxos(self.utxos(self.u,source=True,daa=101),100)
        self.assertEqual(p.combined(self.t,self.u,100)['state'],'TWO_NODE_GATE_BLOCKED')

    def test_source_disagreement_or_unavailability_blocks_pair(self):
        self.preflight(self.t)
        self.assertEqual(p.combined(self.t,self.u,100)['state'],'TWO_NODE_GATE_BLOCKED')
        self.preflight(self.u);self.u.apply_source_utxos(self.utxos(self.u,source=True,found=False),100)
        self.assertEqual(p.combined(self.t,self.u,100)['state'],'TWO_NODE_GATE_BLOCKED')

    def test_issue_depth_and_exact_positive_ticket_entry(self):
        self.t.apply(o.fixture_scan(0,[1],transactions={1:[self.rpcs['issue']]}),100)
        self.assertEqual(self.state(),'WAITING_SUCCESSORS')
        self.t.apply(o.fixture_scan(1,[2,3]),100);self.assertEqual(self.state(),'UTXO_SAMPLE_REQUIRED')
        self.t.apply_utxos(self.utxos(self.t),100);self.assertEqual(self.state(),'ISSUED_UNSPENT_OBSERVED')
        self.issued(self.u);self.assertEqual(p.combined(self.t,self.u,100)['state'],'TWO_NODE_ISSUED_UNSPENT_OBSERVED')
        self.u.apply_utxos(self.utxos(self.u,daa=101),100)
        self.assertEqual(p.combined(self.t,self.u,100)['state'],'TWO_NODE_GATE_BLOCKED')

    def test_ticket_utxo_metadata_and_missing_daa_fail(self):
        self.issued()
        for key,value in [('amount',1),('blockDaaScore',1.0),('scriptPublicKey','000051')]:
            sample=self.utxos(self.t);sample['utxos'][0]['utxoEntry'][key]=value
            with self.assertRaises(p.Error):self.t.apply_utxos(sample,100)
            self.assertEqual(self.state(),'UTXO_SAMPLE_REQUIRED')
        sample=self.utxos(self.t);del sample['utxos'][0]['utxoEntry']['blockDaaScore']
        with self.assertRaises(p.Error):self.t.apply_utxos(sample,100)

    def test_compute_and_storage_mutations_fail_despite_same_native_id(self):
        for kind in ('compute','storage'):
            tx=deepcopy(self.rpcs['issue'])
            if kind=='compute':tx['inputs'][0]['computeBudget']=101
            else:tx['storageMass']+=1;tx['mass']=tx['storageMass']
            self.assertEqual(self.t.reader.project(tx),self.t.reader.project(self.rpcs['issue']))
            with self.assertRaises(p.Error):self.t.apply(o.fixture_scan(0,[1],transactions={1:[tx]}),100)
            self.assertEqual(self.t.tip,o.fake_id(0))

    def test_copied_id_cannot_hide_changed_output_input_or_payload(self):
        for kind in ('output','input','payload'):
            tx=deepcopy(self.rpcs['issue'])
            if kind=='output':tx['outputs'][0]['value']-=1
            elif kind=='input':tx['inputs'][0]['previousOutpoint']['index']+=1
            else:tx['payload']='00'
            with self.assertRaises(p.Error):self.t.apply(o.fixture_scan(0,[1],transactions={1:[tx]}),100)

    def test_node_acceptance_is_trusted_not_an_independent_vm_signature_check(self):
        # Explicit limit: projector checks layout/ID, not signature validity.
        tx=deepcopy(self.rpcs['issue']);tx['inputs'][0]['signatureScript']='abcd'
        self.t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[tx]}),100)
        self.t.apply_utxos(self.utxos(self.t),100)
        self.assertEqual(self.state(),'ISSUED_UNSPENT_OBSERVED')

    def test_both_terminal_states_require_their_own_depth(self):
        self.issued(self.t);self.issued(self.u)
        for t,action in [(self.t,'consume'),(self.u,'refund')]:
            t.apply(o.fixture_scan(3,[4],transactions={4:[self.rpcs[action]]}),101)
            self.assertEqual(self.state(t,101),'WAITING_SUCCESSORS')
            t.apply(o.fixture_scan(4,[5,6]),101)
            self.assertEqual(self.state(t,101),'CONSUMPTION_OBSERVED' if action=='consume' else 'REFUND_OBSERVED')
        self.assertEqual(p.combined(self.t,self.u,101)['state'],'TWO_NODE_GATE_BLOCKED')

    def test_terminal_agreement_does_not_require_ticket_still_unspent(self):
        for t in (self.t,self.u):self.issued(t);self.terminal(t,'consume');t.apply_utxos(self.utxos(t,found=False,before=6),101)
        self.assertEqual(p.combined(self.t,self.u,101)['state'],'TWO_NODE_CONSUMPTION_OBSERVED')

    def test_reorg_removes_terminal_then_requires_new_positive_sample(self):
        self.issued();self.terminal(self.t,'consume')
        self.t.apply(o.fixture_scan(6,[7],removed=[6,5,4]),102)
        self.assertEqual(self.state(now=102),'UTXO_SAMPLE_REQUIRED')
        self.t.apply_utxos(self.utxos(self.t,before=7),102)
        self.assertEqual(self.state(now=102),'ISSUED_UNSPENT_OBSERVED')

    def test_reorg_removes_issue_and_invalidates_old_source_sample(self):
        self.issued();self.t.apply(o.fixture_scan(3,[4],removed=[3,2,1]),101)
        self.assertEqual(self.state(now=101),'SOURCE_SAMPLE_REQUIRED')
        self.t.apply_source_utxos(self.utxos(self.t,source=True,before=4),101)
        self.assertEqual(self.state(now=101),'SOURCE_UNSPENT_OBSERVED')

    def test_source_still_unspent_after_issue_is_inconsistent(self):
        self.issued();self.t.apply_source_utxos(self.utxos(self.t,source=True),100)
        self.assertEqual(self.state(),'INCONSISTENT_SOURCE_UTXO_VIEW')
        self.t.apply_source_utxos(self.utxos(self.t,source=True,before=0),100)
        self.assertEqual(self.state(),'ISSUED_UNSPENT_OBSERVED')

    def test_unexpected_funding_and_malformed_ticket_spends_are_blocked(self):
        # Native projector recomputes the new ID through a public unsigned preview.
        plan=deepcopy(self.plan);plan['evidence_digest']='88'*32
        other=self.reviewer.make(plan)['review']['transactions'][0]
        tx=deepcopy(other['unsigned_rpc']);tx['verboseData']={'transactionId':other['transaction_id']}
        self.t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[tx]}),100)
        self.assertEqual(self.state(),'UNEXPECTED_FUNDING_SPEND')
        self.issued(self.u);tx=deepcopy(self.rpcs['consume'])
        tx['inputs'].append(deepcopy(tx['inputs'][0]))
        with self.assertRaises(p.Error):self.u.apply(o.fixture_scan(3,[4],transactions={4:[tx]}),101)

    def test_restart_requires_scan_and_both_fresh_samples(self):
        self.preflight();self.t.close();self.trackers.remove(self.t);self.t=self.open('first')
        self.assertEqual(self.state(),'SCAN_REQUIRED')
        self.t.apply(o.fixture_scan(3),100);self.assertEqual(self.state(),'SOURCE_SAMPLE_REQUIRED')
        self.t.apply_source_utxos(self.utxos(self.t,source=True),100)
        self.assertEqual(self.state(),'SOURCE_UNSPENT_OBSERVED')

    def test_stale_samples_and_backward_clock_block(self):
        self.preflight();self.t.apply(o.fixture_scan(3),105)
        with self.assertRaises(p.Error):self.t.apply_source_utxos(self.utxos(self.t,source=True),100)
        with self.assertRaises(p.Error):self.state(now=106)

    def test_source_sample_age_is_checked_independently_of_fresh_scan(self):
        self.preflight();old=deepcopy(self.t.source_sample)
        self.t.apply(o.fixture_scan(3),105);self.t.source_sample=old
        self.assertEqual(self.state(now=111),'SOURCE_SAMPLE_REQUIRED')
        self.assertEqual(self.state(now=116),'STALE')
        with self.assertRaises(p.Error):self.state(now=115)

    def test_backlog_bad_network_and_unordered_reorg_block(self):
        self.t.apply(o.fixture_scan(0,[1,2,3],target=99),100)
        self.t.apply_source_utxos(self.utxos(self.t,source=True),100)
        self.assertEqual(self.state(),'CHAIN_BACKLOG')
        page=o.fixture_scan(3);page['node']['networkId']='mainnet'
        with self.assertRaises(p.Error):self.t.apply(page,101)
        with self.assertRaises(p.Error):self.t.apply(o.fixture_scan(3,removed=[2,3],target=1),101)

    def test_same_host_same_store_changed_review_and_policy_cannot_form_pair(self):
        with self.assertRaises(p.Error):p.combined(self.t,self.t,100)
        alias=self.open('alias',endpoint=self.t.endpoint)
        with self.assertRaises(p.Error):p.combined(self.t,alias,100)
        different=self.open('depth',min_successors=3)
        with self.assertRaises(p.Error):p.combined(self.t,different,100)
        plan=deepcopy(self.plan);plan['run_nonce']='66'*32
        different=self.open('changed',self.reviewer.make(plan))
        with self.assertRaises(p.Error):p.combined(self.t,different,100)

    def test_p0_and_lab0_profiles_cannot_share_database_or_combine(self):
        with self.assertRaises(p.Error):o.combined(self.t,self.u,100)
        fixture=o.TicketTracker(self.root/'lab.sqlite',o.fixture_pins(),self.t.endpoint,o.fake_id(0),reader=self.t.reader)
        try:
            with self.assertRaises(p.Error):p.combined(self.t,fixture,100)
            with self.assertRaises(p.Error):
                p.Tracker(self.root/'lab.sqlite',self.review,self.t.endpoint,o.fake_id(0),reader=self.t.reader,reviewer=self.reviewer)
            with self.assertRaises(p.Error):
                o.TicketTracker(self.t.path,o.fixture_pins(),self.t.endpoint,o.fake_id(0),reader=self.t.reader)
        finally:fixture.close()
        path=self.root/'service.sqlite';db=sqlite3.connect(path)
        db.execute('CREATE TABLE private_journal(secret TEXT)');db.close()
        with self.assertRaises(p.Error):self.open('service')
        db=sqlite3.connect(path)
        try:self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(),[('private_journal',)])
        finally:db.close()

    def test_mutated_pins_review_policy_or_binary_are_rejected(self):
        for change in ('pin','review','policy','ticket'):
            t=self.open('mutate-'+change)
            if change=='pin':t.pins['issue']['storage_mass']+=1
            elif change=='review':t.review['plan']['run_nonce']='66'*32
            elif change=='ticket':t.ticket=('33'*32,0)
            else:t.max_age=11
            with self.assertRaises(p.Error):t.status(100)
        binary=self.root/'read';shutil.copy2(self.t.reader.binary,binary)
        t=self.open('binary',reader=o.Reader(self.t.endpoint,binary))
        replacement=self.root/'replacement';replacement.write_bytes(binary.read_bytes()+b'changed')
        replacement.chmod(0o755);replacement.replace(binary)
        with self.assertRaises(p.Error):t.status(100)

    def test_old_handle_fenced_by_reopen(self):
        newer=self.open('first')
        with self.assertRaises(p.Error):self.t.status(100)
        self.assertEqual(newer.status(100)['state'],'SCAN_REQUIRED')

    def test_poll_uses_both_role_queries_then_fresh_scan_and_current_clock(self):
        calls=[]
        def query(key):
            calls.append(key);return self.utxos(self.t,source=key==self.t.funding_key,before=0,after=3,found=key==self.t.funding_key)
        with patch.object(self.t.reader,'utxos',side_effect=query),patch.object(self.t.reader,'scan',return_value=o.fixture_scan(0,[1,2,3])):
            self.assertEqual(self.t.poll(self.t.reader,lambda:100)['state'],'SOURCE_UNSPENT_OBSERVED')
        self.assertEqual(calls,[self.t.funding_key,self.t.ticket_key])

    def test_slow_poll_ages_samples_from_read_start_and_network_failure_invalidates(self):
        times=iter([100,111,112,112])
        with patch.object(self.t.reader,'utxos',side_effect=[self.utxos(self.t,source=True,before=0),self.utxos(self.t,found=False,before=0)]),patch.object(self.t.reader,'scan',return_value=o.fixture_scan(0,[1,2,3])):
            self.assertEqual(self.t.poll(self.t.reader,lambda:next(times))['state'],'SOURCE_SAMPLE_REQUIRED')
        with patch.object(self.t.reader,'utxos',side_effect=p.Error('offline')):
            with self.assertRaises(p.Error):self.t.poll(self.t.reader,lambda:112)
        self.assertEqual(self.state(now=112),'SCAN_REQUIRED')

    def test_pair_poll_failure_invalidates_both_and_wrong_adapter_is_blocked(self):
        self.preflight(self.t);self.preflight(self.u)
        with patch.object(self.t,'poll'),patch.object(self.u,'poll',side_effect=p.Error('second failed')):
            with self.assertRaises(p.Error):p.poll_pair(self.t,self.u,lambda:100)
        self.assertEqual(self.state(),'SCAN_REQUIRED');self.assertEqual(self.state(self.u),'SCAN_REQUIRED')
        with self.assertRaises(p.Error):self.t.poll(self.u.reader,lambda:100)

    def test_read_only_cli_rejects_effect_commands_and_closes_on_node_failure(self):
        for command in ('sign','prepare','submit','broadcast','keygen'):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):p.main([command])
        path=self.root/'review.json';path.write_text(json.dumps(self.review))
        args=['observe',str(path),str(self.root/'cli-first.sqlite'),self.t.endpoint,o.fake_id(0),str(self.root/'cli-second.sqlite'),self.u.endpoint,o.fake_id(0)]
        opened=[]
        def open_tracker(*args,**kwargs):
            t=original(*args,**kwargs);opened.append(t);return t
        original=p.Tracker
        with patch.object(p,'Tracker',side_effect=open_tracker),patch.object(p,'poll_pair',side_effect=p.Error('offline')):
            with self.assertRaises(p.Error):p.main(args)
        self.assertEqual(len(opened),2)
        for tracker in opened:
            with self.assertRaises(sqlite3.ProgrammingError):tracker.db.execute('SELECT 1')

    def test_read_only_cli_returns_only_observational_report(self):
        path=self.root/'review.json';path.write_text(json.dumps(self.review))
        args=['observe',str(path),str(self.root/'cli-first.sqlite'),self.t.endpoint,o.fake_id(0),str(self.root/'cli-second.sqlite'),self.u.endpoint,o.fake_id(0)]
        report=dict(mode=p.MODE,state='TWO_NODE_GATE_BLOCKED')
        output=io.StringIO()
        with patch.object(p,'poll_pair',return_value=report),contextlib.redirect_stdout(output):
            self.assertEqual(p.main(args),report)
        self.assertEqual(json.loads(output.getvalue()),report)

    def test_same_block_child_order_and_conflicting_terminal_page_are_checked(self):
        self.t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[self.rpcs['consume'],self.rpcs['issue']]}),100)
        self.assertEqual(self.state(),'CONSUMPTION_OBSERVED')
        self.issued(self.u)
        with self.assertRaises(p.Error):
            self.u.apply(o.fixture_scan(3,[4,5,6],transactions={4:[self.rpcs['consume'],self.rpcs['refund']]}),101)
        self.assertEqual(self.u.tip,o.fake_id(3));self.assertEqual(self.state(self.u,101),'SCAN_REQUIRED')

    def test_new_handle_during_native_projection_fences_old_page(self):
        original=self.t.reader.project_p0;newer=[]
        def supersede(tx):
            newer.append(self.open('first'));return original(tx)
        with patch.object(self.t.reader,'project_p0',side_effect=supersede):
            with self.assertRaises(p.Error):
                self.t.apply(o.fixture_scan(0,[1,2,3],transactions={1:[self.rpcs['issue']]}),100)
        self.assertEqual(newer[0].tip,o.fake_id(0));self.assertEqual(newer[0].status(100)['state'],'SCAN_REQUIRED')
