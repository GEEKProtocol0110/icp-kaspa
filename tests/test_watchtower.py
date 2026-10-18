import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from watchtower import Store, WatchError, act

H=lambda n:f'{n:064x}'
ROOT=H(1)+':0'
PENDING=H(2)+':0'
CONFIG={'network':'testnet-10','idle_spk':'aa','pending_spk':'bb','recovery_spk':'cc','recipient_spk':'dd','max_fee':1000,'delay_daa':600}
NODE={'networkId':'testnet-10','isSynced':True,'hasUtxoIndex':True,'virtualDaaScore':600000000}

def utxo(outpoint=ROOT,spk='aa',value=10000):
    h,i=outpoint.split(':')
    return {'outpoint':{'transactionId':h,'index':int(i)},'utxoEntry':{'amount':value,'scriptPublicKey':spk,'blockDaaScore':599999000,'covenantId':None}}
def transaction(source=ROOT,ident=H(2),spk='bb',value=9900):
    h,i=source.split(':')
    return {'verboseData':{'transactionId':ident},'inputs':[{'previousOutpoint':{'transactionId':h,'index':int(i)}}],'outputs':[{'value':value,'scriptPublicKey':spk,'covenant':None}]}
def response(cursor=H(10),block=H(11),txs=None,removed=None,daa=600000000):
    return {'node':copy.deepcopy(NODE),'from':cursor,'changes':{'removedChainBlockHashes':removed or [],'addedChainBlockHashes':[block] if block else [],'chainBlockAcceptedTransactions':[{'chainBlockHeader':{'hash':block,'daaScore':daa},'acceptedTransactions':txs or []}] if block else []}}

class Adapter:
    def __init__(self):self.prepared=[];self.broadcasts=[];self.fail=False;self.present=True;self.bad=False
    def snapshot(self):return {'node':copy.deepcopy(NODE),'utxos':[utxo(PENDING,'bb',9900)] if self.present else []}
    def prepare(self,pending):
        self.prepared.append(pending)
        t=transaction(pending,H(3),'ee' if self.bad else 'cc',9800);t.pop('verboseData')
        return {'id':H(3),'transaction':t,'status':'PREPARED'}
    def broadcast(self,payload):
        self.broadcasts.append(copy.deepcopy(payload))
        if self.fail:raise TimeoutError('broadcast outcome unknown')

class WatchtowerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'watch.sqlite'
        self.store=Store(self.path,CONFIG);self.store.arm(H(10),[utxo()])
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def pending(self):self.store.apply(response(txs=[transaction()]))
    def test_unapproved_request_is_recovery_candidate(self):self.pending();self.assertIn(PENDING,self.store.recoveries())
    def test_exact_approval_preserves_legitimate_request(self):
        self.store.authorize(ROOT,PENDING,600000001);self.pending();self.assertFalse(self.store.recoveries())
    def test_expired_approval_does_not_suppress_recovery(self):
        self.store.authorize(ROOT,PENDING,599999999);self.pending();self.assertIn(PENDING,self.store.recoveries())
    def test_approval_does_not_apply_to_other_transaction(self):
        self.store.authorize(ROOT,H(99)+':0',600000001);self.pending();self.assertIn(PENDING,self.store.recoveries())
    def test_late_approval_is_rejected(self):
        self.pending()
        with self.assertRaises(WatchError):self.store.authorize(ROOT,PENDING,600000100)
    def test_wrong_network_is_fail_closed(self):
        r=response(txs=[transaction()]);r['node']['networkId']='mainnet'
        with self.assertRaises(WatchError):self.store.apply(r)
        self.assertEqual(self.store.get('tip'),H(10))
    def test_unsynced_node_is_fail_closed(self):
        r=response();r['node']['isSynced']=False
        with self.assertRaises(WatchError):self.store.apply(r)
    def test_incomplete_chain_page_is_rejected(self):
        r=response(txs=[transaction()]);r['changes']['chainBlockAcceptedTransactions']=[]
        with self.assertRaises(WatchError):self.store.apply(r)
        self.assertIn(ROOT,self.store.state()['outputs'])
    def test_stale_cursor_is_rejected(self):
        self.pending()
        with self.assertRaises(WatchError):self.store.apply(response())
    def test_reorg_removes_orphaned_pending_output(self):
        self.pending();self.store.apply(response(H(11),None,removed=[H(11)]))
        self.assertIn(ROOT,self.store.state()['outputs']);self.assertFalse(self.store.recoveries())
    def test_reorg_below_bootstrap_requires_reconciliation(self):
        with self.assertRaises(WatchError):self.store.apply(response(H(10),None,removed=[H(10)]))
        self.assertEqual(self.store.get('tip'),H(10))
    def test_invalid_accepted_value_rolls_back_entire_batch(self):
        with self.assertRaises(WatchError):self.store.apply(response(txs=[transaction(value=1)]))
        self.assertEqual(self.store.get('tip'),H(10));self.assertIn(ROOT,self.store.state()['outputs'])
    def test_changed_destination_is_rejected(self):
        with self.assertRaises(WatchError):self.store.apply(response(txs=[transaction(spk='ee')]))
    def test_malformed_transaction_cannot_advance_cursor(self):
        t=transaction();t['inputs'][0]['previousOutpoint']['index']=None
        with self.assertRaises(WatchError):self.store.apply(response(txs=[t]))
        self.assertEqual(self.store.get('tip'),H(10))
    def test_dry_run_does_not_sign_or_submit(self):
        self.pending();a=Adapter();act(self.store,a,False,100);self.assertFalse(a.prepared);self.assertFalse(a.broadcasts)
    def test_recovery_submitted_and_confirmed_separately(self):
        self.pending();a=Adapter();act(self.store,a,True,100)
        self.assertEqual(self.store.db.execute('SELECT status FROM actions').fetchone()[0],'SUBMITTED')
        self.store.apply(response(H(11),H(12),[transaction(PENDING,H(3),'cc',9800)]))
        self.assertEqual(self.store.db.execute('SELECT status FROM actions').fetchone()[0],'CONFIRMED')
        self.assertFalse(self.store.recoveries())
    def test_restart_after_ambiguous_broadcast_reuses_signed_transaction(self):
        self.pending();a=Adapter();a.fail=True;act(self.store,a,True,100)
        saved=json.loads(self.store.db.execute('SELECT payload FROM actions').fetchone()[0]);self.store.db.close()
        self.store=Store(self.path,CONFIG);a.fail=False;act(self.store,a,True,111)
        self.assertEqual(len(a.prepared),1);self.assertEqual(a.broadcasts[-1],saved)
    def test_missing_live_utxo_prevents_stale_retry(self):
        self.pending();a=Adapter();a.present=False;act(self.store,a,True,100);self.assertFalse(a.prepared)
    def test_retry_limit_bounds_rebroadcasts(self):
        self.pending();a=Adapter();a.fail=True
        for n in [100,111,122,133]:act(self.store,a,True,n)
        self.assertEqual(len(a.broadcasts),3);self.assertEqual(len(a.prepared),1)
    def test_signer_cannot_redirect_recovery(self):
        self.pending();a=Adapter();a.bad=True;act(self.store,a,True,100);self.assertFalse(a.broadcasts)
    def test_reorg_of_recovery_rearms_existing_outbox(self):
        self.pending();a=Adapter();act(self.store,a,True,100)
        self.store.apply(response(H(11),H(12),[transaction(PENDING,H(3),'cc',9800)]))
        self.store.apply(response(H(12),None,removed=[H(12)]));act(self.store,a,True,111)
        self.assertEqual(len(a.prepared),1);self.assertEqual(len(a.broadcasts),2)
    def test_reorg_of_intent_stops_rebroadcasts(self):
        self.pending();a=Adapter();act(self.store,a,True,100)
        self.store.apply(response(H(11),None,removed=[H(11)]));act(self.store,a,True,111)
        self.assertEqual(len(a.broadcasts),1)
    def test_unauthorized_execution_is_recorded_as_failure(self):
        self.pending();self.store.apply(response(H(11),H(12),[transaction(PENDING,H(4),'dd',9800)]))
        self.assertEqual(self.store.state()['terminal'][ROOT]['kind'],'UNAUTHORIZED_EXECUTION')
    def test_configuration_drift_does_not_reuse_db(self):
        changed=copy.deepcopy(CONFIG);changed['recovery_spk']='ee'
        with self.assertRaises(WatchError):Store(self.path,changed)

if __name__=='__main__':unittest.main()
