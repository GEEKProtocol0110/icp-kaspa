"""Processing/restart bounds, including VSPC pages that do not reach the sink."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from watchtower import Store, WatchError, emit_events, process_scan, scan_batches
from watch_health import health
from test_watchtower import Adapter, CONFIG, H, NODE, PENDING, ROOT, response, transaction, utxo


def page(cursor=H(10),numbers=(11,12,13),transactions=None,target=None,removed=None):
    transactions=transactions or {}
    result=response(cursor,None,removed=removed)
    result['target']=target or H(numbers[-1] if numbers else 10)
    result['changes']['addedChainBlockHashes']=[H(n) for n in numbers]
    result['changes']['chainBlockAcceptedTransactions']=[
        {'chainBlockHeader':{'hash':H(n),'daaScore':600000000+n},
         'acceptedTransactions':transactions.get(n,[])} for n in numbers]
    return result


class ChainBatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'watch.sqlite'
        self.store=Store(self.path,CONFIG);self.store.arm(H(10),[utxo()]);self.adapter=Adapter()

    def tearDown(self):
        self.store.db.close();self.tmp.cleanup()

    def run_page(self,value,**kwargs):
        return process_scan(self.store,self.adapter,value,scanned_at=100,**kwargs)

    def report(self):
        return health(self.path,now=101,require_remote=False)

    def test_blocks_commit_in_bounded_batches_with_recovery_between_them(self):
        tips=[]
        broadcast=self.adapter.broadcast
        def record(payload):
            tips.append(self.store.get('tip'));broadcast(payload)
        self.adapter.broadcast=record
        progress=[]
        backlog=self.run_page(page(transactions={11:[transaction()]}),execute=True,max_blocks=1,
                              after_batch=lambda p:progress.append(copy.deepcopy(p)))
        self.assertFalse(backlog)
        self.assertEqual(tips,[H(11)])
        self.assertEqual([p['remaining_blocks'] for p in progress],[2,1,0])
        self.assertEqual(self.store.get('tip'),H(13))
        self.assertEqual(len(self.adapter.prepared),1)

    def test_transaction_budget_never_splits_an_accepted_block(self):
        irrelevant=transaction(H(99)+':0',H(98),'ff',1)
        values=list(scan_batches(page(transactions={11:[irrelevant,irrelevant],12:[irrelevant]}),
                                 max_blocks=10,max_transactions=2))
        self.assertEqual([len(b['changes']['addedChainBlockHashes']) for b,_ in values],[1,2])
        self.assertEqual([p['remaining_transactions'] for _,p in values],[1,0])

    def test_late_oversized_block_is_rejected_before_any_committed_prefix(self):
        value=page(transactions={11:[transaction()],13:[transaction(),transaction()]})
        with self.assertRaisesRegex(WatchError,'transaction budget'):
            self.run_page(value,execute=True,max_blocks=1,max_transactions=1)
        self.assertEqual(self.store.get('tip'),H(10))
        self.assertFalse(self.adapter.prepared)

    def test_incomplete_or_duplicate_pages_never_advance_the_cursor(self):
        for kind in ('missing','duplicate','wrong_order'):
            value=page(transactions={11:[transaction()]})
            if kind=='missing':value['changes']['chainBlockAcceptedTransactions'].pop()
            elif kind=='duplicate':
                value['changes']['addedChainBlockHashes'][1]=H(11)
                value['changes']['chainBlockAcceptedTransactions'][1]['chainBlockHeader']['hash']=H(11)
            else:value['changes']['chainBlockAcceptedTransactions'].reverse()
            with self.subTest(kind=kind),self.assertRaises(WatchError):
                self.run_page(value,execute=True,max_blocks=1)
            self.assertEqual(self.store.get('tip'),H(10))
            self.assertFalse(self.adapter.prepared)

    def test_removal_budget_stops_before_undo_or_signing(self):
        self.run_page(page(numbers=(11,12)))
        with self.assertRaisesRegex(WatchError,'removal budget'):
            self.run_page(page(H(12),(13,),removed=[H(12),H(11)]),max_removed=1)
        self.assertEqual(self.store.get('tip'),H(12))

    def test_reorg_removals_are_atomic_before_the_first_addition_batch(self):
        self.run_page(page(numbers=(11,12),transactions={11:[transaction()]}))
        observed=[]
        self.run_page(page(H(12),(13,14),removed=[H(12),H(11)]),max_blocks=1,
                      after_batch=lambda _:observed.append((self.store.get('tip'),list(self.store.state()['outputs']))))
        self.assertEqual(observed,[(H(13),[ROOT]),(H(14),[ROOT])])
        self.assertFalse(self.store.recoveries())

    def test_removal_only_page_can_reach_its_target(self):
        self.run_page(page(numbers=(11,12)))
        self.assertFalse(self.run_page(page(H(12),(),target=H(10),removed=[H(12),H(11)])))
        self.assertEqual(self.store.get('tip'),H(10))
        self.assertTrue(json.loads(self.store.get('scan_progress'))['target_reached'])

    def test_restart_resumes_the_committed_prefix_and_keeps_signed_outbox(self):
        def stop(_):raise InterruptedError('simulated shutdown after committed batch')
        with self.assertRaises(InterruptedError):
            self.run_page(page(transactions={11:[transaction()]}),execute=True,max_blocks=1,after_batch=stop)
        self.assertEqual(self.store.get('tip'),H(11))
        self.assertEqual(json.loads(self.store.get('scan_progress'))['remaining_blocks'],2)
        payload=self.store.db.execute('SELECT payload FROM actions').fetchone()[0]
        self.store.db.close();self.store=Store(self.path,CONFIG)
        self.run_page(page(H(11),(12,13)),execute=True,max_blocks=1)
        self.assertEqual(self.store.get('tip'),H(13))
        self.assertEqual(self.store.db.execute('SELECT payload FROM actions').fetchone()[0],payload)
        self.assertEqual(len(self.adapter.prepared),1)
        self.assertEqual(len(self.adapter.broadcasts),1)

    def test_invalid_later_transition_preserves_last_committed_prefix(self):
        value=page(transactions={11:[transaction()],12:[transaction(PENDING,H(3),'ff',9800)]})
        with self.assertRaises(WatchError):self.run_page(value,max_blocks=1)
        self.assertEqual(self.store.get('tip'),H(11))
        self.assertIn(PENDING,self.store.recoveries())
        self.assertIn('CHAIN_BACKLOG',self.report()['issues'])

    def test_server_page_without_target_stays_unhealthy_until_next_scan(self):
        self.assertTrue(self.run_page(page(numbers=(11,),target=H(13)),execute=True))
        progress=self.report()['scan_progress']
        self.assertEqual(progress['remaining_blocks'],0)
        self.assertFalse(progress['target_reached'])
        self.assertIn('CHAIN_BACKLOG',self.report()['issues'])
        self.assertFalse(self.run_page(page(H(11),(12,13)),execute=True))
        self.assertNotIn('CHAIN_BACKLOG',self.report()['issues'])

    def test_empty_current_page_still_reconciles_recovery(self):
        self.run_page(page(numbers=(11,),transactions={11:[transaction()]}))
        self.assertFalse(self.run_page(page(H(11),(),target=H(11)),execute=True))
        self.assertEqual(self.adapter.prepared,[PENDING])

    def test_empty_page_cannot_claim_an_unreached_target(self):
        with self.assertRaisesRegex(WatchError,'no progress'):
            self.run_page(page(numbers=(),target=H(99)),execute=True)
        self.assertEqual(self.store.get('tip'),H(10))
        self.assertFalse(self.adapter.prepared)

    def test_missing_target_requires_updated_native_cli(self):
        value=page();value.pop('target')
        with self.assertRaises(WatchError):self.run_page(value)
        self.assertEqual(self.store.get('tip'),H(10))

    def test_stale_scan_and_unhealthy_node_cannot_sign(self):
        for kind in ('cursor','node'):
            value=page(transactions={11:[transaction()]})
            if kind=='cursor':value['from']=H(99)
            else:value['node']['networkId']='mainnet'
            with self.subTest(kind=kind),self.assertRaises(WatchError):self.run_page(value,execute=True)
        self.assertFalse(self.adapter.prepared)

    def test_recovery_still_requires_exact_live_outpoint_during_backlog(self):
        self.adapter.present=False
        self.run_page(page(transactions={11:[transaction()]}),execute=True,max_blocks=1)
        self.assertFalse(self.adapter.prepared)
        self.assertFalse(self.adapter.broadcasts)

    def test_cached_response_does_not_refresh_observation_time(self):
        self.run_page(page(),max_blocks=1)
        self.assertEqual(json.loads(self.store.get('heartbeat'))['at'],100)
        self.assertIn('STALE_HEARTBEAT',health(self.path,now=200,require_remote=False)['issues'])

    def test_budgets_reject_zero_negative_boolean_and_excessive_limits(self):
        for kw in ({'max_blocks':0},{'max_blocks':True},{'max_blocks':4097},
                   {'max_transactions':-1},{'max_transactions':1000001},{'max_removed':0}):
            with self.subTest(kw=kw),self.assertRaises(WatchError):list(scan_batches(page(),**kw))

    def test_audit_logging_is_bounded_and_resumes_durable_cursor(self):
        with self.store.db:
            for n in range(4):self.store.audit('TEST',{'n':n})
        output=io.StringIO();emit_events(self.store,output,limit=2)
        self.assertEqual(len(output.getvalue().splitlines()),2)
        self.store.db.close();self.store=Store(self.path,CONFIG)
        output=io.StringIO();emit_events(self.store,output,limit=2)
        self.assertEqual([json.loads(line)['event_id'] for line in output.getvalue().splitlines()],[3,4])
        self.assertEqual(self.store.get('logged_event'),'4')

    def test_broken_log_stream_does_not_acknowledge_unwritten_events(self):
        class Broken:
            def write(self,_):raise BrokenPipeError()
        with self.assertRaises(BrokenPipeError):emit_events(self.store,Broken())
        self.assertIsNone(self.store.get('logged_event'))
        output=io.StringIO();emit_events(self.store,output)
        self.assertEqual(json.loads(output.getvalue())['event_id'],1)


if __name__=='__main__':unittest.main()
