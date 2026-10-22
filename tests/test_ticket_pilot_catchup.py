"""Read-only history recovery; no key, signer, private journal or network."""
from copy import deepcopy
from pathlib import Path
import sys
from unittest.mock import patch

from test_ticket_pilot_observer import PilotObserverTests
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_ticket_observer as base
import ticket_pilot_catchup as h
import ticket_pilot_observer as observer


class CatchupTests(PilotObserverTests):
    # Reuse only the funded-profile fixture setup, not the inherited test suite.
    def page(self,start=0,added=(1,2,3),target=100,transactions=None,removed=()):
        return dict(mode=h.MODE,window=256,start_blue_score=0,sink_blue_score=1000,
                    min_confirmation_count=744,
                    scan=base.fixture_scan(start,added,removed,transactions,target=target))

    def reader(self,endpoint=None):
        # The history binary's protocol is mocked here; the native parser has Rust tests.
        return h.HistoryReader(endpoint or self.t.endpoint,self.t.reader.binary)

    def test_partial_history_advances_real_cursor_but_never_eligibility(self):
        self.preflight()
        r=self.reader();value=self.page(3,(4,5),100)
        with patch.object(r,'page',return_value=value): report=h.advance(self.t,r,lambda:101)
        self.assertEqual(self.t.tip,base.fake_id(5))
        self.assertEqual(report['sampled_target'],base.fake_id(100))
        self.assertFalse(report['caught_up']);self.assertFalse(report['eligibility'])
        self.assertFalse(self.t.ready);self.assertIsNone(self.t.source_sample);self.assertIsNone(self.t.utxo_sample)
        self.assertEqual(self.t.status(101)['state'],'SCAN_REQUIRED')

    def test_even_target_reached_requires_original_fresh_snapshot(self):
        r=self.reader();value=self.page(target=3)
        with patch.object(r,'page',return_value=value):report=h.advance(self.t,r,lambda:100)
        self.assertTrue(report['caught_up']);self.assertFalse(self.t.ready)
        self.assertNotEqual(observer.combined(self.t,self.u,100)['state'],'TWO_NODE_SOURCE_UNSPENT_OBSERVED')
        # Normal current full snapshot machinery can make the original policy eligible.
        self.t.apply(base.fixture_scan(3,(4,5),target=5),101)
        self.t.apply_source_utxos(self.utxos(self.t,source=True,before=5),101)
        self.assertEqual(self.t.status(101)['state'],'SOURCE_UNSPENT_OBSERVED')

    def test_full_native_event_is_preserved_and_body_tampering_rejected(self):
        r=self.reader();v=self.page(transactions={1:[self.rpcs['issue']]})
        with patch.object(r,'page',return_value=v):h.advance(self.t,r,lambda:100)
        self.assertEqual(self.t._history()['issue']['transaction_id'],self.rpcs['issue']['verboseData']['transactionId'])
        bad=self.page(3,(4,5),transactions={4:[deepcopy(self.rpcs['consume'])]})
        bad['scan']['changes']['chainBlockAcceptedTransactions'][0]['acceptedTransactions'][0]['outputs'][0]['value']+=1
        with patch.object(r,'page',return_value=bad),self.assertRaises(base.ObservationError):h.advance(self.t,r,lambda:101)
        self.assertEqual(self.t.tip,base.fake_id(3));self.assertFalse(self.t.ready)

    def test_original_bootstrap_and_reorg_rules_remain(self):
        r=self.reader()
        with patch.object(r,'page',return_value=self.page()):h.advance(self.t,r,lambda:100)
        original=base.canonical(self.t._descriptor())
        value=self.page(3,(4,5),removed=(3,2),target=5)
        with patch.object(r,'page',return_value=value):h.advance(self.t,r,lambda:101)
        self.assertEqual(base.canonical(self.t._descriptor()),original)
        bad=self.page(5,(6,),removed=(5,4,1,0),target=6)
        with patch.object(r,'page',return_value=bad),self.assertRaises(base.ObservationError):h.advance(self.t,r,lambda:102)
        self.assertEqual(self.t.tip,base.fake_id(5));self.assertFalse(self.t.ready)

    def test_wrong_profile_cursor_scores_window_health_and_extra_fields_fail(self):
        cases=[lambda v:v.update(mode='other'),lambda v:v.update(window=True),
               lambda v:v.update(min_confirmation_count=745),lambda v:v.update(sink_blue_score=True),
               lambda v:v.update(extra=1),lambda v:v['scan'].update(target='bad'),
               lambda v:v['scan'].update({'from':base.fake_id(9)}),
               lambda v:v['scan']['node'].update(networkId='mainnet'),
               lambda v:v['scan']['changes'].update(extra=[])]
        r=self.reader()
        for mutate in cases:
            v=self.page();mutate(v)
            with self.subTest(mutate=mutate),patch.object(r,'page',return_value=v),self.assertRaises(base.ObservationError):
                h.advance(self.t,r,lambda:100)
            self.assertEqual(self.t.tip,base.fake_id(0));self.assertFalse(self.t.ready)

    def test_failed_read_invalidates_prior_ready_sample(self):
        self.preflight();r=self.reader()
        with patch.object(r,'page',side_effect=base.ObservationError('Unavailable')),self.assertRaises(base.ObservationError):
            h.advance(self.t,r,lambda:101)
        self.assertFalse(self.t.ready);self.assertIsNone(self.t.source_sample)

    def test_endpoint_or_binary_changes_are_rejected(self):
        r=self.reader(self.u.endpoint)
        with patch.object(r,'page') as call,self.assertRaises(base.ObservationError):h.advance(self.t,r,lambda:100)
        call.assert_not_called()
        r=self.reader();r.binary_hash='00'*32
        with self.assertRaises(base.ObservationError):r.check()

    def test_historical_reply_keeps_request_start_and_existing_identity(self):
        descriptor=base.canonical(self.t._descriptor());r=self.reader()
        with patch.object(r,'page',return_value=self.page()):h.advance(self.t,r,lambda:100)
        self.assertEqual(self.t._get('observed_at'),'100')
        self.assertEqual(base.canonical(self.t._descriptor()),descriptor)

    def test_stale_handle_and_no_progress_cannot_rewrite_history(self):
        r=self.reader();new=self.open('first')
        with patch.object(r,'page') as call,self.assertRaises(base.ObservationError):h.advance(self.t,r,lambda:100)
        call.assert_not_called();self.t=new;r=self.reader()
        with patch.object(r,'page',return_value=self.page(added=())),self.assertRaises(base.ObservationError):
            h.advance(self.t,r,lambda:101)
        self.assertEqual(self.t.tip,base.fake_id(0));self.assertFalse(self.t.ready)


# Do not rediscover the parent fixture's unrelated tests in this module.
for _name in tuple(dir(PilotObserverTests)):
    if _name.startswith('test_'):setattr(CatchupTests,_name,None)
del PilotObserverTests
