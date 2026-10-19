"""Accepted-chain custody tracking; these tests do not prove node age enforcement."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from watchtower import Store, WatchError, act, heartbeat
from watch_health import health
from test_watchtower import Adapter, CONFIG, H, NODE, PENDING, ROOT, response, transaction, utxo

PROTECTED = {**CONFIG, 'version': 'protected-v1', 'cold_spk': 'ee', 'cold_delay_daa': 1800}
QUARANTINE = H(3) + ':0'
RELEASE = H(4) + ':0'


class QuarantineTrackingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'watch.sqlite'
        self.store = Store(self.path, PROTECTED)
        self.store.arm(H(10), [utxo()])
        self.adapter = Adapter()

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def recover(self):
        self.store.apply(response(txs=[transaction()]))
        act(self.store, self.adapter, True, 100)
        self.store.apply(response(H(11), H(12), [transaction(PENDING, H(3), 'cc', 9800)]))

    def release(self):
        self.store.apply(response(H(12), H(13), [transaction(QUARANTINE, H(4), 'ee', 9700)], daa=600001900))

    def action(self):
        return dict(self.store.db.execute('SELECT * FROM actions').fetchone())

    def report(self):
        heartbeat(self.store, NODE, True, now=100)
        return health(self.path, now=101, require_remote=False)

    def test_recovery_keeps_exact_quarantine_under_observation(self):
        self.recover()
        output = self.store.state()['outputs'][QUARANTINE]
        self.assertEqual(output, {'stage': 'quarantined', 'root': ROOT, 'amount': 9800,
                                  'accepted_daa': 600000000, 'authorized': False})
        self.assertFalse(self.store.recoveries())
        self.assertEqual(self.action()['status'], 'CONFIRMED')
        act(self.store, self.adapter, True, 111)
        self.assertEqual(self.adapter.prepared, [PENDING])
        self.assertEqual(len(self.adapter.broadcasts), 1)

    def test_cold_exit_preserves_recovery_confirmation_and_records_release(self):
        self.recover()
        self.release()
        state = self.store.state()
        terminal = state['terminal'][ROOT]
        self.assertEqual(terminal['kind'], 'RECOVERED')
        self.assertEqual(terminal['transaction_id'], H(3))
        self.assertEqual(terminal['custody'], 'COLD_RELEASED')
        self.assertEqual(terminal['release_transaction_id'], H(4))
        self.assertEqual(terminal['release_outpoint'], RELEASE)
        self.assertEqual(terminal['release_amount'], 9700)
        self.assertEqual(terminal['release_daa'], 600001900)
        self.assertFalse(state['outputs'])
        self.assertEqual(self.action()['status'], 'CONFIRMED')
        self.assertEqual(self.store.db.execute(
            "SELECT COUNT(*) FROM audit WHERE kind='COLD_RELEASE_OBSERVED'").fetchone()[0], 1)

    def test_wrong_destination_and_recovery_loop_cannot_advance_cursor(self):
        self.recover()
        before = self.store.state()
        for destination in ('dd', 'cc', 'aa', 'ff'):
            with self.subTest(destination=destination), self.assertRaises(WatchError):
                self.store.apply(response(H(12), H(13), [transaction(QUARANTINE, H(4), destination, 9700)]))
            self.assertEqual(self.store.get('tip'), H(12))
            self.assertEqual(self.store.state(), before)

    def test_cold_release_value_and_layout_violations_roll_back(self):
        self.recover()
        for value in (0, 1, 9801):
            with self.subTest(value=value), self.assertRaises(WatchError):
                self.store.apply(response(H(12), H(13), [transaction(QUARANTINE, H(4), 'ee', value)]))
            self.assertIn(QUARANTINE, self.store.state()['outputs'])
        tx = transaction(QUARANTINE, H(4), 'ee', 9700)
        tx['outputs'].append(copy.deepcopy(tx['outputs'][0]))
        with self.assertRaises(WatchError):
            self.store.apply(response(H(12), H(13), [tx]))
        self.assertEqual(self.store.get('tip'), H(12))

    def test_cold_destination_is_not_an_idle_or_pending_exit(self):
        with self.assertRaises(WatchError):
            self.store.apply(response(txs=[transaction(spk='ee')]))
        self.store.apply(response(txs=[transaction()]))
        with self.assertRaises(WatchError):
            self.store.apply(response(H(11), H(12), [transaction(PENDING, H(3), 'ee', 9800)]))
        self.assertIn(PENDING, self.store.recoveries())

    def test_reorg_of_cold_release_restores_quarantine_without_resigning(self):
        self.recover()
        self.release()
        self.store.apply(response(H(13), None, removed=[H(13)]))
        self.assertIn(QUARANTINE, self.store.state()['outputs'])
        self.assertEqual(self.store.state()['terminal'][ROOT]['custody'], 'QUARANTINED')
        self.assertNotIn('release_transaction_id', self.store.state()['terminal'][ROOT])
        self.assertEqual(self.action()['status'], 'CONFIRMED')
        act(self.store, self.adapter, True, 111)
        self.assertEqual(self.adapter.prepared, [PENDING])
        self.assertEqual(len(self.adapter.broadcasts), 1)

    def test_reorg_of_release_and_recovery_restores_pending_outbox(self):
        self.recover()
        self.release()
        self.store.apply(response(H(13), None, removed=[H(13), H(12)]))
        self.assertIn(PENDING, self.store.recoveries())
        self.assertFalse(self.store.state()['terminal'])
        self.assertEqual(self.action()['status'], 'PREPARED')
        act(self.store, self.adapter, True, 111)
        self.assertEqual(self.adapter.prepared, [PENDING])
        self.assertEqual(len(self.adapter.broadcasts), 2)

    def test_replacement_release_is_the_branch_current_observation(self):
        self.recover()
        self.release()
        self.store.apply(response(H(13), H(14), [transaction(QUARANTINE, H(5), 'ee', 9600)],
                                  removed=[H(13)], daa=600001950))
        self.assertEqual(self.store.state()['terminal'][ROOT]['release_transaction_id'], H(5))
        self.assertEqual(self.action()['status'], 'CONFIRMED')
        self.assertEqual(self.report()['custody']['cold_releases_observed'], 1)

    def test_restart_preserves_quarantine_and_later_release(self):
        self.recover()
        self.store.db.close()
        self.store = Store(self.path, PROTECTED)
        self.assertIn(QUARANTINE, self.store.state()['outputs'])
        self.release()
        self.store.db.close()
        self.store = Store(self.path, PROTECTED)
        act(self.store, self.adapter, True, 111)
        self.assertEqual(self.action()['status'], 'CONFIRMED')
        self.assertEqual(len(self.adapter.broadcasts), 1)

    def test_legacy_untracked_quarantine_requires_explicit_reconciliation(self):
        self.recover()
        legacy = self.store.state()
        del legacy['outputs'][QUARANTINE]
        with self.store.db:
            self.store.put('state', json.dumps(legacy))
        with self.assertRaisesRegex(WatchError, 'reconcile accepted-chain history'):
            Store(self.path, PROTECTED)
        self.assertEqual(self.store.state(), legacy)
        self.assertEqual(self.store.get('tip'), H(12))
        self.assertIn('QUARANTINE_TRACKING_INCOMPLETE', self.report()['issues'])

    def test_reorg_into_legacy_untracked_state_is_atomic_and_stops(self):
        self.recover()
        self.release()
        legacy = json.loads(self.store.db.execute('SELECT undo FROM blocks WHERE hash=?', (H(13),)).fetchone()[0])
        del legacy['outputs'][QUARANTINE]
        with self.store.db:
            self.store.db.execute('UPDATE blocks SET undo=? WHERE hash=?', (json.dumps(legacy), H(13)))
        with self.assertRaisesRegex(WatchError, 'reconcile accepted-chain history'):
            self.store.apply(response(H(13), None, removed=[H(13)]))
        self.assertEqual(self.store.get('tip'), H(13))
        self.assertEqual(self.store.state()['terminal'][ROOT]['custody'], 'COLD_RELEASED')
        self.assertEqual(self.action()['status'], 'CONFIRMED')

    def test_health_counts_current_custody_without_calling_release_approval(self):
        self.recover()
        report = self.report()
        self.assertTrue(report['healthy'])
        self.assertEqual(report['custody'], {'quarantined_outputs': 1, 'cold_releases_observed': 0})
        self.release()
        report = self.report()
        self.assertTrue(report['healthy'])
        self.assertEqual(report['custody'], {'quarantined_outputs': 0, 'cold_releases_observed': 1})

    def test_cold_p2pk_spends_are_outside_covenant_tracking(self):
        self.recover()
        self.release()
        terminal = self.store.state()['terminal'][ROOT]
        self.store.apply(response(H(13), H(14), [transaction(RELEASE, H(5), 'ff', 9600)]))
        self.assertEqual(self.store.state()['terminal'][ROOT], terminal)
        self.assertFalse(self.store.state()['outputs'])

    def test_invalid_cold_descriptor_is_rejected(self):
        for updates in ({'cold_spk': None}, {'cold_spk': 'not hex'}, {'cold_delay_daa': 600},
                        {'cold_delay_daa': True}, {'cold_delay_daa': 2**32}):
            with self.subTest(updates=updates), self.assertRaises(WatchError):
                Store(Path(self.tmp.name) / 'other.sqlite', {**PROTECTED, **updates})


if __name__ == '__main__':
    unittest.main()
