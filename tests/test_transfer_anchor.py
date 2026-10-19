"""Synthetic accepted-chain responses; no RPC, mined blocks or funded anchor."""
import copy
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from transfer_lab import (Ed25519PrivateKey, Policy, TransferError, approve,
                          public, seal, sign_send)
from transfer_anchor import AnchorTracker, commitment, demo
from watchtower import WatchError


def ident(n):
    return f'{n:064x}'


NODE = {'networkId': 'testnet-10', 'isSynced': True,
        'hasUtxoIndex': True, 'virtualDaaScore': 467579700}


def scan(start, added=(), removed=(), target=None, transactions=None):
    return {'node': copy.deepcopy(NODE), 'from': ident(start),
            'target': ident(target if target is not None else added[-1] if added else start),
            'changes': {'addedChainBlockHashes': [ident(n) for n in added],
                        'removedChainBlockHashes': [ident(n) for n in removed],
                        'chainBlockAcceptedTransactions': [
                            {'chainBlockHeader': {'hash': ident(n), 'daaScore': 467579700 + n},
                             'acceptedTransactions': (transactions or {}).get(n, [])}
                            for n in added]}}


class TransferAnchorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'anchor.sqlite'
        a, s, r = (Ed25519PrivateKey.generate() for _ in range(3))
        self.approver, self.sender = a, s
        self.policy = Policy(public(a), public(s), public(r))
        envelope, _ = seal(self.policy, b'public synthetic example', 100, 400)
        self.envelope = sign_send(approve(envelope, self.policy, a), self.policy, s, 101)
        self.store = self.open()
        self.tx = {'verboseData': {'transactionId': ident(900)},
                   'payload': commitment(self.envelope, self.policy)}

    def open(self, **kwargs):
        return AnchorTracker(self.path, self.policy, self.envelope, ident(900), ident(0),
                             **dict({'min_successors': 2, 'max_scan_age': 10}, **kwargs))

    def tearDown(self):
        self.store.close(); self.tmp.cleanup()

    def accepted(self, end=3, now=110):
        self.store.apply(scan(0, list(range(1, end + 1)), transactions={1: [self.tx]}), now)

    def state(self, now=110):
        return self.store.status(now)['state']

    def test_exact_commitment_requires_selected_chain_successors(self):
        self.accepted(1)
        self.assertEqual(self.state(), 'WAITING_SUCCESSORS')
        self.store.apply(scan(1, [2]), 111)
        self.assertEqual(self.state(111), 'WAITING_SUCCESSORS')
        self.store.apply(scan(2, [3]), 112)
        status = self.store.status(112)
        self.assertEqual(status['state'], 'OBSERVED_COMMITMENT')
        self.assertEqual(status['selected_chain_successors'], 2)
        self.assertEqual(status['accepting_block'], ident(1))

    def test_daa_delta_does_not_supply_successors(self):
        value = scan(0, [1], transactions={1: [self.tx]})
        value['node']['virtualDaaScore'] += 1000000
        self.store.apply(value, 110)
        self.assertEqual(self.state(), 'WAITING_SUCCESSORS')

    def test_same_payload_in_wrong_transaction_is_not_anchor(self):
        other = dict(self.tx, verboseData={'transactionId': ident(901)})
        self.store.apply(scan(0, [1, 2, 3], transactions={1: [other]}), 110)
        self.assertEqual(self.state(), 'NOT_FOUND')

    def test_pinned_transaction_with_wrong_or_missing_payload_fails(self):
        for payload in (None, '', '00', self.tx['payload'] + '00', self.tx['payload'].upper()):
            with self.subTest(payload=payload):
                value = dict(self.tx, payload=payload)
                with self.assertRaisesRegex(TransferError, 'commitment'):
                    self.store.apply(scan(0, [1], transactions={1: [value]}), 110)
                self.assertEqual(self.store.tip, ident(0))
                self.assertEqual(self.state(), 'SCAN_REQUIRED')

    def test_commitment_changes_with_signed_exchange(self):
        other, _ = seal(self.policy, b'another synthetic exchange', 100, 400)
        other = sign_send(approve(other, self.policy, self.approver), self.policy, self.sender, 101)
        self.assertNotEqual(commitment(other, self.policy), self.tx['payload'])
        self.assertEqual(len(bytes.fromhex(self.tx['payload'])), 49)
        value = copy.deepcopy(self.envelope)
        value['sender_signature'] = '00' * 64
        with self.assertRaises(TransferError): commitment(value, self.policy)
        other_policy = Policy(self.policy.approver, self.policy.sender,
                              self.policy.recipient, max_lifetime=200)
        with self.assertRaises(TransferError): commitment(self.envelope, other_policy)

    def test_pending_broadcast_or_inclusion_is_not_accepted_evidence(self):
        self.assertEqual(self.state(), 'SCAN_REQUIRED')
        value = scan(0, [1, 2, 3])
        value['broadcastResult'] = ident(900)
        value['blockTransactions'] = [self.tx]
        self.store.apply(value, 110)
        self.assertEqual(self.state(), 'NOT_FOUND')

    def test_reorg_removes_anchor_and_reacceptance_resets_depth(self):
        self.accepted()
        self.store.apply(scan(3, [4, 5], removed=[3, 2, 1]), 111)
        self.assertEqual(self.state(111), 'NOT_FOUND')
        self.store.apply(scan(5, [6], transactions={6: [self.tx]}), 112)
        status = self.store.status(112)
        self.assertEqual(status['state'], 'WAITING_SUCCESSORS')
        self.assertEqual(status['selected_chain_successors'], 0)
        self.assertEqual(status['accepting_block'], ident(6))

    def test_reorg_only_successors_revokes_threshold(self):
        self.accepted()
        self.store.apply(scan(3, removed=[3], target=2), 111)
        self.assertEqual(self.state(111), 'WAITING_SUCCESSORS')
        self.assertEqual(self.store.status(111)['selected_chain_successors'], 1)

    def test_reorg_below_bootstrap_fails_and_rolls_back_whole_page(self):
        self.accepted()
        with self.assertRaisesRegex(TransferError, 'bootstrap'):
            self.store.apply(scan(3, removed=[3, 2, 1, 0], target=0), 111)
        self.assertEqual(self.store.tip, ident(3))
        self.assertEqual(self.state(111), 'SCAN_REQUIRED')

    def test_wrong_removal_order_is_atomic(self):
        self.accepted()
        with self.assertRaises(TransferError):
            self.store.apply(scan(3, removed=[3, 1], target=1), 111)
        self.assertEqual(self.store.tip, ident(3))
        self.assertEqual(self.state(111), 'SCAN_REQUIRED')

    def test_restart_preserves_history_but_requires_new_scan(self):
        self.accepted(); self.store.close(); self.store = self.open()
        self.assertEqual(self.state(), 'SCAN_REQUIRED')
        self.store.apply(scan(3), 111)
        self.assertEqual(self.state(111), 'OBSERVED_COMMITMENT')
        self.store.apply(scan(3, removed=[3], target=2), 112)
        self.assertEqual(self.state(112), 'WAITING_SUCCESSORS')

    def test_database_pins_transaction_and_observation_policy(self):
        for values in ({'min_successors': 1}, {'max_scan_age': 20}):
            with self.subTest(values=values), self.assertRaisesRegex(TransferError, 'configuration'):
                self.open(**values)
        with self.assertRaisesRegex(TransferError, 'configuration'):
            AnchorTracker(self.path, self.policy, self.envelope, ident(901), ident(0), 2, 10)

    def test_stale_or_future_scan_time_never_qualifies(self):
        self.accepted()
        self.assertEqual(self.state(120), 'OBSERVED_COMMITMENT')
        self.assertEqual(self.state(121), 'STALE')
        self.assertEqual(self.state(109), 'STALE')

    def test_expiry_remains_local_clock_check_after_observation(self):
        self.accepted(now=399)
        self.assertEqual(self.state(399), 'OBSERVED_COMMITMENT')
        self.assertEqual(self.state(400), 'PERMISSION_INACTIVE')

    def test_sampled_sink_backlog_blocks_otherwise_sufficient_depth(self):
        self.store.apply(scan(0, [1, 2, 3], target=5, transactions={1: [self.tx]}), 110)
        self.assertEqual(self.state(), 'CHAIN_BACKLOG')
        self.store.apply(scan(3, [4, 5]), 111)
        self.assertEqual(self.state(111), 'OBSERVED_COMMITMENT')

    def test_sampled_sink_may_precede_end_of_scan_page(self):
        self.store.apply(scan(0, [1, 2, 3], target=2, transactions={1: [self.tx]}), 110)
        self.assertEqual(self.state(), 'OBSERVED_COMMITMENT')

    def test_empty_page_before_target_is_failure(self):
        self.accepted()
        with self.assertRaisesRegex(TransferError, 'progress'):
            self.store.apply(scan(3, target=4), 111)
        self.assertEqual(self.state(111), 'SCAN_REQUIRED')

    def test_wrong_network_unhealthy_or_pre_activation_node_disables_status(self):
        self.accepted()
        for key, wrong in (('networkId', 'mainnet'), ('isSynced', False),
                           ('hasUtxoIndex', False), ('virtualDaaScore', 1)):
            value = scan(3); value['node'][key] = wrong
            with self.subTest(key=key), self.assertRaises(WatchError):
                self.store.apply(value, 111)
            self.assertEqual(self.state(111), 'SCAN_REQUIRED')

    def test_stale_cursor_and_clock_rollback_do_not_commit(self):
        self.accepted()
        for value, now in ((scan(0, [4]), 111), (scan(3, [4]), 109)):
            with self.assertRaises(TransferError): self.store.apply(value, now)
            self.assertEqual(self.store.tip, ident(3))
            self.assertEqual(self.state(), 'SCAN_REQUIRED')

    def test_incomplete_or_reordered_headers_and_duplicate_blocks_rejected(self):
        cases = [scan(0, [1, 2]), scan(0, [1, 2]), scan(0, [1, 1])]
        cases[0]['changes']['chainBlockAcceptedTransactions'].pop()
        cases[1]['changes']['chainBlockAcceptedTransactions'].reverse()
        for value in cases:
            with self.assertRaises(TransferError): self.store.apply(value, 110)
            self.assertEqual(self.store.tip, ident(0))

    def test_missing_transaction_ids_and_duplicate_acceptance_fail(self):
        for txs in (({},), (self.tx, self.tx)):
            with self.assertRaises((TransferError, KeyError)):
                self.store.apply(scan(0, [1], transactions={1: list(txs)}), 110)
            self.assertEqual(self.store.tip, ident(0))

    def test_transaction_cannot_be_accepted_twice_on_active_branch(self):
        self.accepted()
        with self.assertRaisesRegex(TransferError, 'already accepted'):
            self.store.apply(scan(3, [4], transactions={4: [self.tx]}), 111)
        self.assertEqual(self.store.tip, ident(3))

    def test_duplicate_active_block_rolls_back_new_prefix(self):
        self.accepted()
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.apply(scan(3, [4, 2]), 111)
        self.assertEqual(self.store.tip, ident(3))
        self.assertEqual(self.state(111), 'SCAN_REQUIRED')

    def test_local_processing_budgets_fail_before_committing(self):
        for value in (scan(0, list(range(1, 4098))),
                      scan(0, removed=list(range(1, 2050))),
                      scan(0, [1], transactions={1: [self.tx] * 100001})):
            with self.assertRaisesRegex(TransferError, 'budget'):
                self.store.apply(value, 110)
            self.assertEqual(self.store.tip, ident(0))

    def test_no_signer_broadcast_or_receipt_api_called_and_timeout_invalidates(self):
        self.accepted()
        calls = []
        class Native:
            def call(native, *args):
                calls.append(args)
                return scan(3)
        self.assertEqual(self.store.scan(Native(), lambda: 111)['state'], 'OBSERVED_COMMITMENT')
        self.assertEqual(calls, [('scan', ident(3))])
        class Failing:
            def call(native, *args): raise TimeoutError('synthetic timeout')
        with self.assertRaises(TimeoutError): self.store.scan(Failing(), lambda: 112)
        self.assertEqual(self.state(112), 'SCAN_REQUIRED')

    def test_rpc_latency_uses_fetch_start_for_freshness(self):
        self.accepted()
        class Native:
            def call(native, *args): return scan(3)
        times = iter([111, 122])
        self.assertEqual(self.store.scan(Native(), lambda: next(times))['state'], 'STALE')

    def test_caller_mutation_cannot_replace_pinned_envelope(self):
        self.envelope['manifest']['expires_at'] = 900
        self.accepted(now=399)
        self.assertEqual(self.state(400), 'PERMISSION_INACTIVE')

    def test_public_demo_is_explicitly_synthetic_and_reorg_revocable(self):
        value = demo()
        self.assertEqual(value['mode'], 'SYNTHETIC_CHAIN_NO_RPC_NO_FUNDS')
        self.assertEqual([s['state'] for s in value['snapshots']],
                         ['SCAN_REQUIRED', 'WAITING_SUCCESSORS', 'OBSERVED_COMMITMENT', 'NOT_FOUND'])
        source = Path(__file__).resolve().parents[1] / 'evidence/transfer-anchor-demo.json'
        import json
        self.assertEqual(value, json.loads(source.read_text()))


if __name__ == '__main__':
    unittest.main()
