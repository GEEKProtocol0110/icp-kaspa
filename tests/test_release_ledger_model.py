"""Adversarial tests for a synthetic ledger, not a production release service."""
import concurrent.futures
import copy
from dataclasses import asdict, replace
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from release_ledger_model import (MODE, Ed25519PrivateKey, FakeChain, ModelPolicy,
                                  ReleaseLedger, TransferError, demo, public, sign)


def tag(n):
    return f'{n:064x}'


class Crash(BaseException):
    pass


class ReleaseLedgerModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'model.sqlite'
        self.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.policy = ModelPolicy(tag(1), tag(2), public(self.keys[0]), public(self.keys[1]))
        self.now = 100
        self.ledger = self.open()
        self.record = dict(id=tag(3), version=1, cipher_hash=tag(4), bytes=128, context=tag(5))
        self.ledger.register_record(self.record, tag(6))
        self.chain = FakeChain(self.now)
        self.grant = tag(7)
        self.intent = self.intent_for(self.grant)
        self.issue(self.intent)

    def open(self, path=None):
        return ReleaseLedger(path or self.path, self.policy, lambda: self.now)

    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()

    def intent_for(self, grant):
        return dict(mode=MODE, network='testnet-10-model', policy=self.policy.id,
                    grant=grant, record=copy.deepcopy(self.record), recipient=public(self.keys[2]),
                    delivery_tag=tag(8), delivery_epoch=0, controller_tag=tag(9),
                    not_before=100, expires=300, uses=1)

    def issue(self, intent):
        plan = self.ledger.issue(intent, sign(self.keys[0], 'approve', intent),
                                 sign(self.keys[1], 'send', intent))
        self.chain.accept_issue(plan)
        self.ledger.confirm_issue(intent['grant'], self.chain)
        return plan

    def reserve(self, grant=None):
        body = self.ledger.challenge(grant or self.grant, 'request')
        return self.ledger.reserve(body, sign(self.keys[2], 'request', body), self.chain)

    def accepted(self):
        plan = self.reserve()
        self.ledger.submit(self.grant, self.chain)
        self.chain.accept_consume(plan)
        return plan

    def committed(self):
        plan = self.accepted()
        self.ledger.commit_response(self.grant, self.chain)
        return plan

    def retrieve(self):
        body = self.ledger.challenge(self.grant, 'retrieve')
        return self.ledger.retrieve(body, sign(self.keys[2], 'retrieve', body), self.chain)

    def quota(self):
        return [tuple(row) for row in self.ledger.db.execute('SELECT * FROM quotas ORDER BY window')]

    def reopen(self):
        self.ledger.close(); self.ledger = self.open()

    def test_full_flow_only_returns_non_secret_placeholder(self):
        self.committed()
        first = self.retrieve()
        self.assertEqual(json.loads(first)['kind'], 'NON_SECRET_RESPONSE_PLACEHOLDER')
        self.assertEqual(json.loads(first)['mode'], MODE)
        self.assertEqual(first, self.retrieve())
        self.assertEqual(self.quota(), [(0, 1, 128)])
        self.assertEqual(len(self.chain.submissions), 1)
        self.assertTrue(self.ledger.status(self.grant)['possible_disclosure'])

    def test_demo_is_explicitly_synthetic(self):
        result = demo()
        self.assertEqual((result['keys_delivered'], result['real_transactions']), (0, 0))
        self.assertEqual(result['mode'], MODE)

    def test_approvals_cannot_cross_domains_or_authorities(self):
        intent = self.intent_for(tag(10))
        for key, domain in ((self.keys[1], 'approve'), (self.keys[0], 'icp/lab/approve/v0')):
            with self.subTest(domain=domain), self.assertRaises(TransferError):
                self.ledger.issue(intent, sign(key, domain, intent), sign(self.keys[1], 'send', intent))
        with self.assertRaises(TransferError):
            self.ledger.issue(intent, sign(self.keys[0], 'approve', intent), sign(self.keys[2], 'send', intent))

    def test_changed_delivery_or_record_invalidates_signed_intent(self):
        original = self.intent_for(tag(10))
        for field in ('delivery_tag', 'record'):
            intent = copy.deepcopy(original)
            if field == 'record': intent[field]['cipher_hash'] = tag(99)
            else: intent[field] = tag(99)
            with self.subTest(field=field), self.assertRaises(TransferError):
                self.ledger.issue(intent, sign(self.keys[0], 'approve', original), sign(self.keys[1], 'send', original))

    def test_wrong_network_unknown_field_and_boolean_use_rejected(self):
        for change in ({'network': 'testnet-10'}, {'extra': 1}, {'uses': True}):
            intent = dict(self.intent_for(tag(10)), **change)
            with self.subTest(change=change), self.assertRaises(TransferError):
                self.ledger.issue(intent, sign(self.keys[0], 'approve', intent), sign(self.keys[1], 'send', intent))

    def test_record_key_tag_reuse_and_immutable_version_rejected(self):
        other = dict(self.record, version=2)
        with self.assertRaises(sqlite3.IntegrityError): self.ledger.register_record(other, tag(6))
        with self.assertRaises(sqlite3.IntegrityError): self.ledger.register_record(dict(self.record, bytes=200), tag(20))
        bad = self.intent_for(tag(10)); bad['record']['bytes'] = 129
        with self.assertRaises(TransferError): self.issue(bad)

    def test_duplicate_issue_survives_restart(self):
        self.reopen()
        with self.assertRaises(sqlite3.IntegrityError): self.issue(self.intent)
        self.assertEqual(self.ledger.status(self.grant)['state'], 'ISSUED')

    def test_unaccepted_or_wrong_issuance_binding_cannot_confirm(self):
        intent = self.intent_for(tag(10))
        plan = self.ledger.issue(intent, sign(self.keys[0], 'approve', intent), sign(self.keys[1], 'send', intent))
        with self.assertRaises(TransferError): self.ledger.confirm_issue(intent['grant'], self.chain)
        self.chain.accept_issue(plan)
        self.chain.views[1]['issues'][plan['ticket']] = (tag(999), 2)
        with self.assertRaises(TransferError): self.ledger.confirm_issue(intent['grant'], self.chain)

    def test_wrong_recipient_modified_nonce_and_wrong_purpose_do_not_charge(self):
        body = self.ledger.challenge(self.grant, 'request')
        for request, key, purpose in ((body, self.keys[1], 'request'),
                                      (dict(body, nonce=tag(123)), self.keys[2], 'request'),
                                      (body, self.keys[2], 'retrieve')):
            with self.assertRaises(TransferError):
                self.ledger.reserve(request, sign(key, purpose, request), self.chain)
        self.assertEqual(self.quota(), [])
        self.assertIsNone(self.ledger.outbox(self.grant)['consume'])

    def test_replay_request_cannot_claim_twice(self):
        body = self.ledger.challenge(self.grant, 'request'); sig = sign(self.keys[2], 'request', body)
        self.ledger.reserve(body, sig, self.chain)
        with self.assertRaises(TransferError): self.ledger.reserve(body, sig, self.chain)
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def race(self, grants):
        bodies = [self.ledger.challenge(grant, 'request') for grant in grants]
        def claim(body):
            ledger = self.open()
            try:
                ledger.reserve(body, sign(self.keys[2], 'request', body), self.chain)
                return True
            except TransferError:
                return False
            finally:
                ledger.close()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            return list(pool.map(claim, bodies))

    def test_two_connections_concurrently_claim_one_grant(self):
        self.assertEqual(sorted(self.race([self.grant, self.grant])), [False, True])
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_concurrent_grants_compete_for_atomic_count_budget(self):
        self.rebuild_with_limits(max_grants=1)
        self.issue(self.intent_for(tag(10)))
        self.assertEqual(sorted(self.race([self.grant, tag(10)])), [False, True])
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def rebuild_with_limits(self, **limits):
        self.ledger.close(); self.path.unlink()
        self.policy = replace(self.policy, **limits)
        self.ledger = self.open(); self.ledger.register_record(self.record, tag(6))
        self.chain = FakeChain(self.now); self.intent = self.intent_for(self.grant); self.issue(self.intent)

    def test_concurrent_grants_compete_for_atomic_byte_budget(self):
        self.rebuild_with_limits(max_bytes=200)
        self.issue(self.intent_for(tag(10)))
        self.assertEqual(sorted(self.race([self.grant, tag(10)])), [False, True])
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_expired_request_cannot_charge(self):
        body = self.ledger.challenge(self.grant, 'request'); self.now = body['expires']
        with self.assertRaises(TransferError): self.ledger.reserve(body, sign(self.keys[2], 'request', body), self.chain)
        self.assertEqual(self.quota(), [])

    def test_deadline_crossing_during_reservation_rolls_back_everything(self):
        body = self.ledger.challenge(self.grant, 'request')
        self.ledger.fault = lambda stage: setattr(self, 'now', body['expires']) if stage == 'reserve_before_commit' else None
        with self.assertRaises(TransferError): self.ledger.reserve(body, sign(self.keys[2], 'request', body), self.chain)
        self.assertEqual(self.quota(), [])
        self.assertIsNone(self.ledger.outbox(self.grant)['consume'])
        self.assertEqual(self.ledger.db.execute('SELECT used FROM challenges WHERE nonce=?', (body['nonce'],)).fetchone()[0], 0)

    def test_original_window_deadline_cannot_move_charge(self):
        self.rebuild_with_limits(window=120)
        self.committed(); first = self.retrieve(); self.now = 120
        with self.assertRaises(TransferError): self.retrieve()
        with self.assertRaises(TransferError): self.ledger.commit_response(self.grant, self.chain)
        self.assertEqual(self.quota(), [(0, 1, 128)])
        self.assertTrue(first)

    def test_reorg_before_commit_retains_outbox_and_quota(self):
        plan = self.accepted()
        self.chain.views[1]['spends'].clear()
        with self.assertRaises(TransferError): self.ledger.commit_response(self.grant, self.chain)
        self.assertIsNone(self.ledger.status(self.grant)['response_hash'])
        self.assertEqual(self.ledger.outbox(self.grant)['consume'], plan)
        self.assertEqual(self.quota(), [(0, 1, 128)])
        self.chain.accept_consume(plan); self.ledger.commit_response(self.grant, self.chain)

    def test_reorg_after_commit_blocks_dispatch_but_never_refunds_or_reissues(self):
        plan = self.committed(); first = self.retrieve(); original = self.ledger.status(self.grant)
        self.chain.views[0]['spends'].clear()
        with self.assertRaises(TransferError): self.retrieve()
        self.assertEqual(self.ledger.status(self.grant), original)
        self.assertEqual(self.quota(), [(0, 1, 128)])
        with self.assertRaises(TransferError): self.ledger.submit(self.grant, self.chain)
        self.chain.accept_consume(plan)
        self.ledger.commit_response(self.grant, self.chain)
        self.assertEqual(first, self.retrieve())

    def test_exact_consumption_id_binding_and_depth_required(self):
        plan = self.accepted()
        for value in (('model:' + tag(999), plan['commitment'], 2),
                      (plan['id'], tag(999), 2), (plan['id'], plan['commitment'], 1)):
            self.chain.views[1]['spends'][plan['ticket']] = value
            with self.subTest(value=value), self.assertRaises(TransferError):
                self.ledger.commit_response(self.grant, self.chain)

    def test_offline_stale_future_and_backlogged_observations_fail_closed(self):
        self.accepted(); saved = copy.deepcopy(self.chain.views[1])
        for change in ({'online': False}, {'caught_up': False}, {'at': 89}, {'at': 101}):
            self.chain.views[1] = dict(saved, **change)
            with self.subTest(change=change), self.assertRaises(TransferError):
                self.ledger.commit_response(self.grant, self.chain)

    def test_observation_expires_during_response_transaction(self):
        self.accepted()
        self.ledger.fault = lambda stage: setattr(self, 'now', 111) if stage == 'response_before_commit' else None
        with self.assertRaises(TransferError): self.ledger.commit_response(self.grant, self.chain)
        self.assertIsNone(self.ledger.status(self.grant)['response_hash'])

    def test_lost_submission_reply_is_reconcile_only(self):
        plan = self.reserve(); self.chain.lose_reply = True
        self.ledger.submit(self.grant, self.chain)
        self.assertEqual(self.ledger.status(self.grant)['state'], 'UNKNOWN')
        self.reopen()
        with self.assertRaises(TransferError): self.ledger.submit(self.grant, self.chain)
        self.chain.accept_consume(plan); self.ledger.commit_response(self.grant, self.chain)
        self.assertEqual(len(self.chain.submissions), 1)

    def crash_at(self, name):
        def fail(stage):
            if stage == name: raise Crash()
        self.ledger.fault = fail

    def test_crash_before_reservation_commit_rolls_back(self):
        self.crash_at('reserve_before_commit')
        with self.assertRaises(Crash): self.reserve()
        self.reopen()
        self.assertEqual(self.quota(), [])
        self.assertEqual(self.ledger.status(self.grant)['state'], 'ISSUED')

    def test_crash_after_reservation_commit_keeps_exact_plan(self):
        self.crash_at('reserve_after_commit')
        with self.assertRaises(Crash): self.reserve()
        plan = self.ledger.outbox(self.grant)['consume']; self.reopen()
        self.assertEqual(self.ledger.outbox(self.grant)['consume'], plan)
        with self.assertRaises(TransferError): self.reserve()
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_crash_after_submission_intent_never_retries(self):
        self.reserve(); self.crash_at('submit_intent_committed')
        with self.assertRaises(Crash): self.ledger.submit(self.grant, self.chain)
        self.reopen()
        self.assertEqual(len(self.chain.submissions), 0)
        self.assertEqual(self.ledger.status(self.grant)['state'], 'SUBMITTING')
        with self.assertRaises(TransferError): self.ledger.submit(self.grant, self.chain)

    def test_crash_after_effect_reconciles_original_only(self):
        plan = self.reserve(); self.crash_at('submit_effect_finished')
        with self.assertRaises(Crash): self.ledger.submit(self.grant, self.chain)
        self.reopen(); self.chain.accept_consume(plan)
        self.ledger.commit_response(self.grant, self.chain)
        self.assertEqual(len(self.chain.submissions), 1)

    def process_crash(self, stage):
        self.accepted()
        policy_path = Path(self.tmp.name) / 'policy.json'; policy_path.write_text(json.dumps(asdict(self.policy)))
        program = '''import json, os, sys
from release_ledger_model import *
policy=ModelPolicy(**json.load(open(sys.argv[2])))
def crash(stage):
    if stage==sys.argv[4]: os._exit(73)
ledger=ReleaseLedger(sys.argv[1],policy,lambda:100,crash)
chain=FakeChain(100)
outbox=ledger.outbox(sys.argv[3])
chain.accept_issue(outbox['issue']);chain.accept_consume(outbox['consume'])
ledger.commit_response(sys.argv[3],chain)
'''
        result = subprocess.run([sys.executable, '-c', program, str(self.path), str(policy_path), self.grant, stage],
                                env={'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'scripts')},
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 73, result.stderr.decode())
        self.reopen()

    def test_process_death_before_response_commit_has_no_response(self):
        self.process_crash('response_before_commit')
        self.assertIsNone(self.ledger.status(self.grant)['response_hash'])
        self.ledger.commit_response(self.grant, self.chain)

    def test_process_death_after_response_commit_keeps_identical_bytes(self):
        self.process_crash('response_after_commit')
        first = self.retrieve(); self.reopen()
        self.ledger.commit_response(self.grant, self.chain)
        self.assertEqual(first, self.retrieve())
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_deadline_crossing_during_response_commit_leaves_no_response(self):
        self.accepted()
        self.ledger.fault = lambda stage: setattr(self, 'now', 160) if stage == 'response_before_commit' else None
        with self.assertRaises(TransferError): self.ledger.commit_response(self.grant, self.chain)
        self.assertIsNone(self.ledger.status(self.grant)['response_hash'])
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_expiry_after_retrieval_claim_still_blocks_return(self):
        self.committed()
        self.ledger.fault = lambda stage: setattr(self, 'now', 160) if stage == 'retrieve_after_commit' else None
        with self.assertRaises(TransferError): self.retrieve()
        self.assertIsNotNone(self.ledger.status(self.grant)['response_hash'])

    def test_reorg_after_retrieval_claim_blocks_return(self):
        self.committed()
        self.ledger.fault = lambda stage: self.chain.views[0]['spends'].clear() if stage == 'retrieve_after_commit' else None
        with self.assertRaises(TransferError): self.retrieve()

    def test_retrieval_replay_and_request_signature_cannot_retrieve(self):
        self.committed(); body = self.ledger.challenge(self.grant, 'retrieve')
        with self.assertRaises(TransferError): self.ledger.retrieve(body, sign(self.keys[2], 'request', body), self.chain)
        signature = sign(self.keys[2], 'retrieve', body)
        self.ledger.retrieve(body, signature, self.chain)
        with self.assertRaises(TransferError): self.ledger.retrieve(body, signature, self.chain)

    def test_clock_rollback_latches_halt_across_restart(self):
        # Even a rejected expired request must preserve the observed clock.
        self.now = 300
        with self.assertRaisesRegex(TransferError, 'deadline'):
            self.ledger.challenge(self.grant, 'request')
        self.now = 100
        with self.assertRaisesRegex(TransferError, 'rollback'): self.ledger.challenge(self.grant, 'request')
        self.now = 300; self.reopen()
        with self.assertRaisesRegex(TransferError, 'halted'): self.reserve()

    def test_uncertain_clock_latches_halt(self):
        self.ledger.clock = lambda: None
        with self.assertRaisesRegex(TransferError, 'Uncertain clock'): self.reserve()
        self.reopen()
        with self.assertRaisesRegex(TransferError, 'halted'): self.reserve()

    def test_removed_issuance_blocks_already_committed_response(self):
        self.committed(); original = self.ledger.status(self.grant)
        self.chain.views[1]['issues'].clear()
        with self.assertRaises(TransferError): self.retrieve()
        self.assertEqual(self.ledger.status(self.grant), original)
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_new_window_new_grant_keeps_previous_charge(self):
        self.rebuild_with_limits(window=120, max_grants=1)
        self.reserve(); self.now = 120
        for view in self.chain.views: view['at'] = 120
        other = self.intent_for(tag(10)); self.issue(other); self.reserve(tag(10))
        self.assertEqual(self.quota(), [(0, 1, 128), (1, 1, 128)])

    def test_response_commit_racing_submit_reply_cannot_regress_state(self):
        plan = self.reserve()
        def finish(stage):
            if stage == 'submit_effect_finished':
                other = self.open()
                try:
                    self.chain.accept_consume(plan)
                    other.commit_response(self.grant, self.chain)
                finally:
                    other.close()
        self.ledger.fault = finish
        self.ledger.submit(self.grant, self.chain)
        self.assertEqual(self.ledger.status(self.grant)['state'], 'RESPONSE_COMMITTED')
        self.assertTrue(self.retrieve())

    def test_two_response_writers_commit_one_identical_placeholder(self):
        self.accepted()
        def commit(_):
            ledger = self.open()
            try:
                return ledger.commit_response(self.grant, self.chain)['response_hash']
            finally:
                ledger.close()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            hashes = list(pool.map(commit, range(2)))
        self.assertEqual(hashes[0], hashes[1])
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_reorg_after_final_sample_remains_an_unavoidable_observation_race(self):
        self.committed()
        original_check = self.chain.check
        calls = []
        def sampled_then_reorg(*args):
            original_check(*args)
            calls.append(1)
            if len(calls) == 4:
                # The final successful sample cannot predict a later reorg.
                self.chain.views[0]['spends'].clear()
        self.chain.check = sampled_then_reorg
        self.assertTrue(self.retrieve())
        self.assertTrue(self.ledger.status(self.grant)['possible_disclosure'])
        with self.assertRaises(TransferError): self.retrieve()
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_changed_policy_epoch_or_budget_cannot_reset_database(self):
        for change in ({'epoch': 1}, {'budget': tag(99)}, {'service': tag(99)}, {'max_grants': 99}):
            with self.subTest(change=change), self.assertRaisesRegex(TransferError, 'policy mismatch'):
                ReleaseLedger(self.path, replace(self.policy, **change), lambda: 100)

    def test_revocation_never_refunds_committed_grant(self):
        self.committed(); before = self.ledger.status(self.grant)['response_hash']
        self.ledger.revoke(self.grant)
        with self.assertRaises(TransferError): self.retrieve()
        self.assertEqual(before, self.ledger.status(self.grant)['response_hash'])
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_real_adapter_objects_are_rejected(self):
        body = self.ledger.challenge(self.grant, 'request')
        with self.assertRaisesRegex(TransferError, 'Only FakeChain'):
            self.ledger.reserve(body, sign(self.keys[2], 'request', body), object())
        self.assertTrue(self.ledger.outbox(self.grant)['issue']['ticket'].startswith('model:'))

    def test_explicit_uncertainty_halt_persists(self):
        self.reserve(); self.ledger.halt(); self.reopen()
        with self.assertRaisesRegex(TransferError, 'halted'): self.ledger.submit(self.grant, self.chain)
        self.assertEqual(self.quota(), [(0, 1, 128)])

    def test_copied_database_is_not_global_fencing(self):
        # Deliberate counterexample: a snapshot can be independently claimed.
        clone_path = Path(self.tmp.name) / 'clone.sqlite'
        shutil.copyfile(self.path, clone_path)
        clone = self.open(clone_path)
        try:
            self.reserve()
            body = clone.challenge(self.grant, 'request')
            clone.reserve(body, sign(self.keys[2], 'request', body), self.chain)
            self.assertNotEqual(self.ledger.outbox(self.grant)['consume'], clone.outbox(self.grant)['consume'])
        finally:
            clone.halt(); clone.close()
        self.assertEqual(self.quota(), [(0, 1, 128)])


if __name__ == '__main__':
    unittest.main()
