"""Synthetic cross-component recovery/fencing tests; never real key release."""
import concurrent.futures
from dataclasses import replace
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from release_coordinator_model import (MODE, Context, Coordinator, IntegrityError,
                                       ModelError, Policy, RecoveryRequired, demo)


class Crash(BaseException):
    pass


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / 'components'
        self.authority = self.base / 'independent' / 'authority.sqlite'
        self.now = 100
        self.policy = Policy()
        self.context = Context()
        self.model = self.open(create=True)
        self.model.recover()

    def open(self, create=False, root=None):
        return Coordinator(root or self.root, self.authority, self.policy, lambda: self.now, create=create)

    def tearDown(self):
        self.model.close()
        self.tmp.cleanup()

    def restart(self):
        self.model.close()
        self.model = self.open()
        self.model.recover()

    def reserved(self):
        self.model.reserve(self.context)
        self.model.observe(self.context.grant)

    def authorized(self):
        self.reserved(); self.model.authorize(self.context.grant)

    def prepared(self):
        self.authorized(); self.model.prepare(self.context.grant)

    def committed(self):
        self.prepared(); self.model.commit(self.context.grant)

    def dispatch(self, nonce='model:retrieval'):
        return self.model.dispatch(self.context.grant, self.context.request, nonce,
                                   self.model.status(self.context.grant)['response_hash'])

    def state(self, role):
        # Privileged test inspection, NOT an API offered to a recipient/coordinator caller.
        with sqlite3.connect(self.root / (role + '.sqlite')) as db:
            return json.loads(db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()[0])['state']

    def snapshot(self, name='backup'):
        target = self.base / name
        shutil.copytree(self.root, target)
        return target

    def fail_at(self, stage):
        def hook(actual):
            if actual == stage:
                raise Crash(stage)
        self.model.hook = hook

    def test_demo_is_synthetic_and_retry_is_identical(self):
        result = demo()
        self.assertEqual(result['mode'], MODE)
        self.assertTrue(result['identical_retry'])
        self.assertEqual((result['real_keys'], result['rpc_calls'], result['broadcasts']), (0, 0, 0))

    def test_recovery_is_required_before_mutation(self):
        self.model.close(); self.model = self.open()
        with self.assertRaises(RecoveryRequired): self.model.reserve(self.context)
        self.model.recover(); self.reserved()

    def test_exact_retry_and_restart_preserve_response_and_charge(self):
        self.committed()
        first = self.dispatch()
        self.restart()
        with self.assertRaises(ModelError): self.dispatch('model:retry')
        self.model.observe(self.context.grant)
        self.assertEqual(first, self.dispatch('model:retry'))
        self.model.reserve(self.context)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'], 1)

    def test_status_never_exposes_candidate_bytes(self):
        self.prepared()
        candidate = self.state('vault')['candidates'][self.context.grant]['response']
        status = json.dumps(self.model.status(self.context.grant))
        self.assertNotIn(candidate['placeholder'], status)
        self.assertNotIn('placeholder', status)
        self.assertIsNone(self.model.status(self.context.grant)['response_hash'])
        with self.assertRaises(ModelError): self.dispatch()

    def test_prepare_requires_durable_authorization(self):
        self.reserved()
        with self.assertRaises(ModelError): self.model.prepare(self.context.grant)
        self.assertEqual(self.state('vault')['candidates'], {})

    def test_commit_requires_private_saved_candidate(self):
        self.authorized()
        with self.assertRaises(ModelError): self.model.commit(self.context.grant)
        self.assertFalse(self.model.status(self.context.grant)['used'])

    def test_context_conflict_halts_and_does_not_replace_candidate(self):
        self.prepared()
        original = self.state('vault')
        with self.assertRaises(IntegrityError): self.model.reserve(replace(self.context, binding='model:other-binding'))
        self.assertEqual(self.state('vault'), original)
        with self.assertRaises(ModelError): self.model.commit(self.context.grant)

    def test_stable_operation_does_not_include_policy_or_writer_epoch(self):
        self.prepared(); original = self.state('vault')
        self.restart(); self.model.observe(self.context.grant)
        self.model.prepare(self.context.grant)
        self.assertEqual(self.state('vault'), original)
        self.model.advance_epochs(1, 1)
        with self.assertRaises(IntegrityError): self.model.reserve(replace(self.context, policy_epoch=1, delivery_epoch=1))
        self.assertEqual(self.state('vault'), original)

    def test_challenge_and_ticket_claims_are_permanent(self):
        self.reserved(); self.model.revoke(self.context.grant)
        for candidate in (replace(self.context, grant='model:other', ticket='model:other-ticket'),
                          replace(self.context, grant='model:other', challenge='model:other-challenge')):
            with self.assertRaises(ModelError): self.model.reserve(candidate)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'], 1)

    def test_exhausted_budget_does_not_partially_claim(self):
        self.reserved()
        other = replace(self.context, grant='model:other', challenge='model:new-challenge',
                        ticket='model:new-ticket', size=1000)
        with self.assertRaises(ModelError): self.model.reserve(other)
        self.model.reserve(replace(other, size=128))
        self.assertEqual(self.model.status(other.grant)['charges']['100']['count'], 2)

    def test_overlapping_or_changed_windows_cannot_reset_budget(self):
        self.reserved()
        other = replace(self.context, grant='model:other', challenge='model:new-challenge', ticket='model:new-ticket')
        for value in (replace(other, window_end=179), replace(other, window_start=99)):
            with self.assertRaises(ModelError): self.model.reserve(value)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['bytes'], 128)

    def test_epoch_rotation_keeps_charges_and_blocks_old_grants(self):
        self.committed(); before = self.model.status(self.context.grant)
        self.model.advance_epochs(1, 2)
        for action in (self.model.prepare, self.model.commit):
            with self.assertRaises(ModelError): action(self.context.grant)
        with self.assertRaises(ModelError): self.dispatch()
        other = replace(self.context, grant='model:other', challenge='model:new-challenge',
                        ticket='model:new-ticket', policy_epoch=1, delivery_epoch=2)
        self.model.reserve(other)
        self.assertEqual(self.model.status(other.grant)['charges']['100']['count'], 2)
        self.assertEqual(self.model.status(self.context.grant)['response_hash'], before['response_hash'])
        with self.assertRaises(ModelError): self.model.advance_epochs(0, 2)

    def test_revocation_before_prepare_keeps_charge_and_blocks_candidate(self):
        self.authorized(); self.model.revoke(self.context.grant)
        with self.assertRaises(ModelError): self.model.prepare(self.context.grant)
        self.assertEqual(self.state('vault')['candidates'], {})
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'], 1)

    def test_revocation_between_vault_and_ledger_keeps_private_candidate(self):
        self.prepared(); original = self.state('vault')
        self.model.revoke(self.context.grant)
        with self.assertRaises(ModelError): self.model.commit(self.context.grant)
        self.assertEqual(self.state('vault'), original)
        self.assertFalse(self.model.status(self.context.grant)['used'])
        with self.assertRaises(ModelError): self.dispatch()

    def test_revocation_after_commit_blocks_new_dispatch_and_keeps_history(self):
        self.committed(); original = self.model.status(self.context.grant)
        self.model.revoke(self.context.grant); self.model.revoke(self.context.grant)
        with self.assertRaises(ModelError): self.dispatch()
        after = self.model.status(self.context.grant)
        self.assertTrue(after['used'] and after['possible_disclosure'])
        self.assertEqual(after['charges'], original['charges'])
        self.assertEqual(after['response_hash'], original['response_hash'])
        self.assertEqual(self.state('ledger')['revocations'], 1)

    def test_revocation_before_dispatch_nonce_commit_orders_before_delivery(self):
        self.committed()
        # A revocation accepted first is visible under the gate's authority lock.
        self.model.revoke(self.context.grant)
        with self.assertRaises(ModelError): self.dispatch()
        self.assertEqual(self.state('delivery')['nonces'], {})

    def test_revocation_after_accepted_dispatch_cannot_recall_bytes(self):
        self.committed()
        def hook(stage):
            if stage == 'dispatch:acknowledged':
                self.model.hook = lambda _: None
                self.model.revoke(self.context.grant)
        self.model.hook = hook
        response = self.dispatch()
        self.assertEqual(json.loads(response)['mode'], MODE)
        self.assertTrue(self.model.status(self.context.grant)['revoked'])
        with self.assertRaises(ModelError): self.dispatch('model:later')

    def test_reorg_blocks_every_release_boundary_without_erasing_history(self):
        self.committed(); before = self.model.status(self.context.grant)
        self.model.observe(self.context.grant, (True, False))
        for action in (self.model.authorize, self.model.prepare, self.model.commit):
            with self.assertRaises(ModelError): action(self.context.grant)
        with self.assertRaises(ModelError): self.dispatch()
        self.assertEqual(self.model.status(self.context.grant), before)
        self.model.observe(self.context.grant)
        self.assertEqual(json.loads(self.dispatch())['mode'], MODE)

    def test_stale_observations_and_restart_cache_cannot_authorize(self):
        self.authorized(); self.now = 106
        with self.assertRaises(ModelError): self.model.prepare(self.context.grant)
        self.model.observe(self.context.grant); self.model.prepare(self.context.grant)
        self.restart()
        with self.assertRaises(ModelError): self.model.commit(self.context.grant)

    def test_original_window_end_blocks_prepare_commit_and_dispatch(self):
        self.committed(); self.now = self.context.window_end
        self.model.observe(self.context.grant)
        for action in (self.model.authorize, self.model.prepare, self.model.commit):
            with self.assertRaises(ModelError): action(self.context.grant)
        with self.assertRaises(ModelError): self.dispatch()
        self.assertTrue(self.model.status(self.context.grant)['possible_disclosure'])

    def test_expired_private_candidate_is_not_replaced_on_recovery(self):
        self.prepared(); original = self.state('vault')
        self.now = 201; self.restart(); self.model.observe(self.context.grant)
        with self.assertRaises(ModelError): self.model.commit(self.context.grant)
        self.assertEqual(self.state('vault'), original)
        self.assertFalse(self.model.status(self.context.grant)['committed'])

    def test_request_and_response_binding_and_nonce_replay(self):
        self.committed(); response_hash = self.model.status(self.context.grant)['response_hash']
        for request, expected_hash in (('model:wrong-request', response_hash), (self.context.request, '0' * 64)):
            with self.assertRaises(ModelError): self.model.dispatch(self.context.grant, request, 'model:nonce', expected_hash)
        self.assertEqual(self.state('delivery')['nonces'], {})
        self.dispatch()
        with self.assertRaises(ModelError): self.dispatch()
        self.restart(); self.model.observe(self.context.grant)
        with self.assertRaises(ModelError): self.dispatch()

    def test_old_writer_cannot_mutate_ledger_vault_or_delivery(self):
        self.committed(); old = self.model
        self.model = self.open(); self.model.recover(); self.model.observe(self.context.grant)
        try:
            for action in (lambda: old.reserve(self.context), lambda: old.prepare(self.context.grant),
                           lambda: old.commit(self.context.grant), lambda: old.revoke(self.context.grant),
                           lambda: old.dispatch(self.context.grant, self.context.request, 'model:old',
                                                self.model.status(self.context.grant)['response_hash'])):
                with self.assertRaises(ModelError): action()
            self.assertNotIn('model:old', self.state('delivery')['nonces'])
            self.dispatch()
        finally:
            old.close()

    def test_component_boundary_rejects_expired_lease(self):
        self.reserved()
        with self.model._step() as (lease, loaded):
            snapshot, previous = loaded['vault']
        with self.assertRaises(ModelError): self.model._stores['vault'].save(lease, snapshot, 'bypass', previous, lambda _: None)

    def test_two_workers_with_independent_connections_cannot_both_dispatch(self):
        self.committed()
        root, authority, policy, context = self.root, self.authority, self.policy, self.context
        def worker(index):
            model = Coordinator(root, authority, policy, lambda: 100)
            try:
                model.recover(); model.observe(context.grant)
                response_hash = model.status(context.grant)['response_hash']
                model.dispatch(context.grant, context.request, 'model:shared-nonce', response_hash)
                return 'delivered'
            except ModelError:
                return 'blocked'
            finally:
                model.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(worker, range(2)))
        self.assertEqual(results.count('delivered'), 1)

    def test_restored_ledger_behind_independent_witness_halts(self):
        backup = self.snapshot(); self.reserved()
        self.model.close(); shutil.copyfile(backup / 'ledger.sqlite', self.root / 'ledger.sqlite')
        self.model = self.open()
        with self.assertRaises(IntegrityError): self.model.recover()
        with self.assertRaises(ModelError): self.model.reserve(self.context)

    def test_restored_vault_behind_witness_halts_without_recreating(self):
        self.authorized(); backup = self.snapshot(); self.model.prepare(self.context.grant)
        self.model.close(); shutil.copyfile(backup / 'vault.sqlite', self.root / 'vault.sqlite')
        self.model = self.open()
        with self.assertRaises(IntegrityError): self.model.recover()
        self.assertEqual(self.state('vault')['candidates'], {})

    def test_restored_delivery_journal_cannot_reset_nonce(self):
        self.committed(); backup = self.snapshot(); self.dispatch()
        self.model.close(); shutil.copyfile(backup / 'delivery.sqlite', self.root / 'delivery.sqlite')
        self.model = self.open()
        with self.assertRaises(IntegrityError): self.model.recover()

    def test_cloned_components_cannot_race_live_authority_from_old_prefix(self):
        self.reserved(); clone = self.snapshot(); self.model.authorize(self.context.grant)
        other = self.open(root=clone)
        try:
            with self.assertRaises(IntegrityError): other.recover()
            with self.assertRaises(ModelError): self.model.prepare(self.context.grant)
        finally:
            other.close()

    def test_tampered_component_history_halts(self):
        self.reserved()
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            db.execute("UPDATE events SET hash=? WHERE seq=1", ('f' * 64,))
        with self.assertRaises(IntegrityError): self.model.status(self.context.grant)
        with self.assertRaises(ModelError): self.model.reserve(self.context)

    def test_checkpoint_conflict_halts(self):
        self.reserved()
        with sqlite3.connect(self.authority) as db:
            db.execute("UPDATE checkpoints SET hash=? WHERE role='ledger' AND seq=1", ('f' * 64,))
        with self.assertRaises(IntegrityError): self.model.status(self.context.grant)

    def test_missing_authority_is_not_silently_reinitialized(self):
        self.reserved(); missing = self.base / 'absent.sqlite'
        with self.assertRaises(IntegrityError): Coordinator(self.root, missing, self.policy, lambda: 100)
        self.assertFalse(missing.exists())

    def test_initialization_and_policy_mismatch_do_not_reset_state(self):
        self.reserved()
        with self.assertRaises(ModelError): self.open(create=True)
        with self.assertRaises(IntegrityError): Coordinator(self.root, self.authority, replace(self.policy, count_limit=99), lambda: 100)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'], 1)

    def test_backward_clock_latches_halt(self):
        self.reserved(); self.now = 99
        with self.assertRaises(ModelError): self.model.status(self.context.grant)
        self.now = 100
        with self.assertRaises(ModelError): self.model.status(self.context.grant)

    def test_failed_request_preserves_clock_high_water(self):
        self.reserved(); self.now = 110
        with self.assertRaises(ModelError): self.model.prepare(self.context.grant)
        self.now = 109
        with self.assertRaises(ModelError): self.model.status(self.context.grant)
        self.now = 110
        with self.assertRaises(ModelError): self.model.status(self.context.grant)

    def test_uncertain_clock_latches_halt(self):
        self.reserved(); self.now = None
        with self.assertRaises(ModelError): self.model.status(self.context.grant)
        self.now = 100
        with self.assertRaises(ModelError): self.model.status(self.context.grant)

    def test_backward_clock_at_boundary_exit_blocks_response(self):
        self.committed()
        response_hash = self.model.status(self.context.grant)['response_hash']
        values = iter([100, 99])
        self.model._authority.clock = lambda: next(values)
        with self.assertRaises(ModelError):
            self.model.dispatch(self.context.grant, self.context.request, 'model:clock-failure', response_hash)
        self.assertIn('model:clock-failure', self.state('delivery')['nonces'])

    def test_pending_vault_ack_requires_recovery_and_keeps_same_candidate(self):
        self.authorized(); self.fail_at('vault:saved')
        with self.assertRaises(Crash): self.model.prepare(self.context.grant)
        original = self.state('vault')
        self.model.hook = lambda _: None
        with self.assertRaises(RecoveryRequired): self.model.commit(self.context.grant)
        self.restart(); self.model.observe(self.context.grant); self.model.prepare(self.context.grant)
        self.model.commit(self.context.grant)
        self.assertEqual(self.state('vault'), original)
        self.assertEqual(json.loads(self.dispatch()), original['candidates'][self.context.grant]['response'])

    def test_response_commit_lost_reply_recovers_identical_bytes(self):
        self.prepared(); original = self.state('vault')['candidates'][self.context.grant]['response']
        self.fail_at('commit:acknowledged')
        with self.assertRaises(Crash): self.model.commit(self.context.grant)
        self.restart(); self.model.observe(self.context.grant); self.model.commit(self.context.grant)
        self.assertEqual(json.loads(self.dispatch()), original)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'], 1)

    def test_pending_ledger_checkpoint_blocks_dispatch_until_exact_recovery(self):
        self.prepared(); self.fail_at('ledger:saved')
        with self.assertRaises(Crash): self.model.commit(self.context.grant)
        self.model.hook = lambda _: None
        with self.assertRaises(RecoveryRequired): self.dispatch()
        self.restart(); self.model.observe(self.context.grant)
        self.assertTrue(self.model.status(self.context.grant)['used'])
        self.dispatch()

    def test_dispatch_lost_ack_keeps_nonce_consumed(self):
        self.committed(); self.fail_at('delivery:saved')
        with self.assertRaises(Crash): self.dispatch()
        self.restart(); self.model.observe(self.context.grant)
        with self.assertRaises(ModelError): self.dispatch()
        self.assertEqual(json.loads(self.dispatch('model:new-retrieval'))['mode'], MODE)

    def test_revocation_saved_before_lost_ack_is_reconciled_not_undone(self):
        self.prepared(); self.fail_at('ledger:saved')
        with self.assertRaises(Crash): self.model.revoke(self.context.grant)
        self.restart(); self.model.observe(self.context.grant)
        with self.assertRaises(ModelError): self.model.commit(self.context.grant)
        self.assertTrue(self.model.status(self.context.grant)['revoked'])

    def test_real_process_crashes_around_vault_commit(self):
        self.authorized(); self.model.close()
        for stage, should_exist in [('vault:before_commit', False), ('vault:saved', True), ('prepare:acknowledged', True)]:
            with self.subTest(stage=stage):
                script = '''import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from release_coordinator_model import Coordinator,Policy,Context
m=Coordinator(sys.argv[2],sys.argv[3],Policy(),lambda:100)
m.recover();m.observe(Context().grant)
m.hook=lambda stage: os._exit(73) if stage==sys.argv[4] else None
m.prepare(Context().grant)
'''
                result = subprocess.run([sys.executable, '-c', script, str(Path(__file__).resolve().parents[1] / 'scripts'),
                                         str(self.root), str(self.authority), stage], capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 73, result.stderr.decode())
                self.assertEqual(bool(self.state('vault')['candidates']), should_exist)
                original = self.state('vault')
                self.model = self.open(); self.model.recover(); self.model.observe(self.context.grant)
                if should_exist:
                    self.model.prepare(self.context.grant)
                    self.assertEqual(self.state('vault'), original)
                self.model.close()
        self.model = self.open(); self.model.recover(); self.model.observe(self.context.grant)
        self.model.commit(self.context.grant); self.dispatch()

    def test_rolling_back_authority_together_with_components_is_outside_target(self):
        self.committed(); backup = self.snapshot()
        authority_backup = self.base / 'authority-backup.sqlite'
        shutil.copyfile(self.authority, authority_backup)
        first = self.dispatch()
        self.model.close()
        for role in ('ledger', 'vault', 'delivery'):
            shutil.copyfile(backup / (role + '.sqlite'), self.root / (role + '.sqlite'))
        shutil.copyfile(authority_backup, self.authority)
        self.model = self.open(); self.model.recover(); self.model.observe(self.context.grant)
        # Counterexample: a rolled-back witness cannot detect its own lost history.
        self.assertEqual(first, self.dispatch())

    def test_reservation_lost_ack_recovers_one_charge_and_original_claims(self):
        self.fail_at('ledger:saved')
        with self.assertRaises(Crash): self.model.reserve(self.context)
        self.restart(); self.model.reserve(self.context)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'], 1)
        self.model.observe(self.context.grant); self.model.authorize(self.context.grant)
        self.model.prepare(self.context.grant); self.model.commit(self.context.grant); self.dispatch()

    def test_foreign_authority_lease_cannot_write_private_vault(self):
        other = Coordinator(self.base / 'other', self.base / 'other-authority.sqlite',
                            self.policy, lambda: 100, create=True)
        try:
            other.recover()
            with self.model._step() as (_, loaded):
                state, previous = loaded['vault']
            with self.assertRaises(IntegrityError):
                with other._step() as (lease, _):
                    self.model._stores['vault'].save(lease, state, 'foreign', previous, lambda _: None)
            self.assertEqual(self.state('vault')['candidates'], {})
        finally:
            other.close()

    def test_missing_candidate_after_response_commit_is_integrity_failure(self):
        self.committed()
        # Inject a trusted-component storage fault, including a matching checkpoint.
        with self.model._step() as (lease, loaded):
            loaded['vault'][0]['candidates'].clear()
            self.model._save(lease, loaded, 'vault', 'injected-loss')
        with self.assertRaises(IntegrityError): self.model.prepare(self.context.grant)
        self.assertEqual(self.state('vault')['candidates'], {})
        with self.assertRaises(ModelError): self.dispatch()

    def test_expiry_before_window_end_blocks_existing_candidate(self):
        self.context = replace(self.context, expires=120)
        self.prepared(); self.now = 120; self.model.observe(self.context.grant)
        with self.assertRaises(ModelError): self.model.commit(self.context.grant)
        self.assertFalse(self.model.status(self.context.grant)['used'])

    def test_reorg_after_accepted_dispatch_cannot_recall_bytes(self):
        self.committed()
        def hook(stage):
            if stage == 'dispatch:acknowledged':
                self.model.hook = lambda _: None
                self.model.observe(self.context.grant, (False, False))
        self.model.hook = hook
        self.assertEqual(json.loads(self.dispatch())['mode'], MODE)
        with self.assertRaises(ModelError): self.dispatch('model:after-reorg')
        self.assertTrue(self.model.status(self.context.grant)['possible_disclosure'])

    def test_malformed_journal_body_latches_integrity_halt(self):
        self.reserved()
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            db.execute("UPDATE events SET body='{' WHERE seq=1")
        with self.assertRaises(IntegrityError): self.model.status(self.context.grant)
        with self.assertRaises(ModelError): self.model.recover()

    def test_candidate_response_from_another_context_is_not_committed(self):
        self.prepared()
        from release_coordinator_model import digest
        # Model a component fault that saves a valid digest for the wrong response.
        with self.model._step() as (lease, loaded):
            candidate = loaded['vault'][0]['candidates'][self.context.grant]
            candidate['response']['context'] = 'model:wrong-context'
            candidate['response_hash'] = digest(candidate['response'])
            self.model._save(lease, loaded, 'vault', 'injected-wrong-response')
        with self.assertRaises(IntegrityError): self.model.commit(self.context.grant)
        self.assertFalse(self.state('ledger')['grants'][self.context.grant]['used'])

    def test_model_labels_and_exact_types_reject_real_or_ambiguous_inputs(self):
        for kwargs in ({'grant': 'kaspa:real'}, {'size': True}, {'window_end': 100}, {'policy_epoch': -1}):
            with self.assertRaises(ModelError): Context(**kwargs)
        with self.assertRaises(ModelError): self.model.reserve({'grant': 'model:grant'})
        with self.assertRaises(ModelError): self.model.observe(self.context.grant, (1, True))


if __name__ == '__main__':
    unittest.main()
