"""Actual native fixture outboxes, trusted local journal/authority and fake effects."""
import concurrent.futures
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import native_ticket_controller as lab


class Crash(BaseException):
    pass


class NativeControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / 'components'
        self.authority = self.base / 'independent/authority.sqlite'
        self.issue = json.loads((lab.ROOT / 'evidence/native-ticket-lab-demo.json').read_text())['examples'][0]['plan']
        self.worker = lab.Worker()
        self.now = 100
        self.c = self.open(create=True)
        self.c.recover()
        self.a, self.b = lab.FakeNode(), lab.FakeNode()

    def open(self, create=False, root=None, authority=None, worker=None):
        return lab.Controller(root or self.root, authority or self.authority, self.issue,
                              lambda: self.now, create=create, worker=worker or self.worker)

    def tearDown(self):
        self.c.close()
        self.tmp.cleanup()

    def restart(self):
        self.c.close(); self.c = self.open(); self.c.recover()

    def issued(self):
        info = self.c.prepare('issue')
        self.c.submit_fake('issue', self.a)
        self.b.accept(info)
        self.assertTrue(self.c.observe_fake('issue', self.a, self.b))
        return info

    def choose(self, action='consume'):
        return self.c.choose(self.worker.terminal(self.issue, action))

    def record(self, phase):
        # Privileged inspection of the private fixture DB, never a status API.
        with sqlite3.connect(self.root / 'ticket.sqlite') as db:
            row = db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()
            return json.loads(row[0])['state'][phase + '_record']

    def crash_at(self, stage):
        def hook(actual):
            if actual == stage:
                raise Crash(stage)
        self.c.hook = hook

    def test_demo_recovers_native_outbox_and_blocks_opposite_branch(self):
        result = lab.demo()
        self.assertEqual(result['mode'], lab.MODE)
        for key in ('identical_saved_transaction', 'retry_reconciles_without_effect', 'opposite_branch_blocked'):
            self.assertIs(result[key], True)
        self.assertEqual((result['real_rpc_calls'], result['broadcasts'], result['content_keys']), (0, 0, 0))

    def test_recovery_required_before_new_or_existing_work(self):
        self.c.close(); self.c = self.open()
        with self.assertRaises(lab.RecoveryRequired): self.c.prepare('issue')
        self.c.recover(); self.c.prepare('issue')

    def test_issue_record_is_exact_after_repeated_prepare_and_restart(self):
        first = self.c.prepare('issue'); raw = self.record('issue')
        self.restart()
        with patch.object(self.worker, 'prepare', side_effect=AssertionError('must not sign')):
            self.assertEqual(self.c.prepare('issue'), first)
        self.assertEqual(self.record('issue'), raw)

    def test_terminal_requires_permanent_choice_before_signing(self):
        self.issued()
        with patch.object(self.worker, 'prepare', side_effect=AssertionError('must not sign')):
            with self.assertRaises(lab.ModelError): self.c.prepare('terminal')

    def test_branch_choice_requires_current_reconciled_issue(self):
        with self.assertRaises(lab.ModelError): self.choose()
        info = self.c.prepare('issue')
        self.a.accept(info); self.b.accept(info)
        with self.assertRaises(lab.ModelError): self.c.observe_fake('issue', self.a, self.b)
        with self.assertRaises(lab.ModelError): self.choose()

    def test_consume_choice_and_original_charge_survive_restart(self):
        self.issued(); status = self.choose(); self.restart()
        self.assertEqual(self.c.status()['charge'], dict(count=1, bytes=128, window_start=100, window_end=180))
        self.assertEqual(status['branch'], self.c.status()['branch'])
        with self.assertRaises(lab.ModelError): self.choose('refund')

    def test_premature_expiry_refund_cannot_select_branch(self):
        self.issued()
        with self.assertRaises(lab.ModelError): self.choose('refund')
        self.assertIsNone(self.c.status()['branch'])
        self.choose()

    def test_unused_expiry_refund_stays_closed_without_charge(self):
        self.issued(); self.now = 200; self.c.observe_fake('issue', self.a, self.b)
        self.choose('refund'); self.c.prepare('terminal'); self.restart()
        self.assertEqual(self.c.status()['branch'], 'refund')
        self.assertIsNone(self.c.status()['charge'])
        with self.assertRaises(lab.ModelError): self.choose()

    def test_revoked_refund_is_only_a_trusted_fixture_input(self):
        self.issued(); p = self.worker.terminal(self.issue, 'refund'); p['closure']['reason'] = 'revoked'
        self.c.choose(p); self.c.prepare('terminal')
        self.assertEqual(self.c.status()['branch'], 'refund')
        self.assertIsNone(self.c.status()['charge'])

    def test_expired_reserved_grant_never_switches_or_refunds_charge(self):
        self.issued(); self.choose(); self.now = 200; self.c.observe_fake('issue', self.a, self.b)
        with self.assertRaises(lab.ModelError): self.c.prepare('terminal')
        with self.assertRaises(lab.ModelError): self.choose('refund')
        self.assertEqual(self.c.status()['charge']['count'], 1)

    def test_terminal_outbox_is_exact_after_restart_without_signing(self):
        self.issued(); self.choose(); first = self.c.prepare('terminal'); raw = self.record('terminal')
        self.restart()
        with patch.object(self.worker, 'prepare', side_effect=AssertionError('must not sign')):
            self.assertEqual(self.c.prepare('terminal'), first)
        self.assertEqual(self.record('terminal'), raw)

    def test_signer_failure_preserves_choice_without_alternate_outbox(self):
        self.issued(); self.choose()
        with patch.object(self.worker, 'prepare', side_effect=lab.WorkerUnavailable('offline')):
            with self.assertRaises(lab.WorkerUnavailable): self.c.prepare('terminal')
        self.assertIsNone(self.record('terminal'))
        with self.assertRaises(lab.ModelError): self.choose('refund')
        self.c.prepare('terminal')

    def test_unknown_issue_submission_is_reconcile_only_after_restart(self):
        info = self.c.prepare('issue'); self.a.lose_reply = True
        with self.assertRaises(lab.ModelError): self.c.submit_fake('issue', self.a)
        self.restart(); self.assertEqual(self.c.submit_fake('issue', self.a), 'RECONCILE_ONLY')
        self.assertEqual(self.a.calls, 1)
        self.b.accept(info); self.assertTrue(self.c.observe_fake('issue', self.a, self.b)); self.choose()

    def test_unknown_terminal_submission_never_attempts_again(self):
        self.issued(); self.choose(); info = self.c.prepare('terminal'); self.a.lose_reply = True
        with self.assertRaises(lab.ModelError): self.c.submit_fake('terminal', self.a)
        self.restart(); self.assertEqual(self.c.submit_fake('terminal', self.a), 'RECONCILE_ONLY')
        self.assertEqual(self.a.calls, 2)
        self.b.accept(info); self.assertTrue(self.c.observe_fake('terminal', self.a, self.b))
        self.assertEqual(self.c.status()['terminal_attempt'], 'OBSERVED')

    def test_crash_after_intent_before_effect_forbids_retry_even_if_absent(self):
        self.c.prepare('issue'); self.crash_at('issue-intent:acknowledged')
        with self.assertRaises(Crash): self.c.submit_fake('issue', self.a)
        self.restart(); self.assertEqual(self.c.submit_fake('issue', self.a), 'RECONCILE_ONLY')
        self.assertEqual(self.a.calls, 0)
        self.assertFalse(self.c.observe_fake('issue', self.a, self.b))

    def test_branch_saved_before_ack_recovers_same_choice(self):
        self.issued(); self.crash_at('branch:saved')
        with self.assertRaises(Crash): self.choose()
        with self.assertRaises(lab.RecoveryRequired): self.c.status()
        self.restart(); self.assertEqual(self.c.status()['branch'], 'consume')
        with self.assertRaises(lab.ModelError): self.choose('refund')

    def test_failure_before_branch_component_commit_does_not_choose(self):
        self.issued(); self.crash_at('branch:before_commit')
        with self.assertRaises(Crash): self.choose()
        self.restart(); self.assertIsNone(self.c.status()['branch'])

    def test_terminal_outbox_saved_before_ack_is_recovered_without_signing(self):
        self.issued(); self.choose(); self.crash_at('terminal-outbox:saved')
        with self.assertRaises(Crash): self.c.prepare('terminal')
        raw = self.record('terminal'); self.restart()
        with patch.object(self.worker, 'prepare', side_effect=AssertionError('must not sign')):
            self.c.prepare('terminal')
        self.assertEqual(raw, self.record('terminal'))

    def test_samples_do_not_survive_restart(self):
        self.issued(); self.choose(); self.restart()
        with self.assertRaises(lab.ModelError): self.c.prepare('terminal')
        self.c.observe_fake('issue', self.a, self.b); self.c.prepare('terminal')

    def test_stale_or_disagreeing_samples_stop_new_signing(self):
        self.issued(); self.choose(); self.now = 106
        with self.assertRaises(lab.ModelError): self.c.prepare('terminal')
        self.b.accepted.clear(); self.assertFalse(self.c.observe_fake('issue', self.a, self.b))
        with self.assertRaises(lab.ModelError): self.c.prepare('terminal')

    def test_fake_reorg_preserves_branch_charge_and_outbox(self):
        self.issued(); self.choose(); self.c.prepare('terminal'); before = self.c.status()
        self.a.accepted.clear(); self.assertFalse(self.c.observe_fake('issue', self.a, self.b))
        with self.assertRaises(lab.ModelError): self.c.submit_fake('terminal', self.a)
        self.assertEqual(self.c.status(), before)
        with self.assertRaises(lab.ModelError): self.choose('refund')

    def test_status_never_exposes_signature_or_saved_native_bytes(self):
        self.issued(); self.choose(); self.c.prepare('terminal')
        raw = json.dumps(self.c.status()); signed = json.loads(self.record('terminal'))
        self.assertNotIn(signed['transaction']['inputs'][0]['signatureScript'], raw)
        self.assertNotIn('signature', raw); self.assertNotIn('transaction', raw)

    def test_restore_component_behind_witness_halts(self):
        self.issued(); backup = self.base / 'backup'; shutil.copytree(self.root, backup)
        self.choose(); self.c.close(); shutil.rmtree(self.root); shutil.copytree(backup, self.root)
        self.c = self.open()
        with self.assertRaises(lab.IntegrityError): self.c.recover()
        with self.assertRaises(lab.ModelError): self.c.recover()

    def test_changed_native_record_halts_without_replacement(self):
        self.issued(); self.choose(); self.c.prepare('terminal')
        db = self.c._journal.db
        seq, raw = db.execute('SELECT seq,body FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        body = json.loads(raw); body['state']['terminal_record'] += ' '
        db.execute('UPDATE events SET body=? WHERE seq=?', (json.dumps(body), seq))
        with self.assertRaises(lab.IntegrityError): self.c.recover()

    def test_worker_unavailability_blocks_without_erasing_outbox(self):
        self.issued(); self.choose(); self.c.prepare('terminal'); raw = self.record('terminal')
        with patch.object(self.worker, 'verify', side_effect=lab.WorkerUnavailable('offline')):
            with self.assertRaises(lab.WorkerUnavailable): self.c.status()
        self.assertEqual(raw, self.record('terminal')); self.c.status()

    def test_old_generation_cannot_sign_or_submit(self):
        self.c.prepare('issue'); newer = self.open(); newer.recover()
        try:
            with self.assertRaises(lab.ModelError): self.c.prepare('issue')
            with self.assertRaises(lab.ModelError): self.c.submit_fake('issue', self.a)
            self.assertEqual(self.a.calls, 0)
        finally:
            newer.close()

    def test_independent_connections_serialize_opposite_choices(self):
        self.issued(); self.now = 200; self.c.observe_fake('issue', self.a, self.b)
        consume = self.worker.terminal(self.issue, 'consume')
        # Both branches eligible at a chosen logical instant: revocation is fixture input.
        refund = self.worker.terminal(self.issue, 'refund'); refund['closure']['reason'] = 'revoked'
        self.now = 100
        # Use new clock-continuous deployment rather than resetting the authority clock.
        self.c.close(); self.root = self.base / 'race'; self.authority = self.base / 'race-authority/state.sqlite'
        self.c = self.open(create=True); self.c.recover(); self.issued()
        generation = self.c.generation
        def choose(plan):
            c = self.open(); c.generation = generation
            try:
                c.observe_fake('issue', self.a, self.b)
                try: c.choose(plan); return plan['action']
                except lab.ModelError: return 'blocked'
            finally: c.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(choose, (consume, refund)))
        self.assertEqual(results.count('blocked'), 1)
        self.assertIn(self.c.status()['branch'], results)

    def test_identical_choice_is_idempotent_but_context_substitution_halts(self):
        self.issued(); first = self.choose(); self.assertEqual(self.choose(), first)
        other = self.worker.terminal(self.issue, 'consume'); other['admission']['request_digest'] = '31' * 32
        with self.assertRaises(lab.IntegrityError): self.c.choose(other)

    def test_funded_sources_wrong_network_and_unknown_fields_are_rejected(self):
        for key, value in [('network', 'mainnet'), ('funding_transaction_id', 'ff' * 32), ('extra', 0)]:
            p = deepcopy(self.issue); p[key] = value
            with self.assertRaises(lab.ModelError): self.worker.validate(p)

    def test_real_adapter_subclasses_and_same_fake_endpoint_are_refused(self):
        class Other(lab.FakeNode): pass
        self.c.prepare('issue')
        with self.assertRaises(lab.ModelError): self.c.submit_fake('issue', Other())
        with self.assertRaises(lab.ModelError): self.c.observe_fake('issue', self.a, self.a)
        self.assertEqual(self.a.calls, 0)

    def test_cached_plan_mutation_cannot_change_pinned_operation(self):
        self.c.issue['context']['grant'] = 'model:substitution'
        with patch.object(self.worker, 'prepare', side_effect=AssertionError('must not sign')):
            with self.assertRaises(lab.IntegrityError): self.c.prepare('issue')

    def test_changed_worker_binary_is_refused_without_losing_saved_record(self):
        binary = self.base / 'fixture-worker'
        shutil.copy2(self.worker.path, binary)
        worker = lab.Worker(binary)
        c = self.open(create=True, root=self.base / 'worker-component',
                      authority=self.base / 'worker-authority/state.sqlite', worker=worker)
        try:
            c.recover(); c.prepare('issue'); expected = c.status()['issue_outbox_hash']
            with binary.open('ab') as f: f.write(b'changed')
            with self.assertRaises(lab.WorkerUnavailable): c.status()
            shutil.copy2(self.worker.path, binary)
            self.assertEqual(c.status()['issue_outbox_hash'], expected)
        finally:
            c.close()

    def test_backward_clock_halts_before_signing(self):
        self.issued(); self.choose(); self.now = 99
        with patch.object(self.worker, 'prepare', side_effect=AssertionError('must not sign')):
            with self.assertRaises(lab.ModelError): self.c.prepare('terminal')
        self.now = 100
        with self.assertRaises(lab.ModelError): self.c.status()

    def test_deadline_crossing_after_intent_blocks_fake_effect_and_retry(self):
        self.c.prepare('issue')
        def hook(stage):
            if stage == 'issue-intent:acknowledged': self.now = 200
        self.c.hook = hook
        with self.assertRaises(lab.ModelError): self.c.submit_fake('issue', self.a)
        self.assertEqual(self.a.calls, 0)
        self.restart()
        self.assertEqual(self.c.submit_fake('issue', self.a), 'RECONCILE_ONLY')

    def test_missing_store_and_reinitialization_do_not_reset_history(self):
        self.issued(); self.choose()
        with self.assertRaises(FileExistsError): self.open(create=True)
        self.c.close(); (self.root / 'ticket.sqlite').unlink()
        with self.assertRaises(lab.IntegrityError): self.open()

    def test_joint_authority_restore_counterexample_can_lose_branch(self):
        self.issued(); saved = self.base / 'both'; saved.mkdir()
        shutil.copytree(self.root, saved / 'component'); shutil.copy2(self.authority, saved / 'authority.sqlite')
        self.choose(); self.c.close()
        shutil.rmtree(self.root); shutil.copytree(saved / 'component', self.root)
        shutil.copy2(saved / 'authority.sqlite', self.authority)
        self.c = self.open(); self.c.recover(); self.c.observe_fake('issue', self.a, self.b)
        p = self.worker.terminal(self.issue, 'refund'); p['closure']['reason'] = 'revoked'
        self.c.choose(p); self.assertEqual(self.c.status()['branch'], 'refund')

    def test_real_child_process_exit_after_branch_or_outbox_commit(self):
        # Separate actual processes leave the journal ahead of an uncommitted witness.
        for phase in ('branch:saved', 'terminal-outbox:saved'):
            with self.subTest(phase=phase):
                base = self.base / phase.replace(':', '-')
                root, authority = base / 'component', base / 'independent/state.sqlite'
                c = self.open(create=True, root=root, authority=authority); c.recover()
                info = c.prepare('issue'); c.submit_fake('issue', self.a); self.b.accept(info)
                c.observe_fake('issue', self.a, self.b)
                if phase.startswith('terminal'): c.choose(self.worker.terminal(self.issue, 'consume'))
                c.close()
                code = '''import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import native_ticket_controller as l
p=json.loads((l.ROOT/'evidence/native-ticket-lab-demo.json').read_text())['examples'][0]['plan']
c=l.Controller(sys.argv[2],sys.argv[3],p,lambda:100);c.recover()
a,b=l.FakeNode(),l.FakeNode(); info=c.prepare('issue');a.accept(info);b.accept(info);c.observe_fake('issue',a,b)
c.hook=lambda s:os._exit(73) if s==sys.argv[4] else None
if sys.argv[4]=='branch:saved':c.choose(c.worker.terminal(p,'consume'))
else:c.prepare('terminal')
'''
                proc = subprocess.run([sys.executable, '-c', code, str(lab.ROOT / 'scripts'), str(root), str(authority), phase], capture_output=True)
                self.assertEqual(proc.returncode, 73, proc.stderr.decode())
                c = self.open(root=root, authority=authority)
                try:
                    c.recover(); self.assertEqual(c.status()['branch'], 'consume')
                    with self.assertRaises(lab.ModelError): c.choose(self.worker.terminal(self.issue, 'refund'))
                    if phase.startswith('terminal'):
                        with patch.object(c.worker, 'prepare', side_effect=AssertionError('must not sign')):
                            c.prepare('terminal')
                finally: c.close()
