"""File integration boundaries; fictional bytes, temporary keys and no RPC."""
import concurrent.futures
import copy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import recipient_adapter as app


class RecipientAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.a, self.s, self.r = (app.Endpoint.create(self.root / role, role) for role in app.ROLES)
        self.policy = app.make_policy(self.a.public(), self.s.public(), self.r.public())
        self.policy_file = self.root / 'policy.json'
        app.write_json(self.policy_file, self.policy.body())
        proof = self.r.answer(self.policy, self.a.challenge(self.policy, 100), 101)
        self.binding = self.a.bind(self.policy, proof, 102)
        self.plaintext = b'FICTIONAL\x00binary\xffpayload'
        self.envelope = self.exchange()

    def tearDown(self):
        self.tmp.cleanup()

    def exchange(self, plaintext=None):
        return self.s.send(self.policy, self.a.approve(self.policy, self.s.seal(
            self.policy, self.binding, self.plaintext if plaintext is None else plaintext, 103), 104), 105)

    def raw(self):
        return app.lab.canonical(self.envelope)

    def cli(self, *arguments):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/recipient_adapter.py'),
                               *map(str, arguments)], capture_output=True, timeout=15)

    def test_binary_handoff_and_saved_receipt(self):
        received, receipt = self.r.receive(self.policy, self.raw(), 106)
        self.assertEqual(received, self.plaintext)
        self.assertTrue(app.lab.verify_receipt(receipt, self.envelope, self.policy))
        reopened = app.Endpoint(self.root / 'recipient')
        self.assertEqual(reopened.receipt(self.policy, self.envelope['manifest']['transfer_id']), receipt)

    def test_only_recipient_endpoint_has_delivery_private_key(self):
        for endpoint in (self.a, self.s):
            self.assertIsNone(endpoint.delivery)
            self.assertNotIn('delivery_private', app.read_json(endpoint.path / 'keys.json'))
        self.assertNotIn(self.r.delivery.private_bytes_raw().hex(), self.raw().decode())
        self.assertNotIn('private', app.lab.canonical(self.r.public()).decode())

    def test_policy_requires_explicit_matching_pin(self):
        self.assertEqual(app.load_policy(self.policy_file, self.policy.id), self.policy)
        with self.assertRaises(app.lab.TransferError): app.load_policy(self.policy_file, '00' * 32)

    def test_policy_rejects_suite_or_namespace_substitution(self):
        for field, value in [('suite', 'other'), ('network', 'mainnet'), ('version', 'R0'), ('extra', 1)]:
            changed = self.root / f'{field}.json'
            app.write_json(changed, dict(self.policy.body(), **{field: value}))
            with self.assertRaises(app.lab.TransferError): app.load_policy(changed, self.policy.id)

    def test_public_role_substitution_rejected(self):
        with self.assertRaises(app.lab.TransferError):
            app.make_policy(self.s.public(), self.a.public(), self.r.public())

    def test_duplicate_policy_roles_rejected(self):
        sender = dict(self.s.public(), signing_key=self.a.public()['signing_key'])
        with self.assertRaises(app.lab.TransferError): app.make_policy(self.a.public(), sender, self.r.public())

    def test_wrong_role_cannot_approve_send_or_receive(self):
        for call in (lambda: self.s.approve(self.policy, self.envelope, 106),
                     lambda: self.a.send(self.policy, self.envelope, 106),
                     lambda: self.s.receive(self.policy, self.raw(), 106)):
            with self.assertRaises(app.lab.TransferError): call()

    def test_other_recipient_keys_rejected(self):
        other = app.Endpoint.create(self.root / 'other', 'recipient')
        with self.assertRaises(app.lab.TransferError): other.receive(self.policy, self.raw(), 106)

    def test_ciphertext_tamper_creates_no_receipt(self):
        changed = copy.deepcopy(self.envelope)
        changed['ciphertext'] = ('00' if changed['ciphertext'][:2] != '00' else '01') + changed['ciphertext'][2:]
        with self.assertRaises(app.lab.TransferError):
            self.r.receive(self.policy, app.lab.canonical(changed), 106)
        with self.assertRaises(app.lab.TransferError):
            self.r.receipt(self.policy, self.envelope['manifest']['transfer_id'])

    def test_replay_rejected_after_endpoint_restart(self):
        self.r.receive(self.policy, self.raw(), 106)
        with self.assertRaises(app.lab.TransferError):
            app.Endpoint(self.r.path).receive(self.policy, self.raw(), 107)

    def test_concurrent_acceptance_claims_one_receipt(self):
        def accept(_):
            try:
                app.Endpoint(self.r.path).receive(self.policy, self.raw(), 106)
                return True
            except app.lab.TransferError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(accept, range(2))), [False, True])

    def test_expired_message_rejected(self):
        with self.assertRaises(app.lab.TransferError): self.r.receive(self.policy, self.raw(), 403)

    def test_size_limit_accepts_exact_boundary_and_rejects_more(self):
        envelope = self.exchange(b'x' * self.policy.max_bytes)
        self.assertEqual(len(self.r.receive(self.policy, app.lab.canonical(envelope), 106)[0]), self.policy.max_bytes)
        with self.assertRaises(app.lab.TransferError): self.exchange(b'x' * (self.policy.max_bytes + 1))

    def test_empty_payload_rejected(self):
        with self.assertRaises(app.lab.TransferError): self.exchange(b'')

    def test_recover_binding_without_new_enrollment(self):
        self.assertEqual(app.Endpoint(self.a.path).binding(self.policy), self.binding)
        with self.assertRaises(app.lab.TransferError): self.a.challenge(self.policy, 106)

    def test_keygen_never_overwrites_existing_endpoint(self):
        original = (self.r.path / 'keys.json').read_bytes()
        with self.assertRaises(FileExistsError): app.Endpoint.create(self.r.path, 'recipient')
        self.assertEqual((self.r.path / 'keys.json').read_bytes(), original)

    def test_private_key_permissions_required(self):
        path = self.r.path / 'keys.json'
        path.chmod(0o644)
        with self.assertRaises(app.lab.TransferError): app.Endpoint(self.r.path)

    def test_private_directory_permissions_required(self):
        self.r.path.chmod(0o755)
        with self.assertRaises(app.lab.TransferError): app.Endpoint(self.r.path)

    def test_symlink_endpoint_and_keys_rejected(self):
        link = self.root / 'linked-endpoint'
        link.symlink_to(self.r.path, target_is_directory=True)
        with self.assertRaises(app.lab.TransferError): app.Endpoint(link)
        keys = self.r.path / 'keys.json'
        keys.rename(self.r.path / 'saved.json')
        keys.symlink_to('saved.json')
        with self.assertRaises(OSError): app.Endpoint(self.r.path)

    def test_symlink_state_rejected_without_changing_target(self):
        target = self.root / 'do-not-change'
        target.write_bytes(b'untouched')
        (self.r.path / f'received-{self.policy.id}.sqlite').symlink_to(target)
        with self.assertRaises(OSError): self.r.receive(self.policy, self.raw(), 106)
        self.assertEqual(target.read_bytes(), b'untouched')

    def test_insecure_existing_database_rejected(self):
        path = self.r._state(self.policy, 'received')
        path.chmod(0o644)
        with self.assertRaises(app.lab.TransferError): self.r.receive(self.policy, self.raw(), 106)

    def test_bounded_input_rejects_fifo_symlink_oversize_and_duplicate_json(self):
        big = self.root / 'big'
        big.write_bytes(b'x' * 20)
        with self.assertRaises(app.lab.TransferError): app.read_bytes(big, 19)
        link = self.root / 'link'
        link.symlink_to(big)
        with self.assertRaises(OSError): app.read_bytes(link, 20)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(app.lab.TransferError): app.read_bytes(fifo, 20)
        duplicate = self.root / 'duplicate.json'
        duplicate.write_bytes(b'{"x":1,"x":2}')
        with self.assertRaises(app.lab.TransferError): app.read_json(duplicate)

    def test_atomic_output_is_private_and_no_clobber(self):
        path = self.root / 'output'
        app.write_new(path, b'first')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError): app.write_new(path, b'second')
        self.assertEqual(path.read_bytes(), b'first')
        self.assertEqual(list(self.root.glob('.icp-write-*')), [])

    def test_atomic_output_never_follows_destination_symlink(self):
        target, link = self.root / 'target', self.root / 'output-link'
        target.write_bytes(b'first')
        link.symlink_to(target)
        with self.assertRaises(FileExistsError): app.write_new(link, b'second')
        self.assertEqual(target.read_bytes(), b'first')

    def test_cli_failure_does_not_print_private_input(self):
        (self.r.path / 'keys.json').write_text('PRIVATE-CANARY-DO-NOT-LOG')
        result = self.cli('receipt', '--endpoint', self.r.path, '--policy', self.policy_file,
                          '--policy-id', self.policy.id, '--transfer-id', self.envelope['manifest']['transfer_id'],
                          '--output', self.root / 'receipt.json')
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b'PRIVATE-CANARY', result.stdout + result.stderr)
        self.assertEqual(result.stdout, b'')

    def test_output_conflict_does_not_claim_recipient_message(self):
        output, raw = self.root / 'output.bin', self.root / 'envelope.json'
        app.write_new(output, b'existing')
        app.write_new(raw, self.raw())
        args = app.parser().parse_args(['receive', '--endpoint', str(self.r.path), '--policy', str(self.policy_file),
            '--policy-id', self.policy.id, '--input', str(raw), '--output', str(output),
            '--receipt', str(self.root / 'receipt.json')])
        with patch('recipient_adapter.time.time', return_value=106), self.assertRaises(app.lab.TransferError): app.run(args)
        self.assertEqual(self.r.receive(self.policy, self.raw(), 106)[0], self.plaintext)

    def test_export_failure_preserves_acceptance_and_recoverable_receipt(self):
        raw = self.root / 'envelope.json'
        app.write_new(raw, self.raw())
        args = app.parser().parse_args(['receive', '--endpoint', str(self.r.path), '--policy', str(self.policy_file),
            '--policy-id', self.policy.id, '--input', str(raw), '--output', str(self.root / 'output.bin'),
            '--receipt', str(self.root / 'receipt.json')])
        with patch('recipient_adapter.time.time', return_value=106), \
             patch('recipient_adapter.write_new', side_effect=OSError('simulated export failure')):
            with self.assertRaises(OSError): app.run(args)
        receipt = self.r.receipt(self.policy, self.envelope['manifest']['transfer_id'])
        self.assertTrue(app.lab.verify_receipt(receipt, self.envelope, self.policy))
        with self.assertRaises(app.lab.TransferError): self.r.receive(self.policy, self.raw(), 107)
        self.assertFalse((self.root / 'output.bin').exists())

    def test_tampered_receipt_fails_verification(self):
        _, receipt = self.r.receive(self.policy, self.raw(), 106)
        receipt['body']['accepted_at'] += 1
        with self.assertRaises(app.lab.TransferError): app.lab.verify_receipt(receipt, self.envelope, self.policy)

    def test_separate_process_file_demo(self):
        spec = importlib.util.spec_from_file_location('recipient_file_exchange', ROOT / 'examples/recipient_file_exchange.py')
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)
        result = demo.demo()
        self.assertTrue(result['recipient_bytes_match'])
        self.assertTrue(result['replay_rejected'])
        self.assertFalse(result['private_keys_exchanged'])
        self.assertTrue(result['network_delivery_tested'])
        self.assertEqual(result['network_scope'], 'LOOPBACK_SINGLE_HOST')


if __name__ == '__main__':
    unittest.main()
