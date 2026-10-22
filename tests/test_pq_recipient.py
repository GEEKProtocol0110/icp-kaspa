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
import pq_recipient_adapter as app
import recipient_adapter as legacy_adapter
import recipient_lab as legacy
from dataclasses import replace
import hashlib
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey


class PQAdapterTests(unittest.TestCase):
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
        return subprocess.run([sys.executable, str(ROOT / 'scripts/pq_recipient_adapter.py'),
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
        with self.assertRaises(app.lab.TransferError): app.load_policy(self.policy_file, '00' * 48)

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
        with patch('pq_recipient_adapter.time.time', return_value=106), self.assertRaises(app.lab.TransferError): app.run(args)
        self.assertEqual(self.r.receive(self.policy, self.raw(), 106)[0], self.plaintext)

    def test_export_failure_preserves_acceptance_and_recoverable_receipt(self):
        raw = self.root / 'envelope.json'
        app.write_new(raw, self.raw())
        args = app.parser().parse_args(['receive', '--endpoint', str(self.r.path), '--policy', str(self.policy_file),
            '--policy-id', self.policy.id, '--input', str(raw), '--output', str(self.root / 'output.bin'),
            '--receipt', str(self.root / 'receipt.json')])
        with patch('pq_recipient_adapter.time.time', return_value=106), \
             patch('pq_recipient_adapter.write_new', side_effect=OSError('simulated export failure')):
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
        spec = importlib.util.spec_from_file_location('recipient_file_exchange', ROOT / 'examples/pq_recipient_file_exchange.py')
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)
        result = demo.demo()
        self.assertTrue(result['recipient_bytes_match'])
        self.assertTrue(result['replay_rejected'])
        self.assertFalse(result['private_keys_exchanged'])
        self.assertTrue(result['network_delivery_tested'])
        self.assertEqual(result['network_scope'], 'LOOPBACK_SINGLE_HOST')


class PQCryptographicProfileTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PQAdapterTests()
        self.fixture.setUp()
        self.f = self.fixture
        self.lab = app.lab

    def tearDown(self):
        self.fixture.tearDown()

    def decrypt_with(self, delivery, envelope=None):
        envelope = self.f.envelope if envelope is None else envelope
        context = {key: value for key, value in envelope['manifest'].items() if key != 'ciphertext_hash'}
        return self.lab.SUITE.decrypt(bytes.fromhex(envelope['ciphertext']), delivery.hpke_key(),
                                     info=self.lab.info('message', context))

    def test_library_verifies_full_manifest_with_mldsa_context(self):
        envelope = self.f.envelope
        self.f.s.identity.public_key().verify(bytes.fromhex(envelope['sender_signature']),
            self.lab.canonical(envelope['manifest']), context=(self.lab.DOMAIN + 'send').encode())
        self.assertEqual(len(bytes.fromhex(envelope['sender_signature'])), 3309)

    def test_hybrid_key_and_signing_seed_roundtrip(self):
        restored = self.lab.DeliveryPrivateKey.from_private_bytes(self.f.r.delivery.private_bytes_raw())
        self.assertEqual(self.decrypt_with(restored), self.f.plaintext)
        self.assertEqual(len(restored.private_bytes_raw()), 96)
        self.assertEqual(len(restored.public_key().public_bytes_raw()), 1216)
        self.assertEqual(len(bytes.fromhex(self.f.policy.recipient)), 1952)
        signer = self.lab.SigningPrivateKey.from_seed_bytes(self.f.s.identity.private_bytes_raw())
        self.assertEqual(self.lab.public(signer), self.f.policy.sender)

    def test_classical_component_alone_is_insufficient(self):
        other = self.lab.DeliveryPrivateKey.generate()
        mixed = self.lab.DeliveryPrivateKey(other.mlkem, self.f.r.delivery.classical)
        with self.assertRaises(InvalidTag): self.decrypt_with(mixed)

    def test_mlkem_component_alone_is_insufficient(self):
        other = self.lab.DeliveryPrivateKey.generate()
        mixed = self.lab.DeliveryPrivateKey(self.f.r.delivery.mlkem, other.classical)
        with self.assertRaises(InvalidTag): self.decrypt_with(mixed)

    def test_fresh_encapsulation_for_identical_plaintext(self):
        other = self.f.exchange()
        self.assertNotEqual(self.f.envelope['ciphertext'][:2240], other['ciphertext'][:2240])
        self.assertEqual(self.decrypt_with(self.f.r.delivery, other), self.f.plaintext)

    def test_low_order_classical_delivery_component_rejected(self):
        raw = self.f.r.delivery.public_key().public_bytes_raw()
        for classical in (bytes(32), b'\x01' + bytes(31)):
            with self.assertRaises(ValueError): replace(self.f.policy, delivery_key=(raw[:1184] + classical).hex())

    def test_malformed_mlkem_public_component_rejected(self):
        raw = self.f.r.delivery.public_key().public_bytes_raw()
        with self.assertRaises(ValueError): replace(self.f.policy, delivery_key=(b'\xff' * 1184 + raw[1184:]).hex())

    def test_legacy_signer_and_signature_rejected(self):
        key = legacy.Ed25519PrivateKey.generate()
        with self.assertRaises(ValueError): self.lab.signature(key, 'send', self.f.envelope['manifest'])
        with self.assertRaises(ValueError):
            self.lab.verify_signature(self.f.policy.sender, key.sign(b'fictional').hex(), 'send', self.f.envelope['manifest'])

    def test_mldsa_wrong_parameter_set_rejected(self):
        key = MLDSA44PrivateKey.generate()
        with self.assertRaises(ValueError): self.lab.signature(key, 'send', self.f.envelope['manifest'])
        with self.assertRaises(ValueError):
            self.lab.verify_signature(key.public_key().public_bytes_raw().hex(), key.sign(b'fictional').hex(),
                                      'send', self.f.envelope['manifest'])

    def test_signature_purpose_is_bound(self):
        body = self.f.envelope['manifest']
        sig = self.lab.signature(self.f.s.identity, 'send', body)
        self.lab.verify_signature(self.f.policy.sender, sig, 'send', body)
        with self.assertRaises(ValueError): self.lab.verify_signature(self.f.policy.sender, sig, 'approve', body)

    def test_signature_missing_or_truncated_rejected(self):
        for field in ('approval', 'sender_signature'):
            for value in (None, '00' * 64, self.f.envelope[field][:-2]):
                envelope = dict(self.f.envelope, **{field: value})
                with self.assertRaises(ValueError): self.lab.verify_envelope(envelope, self.f.policy, 106)

    def test_certificate_from_another_policy_rejected(self):
        other = app.Endpoint.create(self.f.root / 'other-recipient', 'recipient')
        policy = app.make_policy(self.f.a.public(), self.f.s.public(), other.public())
        with self.assertRaises(ValueError): self.lab.verify_binding(self.f.binding, policy, 106)

    def test_resigned_metadata_cannot_repair_encryption_context(self):
        envelope = copy.deepcopy(self.f.envelope)
        envelope['manifest']['record_version'] += 1
        envelope = self.f.s.send(self.f.policy, self.f.a.approve(self.f.policy, envelope, 105), 105)
        with self.assertRaises(ValueError): self.f.r.receive(self.f.policy, self.lab.canonical(envelope), 106)

    def test_resigned_ciphertext_mutation_still_fails_aead(self):
        envelope = copy.deepcopy(self.f.envelope)
        raw = bytearray.fromhex(envelope['ciphertext']); raw[-1] ^= 1
        envelope['ciphertext'] = raw.hex()
        envelope['manifest']['ciphertext_hash'] = hashlib.sha384(raw).hexdigest()
        envelope = self.f.s.send(self.f.policy, self.f.a.approve(self.f.policy, envelope, 105), 105)
        with self.assertRaises(ValueError): self.f.r.receive(self.f.policy, self.lab.canonical(envelope), 106)

    def test_bad_possession_token_does_not_consume_good_proof(self):
        registry = self.lab.BindingRegistry(self.f.root / 'other-binding.sqlite', self.f.policy)
        try:
            challenge = registry.challenge(110)
            good = self.f.r.answer(self.f.policy, challenge, 111)
            bad = copy.deepcopy(good); bad['body']['token_hash'] = '00' * 48
            bad['signature'] = self.lab.signature(self.f.r.identity, 'binding-proof', bad['body'])
            with self.assertRaises(ValueError): registry.register(bad, self.f.a.identity, 112)
            binding = registry.register(good, self.f.a.identity, 112)
            self.lab.verify_binding(binding, self.f.policy, 113)
        finally:
            registry.close()

    def test_database_rejects_legacy_profile_in_both_directions(self):
        keys = [legacy.Ed25519PrivateKey.generate() for _ in range(3)]
        delivery = legacy.X25519PrivateKey.generate()
        old_policy = legacy.DeliveryPolicy(*(legacy.public(k) for k in keys), legacy.key_public(delivery))
        path = self.f.root / 'legacy.sqlite'
        legacy.BindingRegistry(path, old_policy).close()
        with self.assertRaises(ValueError): self.lab.BindingRegistry(path, self.f.policy)
        pq_path = self.f.root / 'new-pq.sqlite'
        self.lab.BindingRegistry(pq_path, self.f.policy).close()
        with self.assertRaises(ValueError): legacy.BindingRegistry(pq_path, old_policy)

    def test_endpoint_formats_do_not_migrate_implicitly(self):
        with self.assertRaises(ValueError): legacy_adapter.Endpoint(self.f.r.path)
        old = legacy_adapter.Endpoint.create(self.f.root / 'legacy-endpoint', 'recipient')
        with self.assertRaises(ValueError): app.Endpoint(old.path)

    def test_legacy_envelope_is_not_accepted_as_pq(self):
        old = legacy.demo()
        with self.assertRaises(ValueError): self.lab.verify_envelope(old['envelope'], self.f.policy, 106)
        with self.assertRaises(ValueError): legacy.verify_envelope(self.f.envelope, self.f.policy, 106)

    def test_unsupported_hybrid_backend_has_no_fallback(self):
        with patch.object(self.lab, 'SUITE') as suite:
            suite.encrypt.side_effect = self.lab.UnsupportedAlgorithm('unavailable')
            with self.assertRaises(self.lab.UnsupportedAlgorithm):
                self.f.s.seal(self.f.policy, self.f.binding, self.f.plaintext, 105)
            self.assertEqual(suite.encrypt.call_count, 1)

    def test_signature_algorithm_is_in_pinned_policy(self):
        changed = self.f.root / 'downgraded.json'
        app.write_json(changed, dict(self.f.policy.body(), suite=legacy.SUITE_NAME))
        with self.assertRaises(ValueError): app.load_policy(changed, self.f.policy.id)

    def test_max_payload_accounts_for_larger_public_keys_and_signatures(self):
        envelope = self.f.exchange(b'\xff' * 65536)
        raw = self.lab.canonical(envelope)
        self.assertGreater(len(raw), legacy.MAX_WIRE)
        self.assertLessEqual(len(raw), self.lab.MAX_WIRE)
        with self.assertRaises(ValueError): legacy.decode(raw)
        self.assertEqual(self.f.r.receive(self.f.policy, raw, 106)[0], b'\xff' * 65536)


if __name__ == '__main__':
    unittest.main()



