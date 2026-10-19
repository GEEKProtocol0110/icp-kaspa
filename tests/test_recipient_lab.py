"""Fictional data only; no real agency, chain or protected release service."""
import concurrent.futures
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import recipient_lab as lab
from recipient_lab import (BindingRegistry, DeliveryPolicy, Ed25519PrivateKey, InvalidTag,
                           Recipient, SUITE, TransferError, X25519PrivateKey, answer_challenge,
                           approve, canonical, decode, demo, identify, info, key_public, public,
                           receipt_body, seal, sign_send, signature, verify_binding,
                           verify_envelope, verify_receipt)


class RecipientLabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.delivery = X25519PrivateKey.generate()
        self.policy = DeliveryPolicy(*(public(key) for key in self.keys), key_public(self.delivery))
        self.registry = BindingRegistry(self.root / 'binding.sqlite', self.policy)
        self.challenge = self.registry.challenge(100)
        self.proof = answer_challenge(self.challenge, self.policy, self.keys[2], self.delivery, 101)
        self.binding = self.registry.register(self.proof, self.keys[0], 102)
        self.plaintext = b'FICTIONAL MESSAGE. Not an agency record.'
        self.envelope = self.exchange(self.plaintext)
        self.recipient = self.open_recipient()

    def tearDown(self):
        self.registry.close(); self.recipient.close(); self.tmp.cleanup()

    def open_recipient(self, path=None):
        return Recipient(path or self.root / 'recipient.sqlite', self.policy, self.keys[2], self.delivery)

    def exchange(self, plaintext):
        return self.sign(seal(self.policy, self.binding, plaintext, 103, 200))

    def sign(self, envelope):
        return sign_send(approve(envelope, self.policy, self.keys[0], 104), self.policy, self.keys[1], 105)

    def raw(self, envelope=None):
        return canonical(self.envelope if envelope is None else envelope)

    def decrypt_direct(self, envelope, key=None):
        context = {k: v for k, v in envelope['manifest'].items() if k != 'ciphertext_hash'}
        return SUITE.decrypt(bytes.fromhex(envelope['ciphertext']), key or self.delivery,
                             info=info('message', context))

    def test_intended_recipient_decrypts_and_receipt_verifies(self):
        plaintext, receipt = self.recipient.receive(self.raw(), 106)
        self.assertEqual(plaintext, self.plaintext)
        self.assertTrue(verify_receipt(receipt, self.envelope, self.policy))
        self.assertEqual(self.recipient.get_receipt(self.envelope['manifest']['transfer_id']), receipt)

    def test_no_raw_content_key_returned_by_seal(self):
        envelope = seal(self.policy, self.binding, self.plaintext, 103, 200)
        self.assertEqual(set(envelope), {'manifest', 'ciphertext', 'binding'})
        self.assertNotIn(self.plaintext, canonical(envelope))

    def test_wrong_delivery_private_key_cannot_decrypt(self):
        with self.assertRaises(InvalidTag): self.decrypt_direct(self.envelope, X25519PrivateKey.generate())

    def test_recipient_requires_both_correct_key_roles(self):
        for identity, delivery in ((self.keys[1], self.delivery), (self.keys[2], X25519PrivateKey.generate())):
            with self.assertRaises(TransferError):
                Recipient(self.root / 'wrong.sqlite', self.policy, identity, delivery)

    def test_signing_bytes_must_not_be_reused_as_delivery_key(self):
        with self.assertRaisesRegex(TransferError, 'Distinct'):
            replace(self.policy, delivery_key=self.policy.recipient)

    def test_invalid_low_order_delivery_keys_are_rejected(self):
        for key in ('00' * 32, '01' + '00' * 31):
            with self.subTest(key=key), self.assertRaisesRegex(TransferError, 'Invalid delivery'):
                replace(self.policy, delivery_key=key)

    def test_fresh_encryption_changes_encapsulation_and_transfer_id(self):
        other = self.exchange(self.plaintext)
        self.assertNotEqual(self.envelope['ciphertext'], other['ciphertext'])
        self.assertNotEqual(self.envelope['ciphertext'][:64], other['ciphertext'][:64])
        self.assertNotEqual(self.envelope['manifest']['transfer_id'], other['manifest']['transfer_id'])
        self.assertEqual(self.decrypt_direct(other), self.plaintext)

    def test_challenge_does_not_publish_expected_token_hash(self):
        self.assertNotIn('token_hash', self.challenge)
        self.assertNotIn(self.proof['body']['token_hash'], canonical(self.challenge).decode())

    def test_binding_challenge_requires_identity_and_delivery_keys(self):
        with self.assertRaises(TransferError):
            answer_challenge(self.challenge, self.policy, self.keys[2], X25519PrivateKey.generate(), 101)
        with self.assertRaises(TransferError):
            answer_challenge(self.challenge, self.policy, self.keys[1], self.delivery, 101)

    def test_modified_encrypted_challenge_is_rejected(self):
        challenge = copy.deepcopy(self.challenge)
        encrypted = bytearray.fromhex(challenge['encrypted_token']); encrypted[-1] ^= 1
        challenge['encrypted_token'] = encrypted.hex()
        with self.assertRaises(TransferError):
            answer_challenge(challenge, self.policy, self.keys[2], self.delivery, 101)

    def test_replayed_possession_proof_rejected_after_restart(self):
        self.registry.close(); self.registry = BindingRegistry(self.root / 'binding.sqlite', self.policy)
        self.assertEqual(self.registry.get_binding(), self.binding)
        with self.assertRaisesRegex(TransferError, 'replayed'):
            self.registry.register(self.proof, self.keys[0], 103)

    def pending(self, name='other-binding.sqlite'):
        registry = BindingRegistry(self.root / name, self.policy)
        self.addCleanup(registry.close)
        challenge = registry.challenge(100)
        proof = answer_challenge(challenge, self.policy, self.keys[2], self.delivery, 101)
        return registry, challenge, proof

    def test_forged_challenge_response_does_not_consume_enrollment(self):
        registry, _, proof = self.pending()
        self.assertIsNone(registry.get_binding())
        bad = copy.deepcopy(proof); bad['body']['token_hash'] = '00' * 32
        bad['signature'] = signature(self.keys[2], 'binding-proof', bad['body'])
        with self.assertRaisesRegex(TransferError, 'possession'): registry.register(bad, self.keys[0], 102)
        self.assertTrue(verify_binding(registry.register(proof, self.keys[0], 102), self.policy, 103))

    def test_recipient_signature_cannot_replace_approver_binding(self):
        certificate = copy.deepcopy(self.binding)
        certificate['signature'] = signature(self.keys[2], 'binding-certificate', certificate['body'])
        with self.assertRaises(TransferError): verify_binding(certificate, self.policy, 103)
        registry, _, proof = self.pending()
        with self.assertRaises(TransferError): registry.register(proof, self.keys[1], 102)

    def test_binding_proof_domain_cannot_be_replaced_by_receipt_domain(self):
        registry, _, proof = self.pending()
        bad = copy.deepcopy(proof)
        bad['signature'] = signature(self.keys[2], 'receipt', bad['body'])
        with self.assertRaises(TransferError): registry.register(bad, self.keys[0], 102)
        self.assertTrue(verify_binding(registry.register(proof, self.keys[0], 102), self.policy, 103))

    def test_expired_possession_challenge_rejected(self):
        registry, challenge, proof = self.pending()
        with self.assertRaises(TransferError):
            answer_challenge(challenge, self.policy, self.keys[2], self.delivery, 160)
        with self.assertRaises(TransferError): registry.register(proof, self.keys[0], 160)

    def test_enrollment_race_accepts_one_proof(self):
        registry = BindingRegistry(self.root / 'race.sqlite', self.policy)
        challenges = [registry.challenge(100) for _ in range(2)]
        registry.close()
        proofs = [answer_challenge(c, self.policy, self.keys[2], self.delivery, 101) for c in challenges]
        def register(proof):
            store = BindingRegistry(self.root / 'race.sqlite', self.policy)
            try:
                store.register(proof, self.keys[0], 102); return True
            except TransferError:
                return False
            finally:
                store.close()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(register, proofs)), [False, True])

    def test_enrollment_limit_bounds_challenge_growth(self):
        registry = BindingRegistry(self.root / 'bounded.sqlite', self.policy)
        try:
            for _ in range(16): registry.challenge(100)
            with self.assertRaisesRegex(TransferError, 'limit'): registry.challenge(100)
        finally:
            registry.close()

    def test_wrong_signature_domains_and_missing_approvals_rejected(self):
        for field, key, domain in (('approval', self.keys[0], 'send'),
                                   ('sender_signature', self.keys[1], 'approve'),
                                   ('approval', self.keys[1], 'approve')):
            envelope = copy.deepcopy(self.envelope)
            envelope[field] = signature(key, domain, envelope['manifest'])
            with self.assertRaises(TransferError): self.recipient.receive(self.raw(envelope), 106)
        envelope = copy.deepcopy(self.envelope); del envelope['approval']
        with self.assertRaises(TransferError): self.recipient.receive(self.raw(envelope), 106)

    def test_unauthenticated_input_rejected_before_decryption(self):
        envelope = copy.deepcopy(self.envelope); envelope['sender_signature'] = '00' * 64
        with patch('recipient_lab.SUITE') as crypto:
            with self.assertRaises(TransferError): self.recipient.receive(self.raw(envelope), 106)
            crypto.decrypt.assert_not_called()

    def test_ciphertext_tampering_and_rehashed_tampering_rejected(self):
        envelope = copy.deepcopy(self.envelope)
        ciphertext = bytearray.fromhex(envelope['ciphertext']); ciphertext[-1] ^= 1
        envelope['ciphertext'] = ciphertext.hex()
        with self.assertRaises(TransferError): self.recipient.receive(self.raw(envelope), 106)
        envelope['manifest']['ciphertext_hash'] = hashlib.sha256(ciphertext).hexdigest()
        envelope = self.sign(envelope)
        with self.assertRaisesRegex(TransferError, 'authentication'): self.recipient.receive(self.raw(envelope), 106)
        envelope['ciphertext'] = '00' * 32 + envelope['ciphertext'][64:]
        envelope['manifest']['ciphertext_hash'] = hashlib.sha256(bytes.fromhex(envelope['ciphertext'])).hexdigest()
        with self.assertRaisesRegex(TransferError, 'authentication'):
            self.recipient.receive(self.raw(self.sign(envelope)), 106)

    def test_re_signed_context_change_still_fails_hpke(self):
        for change in ({'record_version': 2}, {'record_id': '11' * 32}, {'expires_at': 199}):
            envelope = copy.deepcopy(self.envelope); envelope['manifest'].update(change)
            envelope = self.sign(envelope)
            with self.subTest(change=change), self.assertRaisesRegex(TransferError, 'authentication'):
                self.recipient.receive(self.raw(envelope), 106)

    def test_certificate_transplant_still_fails_encryption_context(self):
        registry, _, proof = self.pending()
        other = registry.register(proof, self.keys[0], 102)
        envelope = copy.deepcopy(self.envelope); envelope['binding'] = other
        envelope['manifest']['binding_id'] = identify('binding', other)
        envelope = self.sign(envelope)
        with self.assertRaisesRegex(TransferError, 'authentication'): self.recipient.receive(self.raw(envelope), 106)

    def test_network_epoch_and_delivery_key_substitutions_rejected(self):
        for change in ({'network': 'mainnet'}, {'delivery_epoch': 1},
                       {'delivery_key': key_public(X25519PrivateKey.generate())}, {'mode': 'release'}):
            envelope = copy.deepcopy(self.envelope); envelope['manifest'].update(change)
            with self.subTest(change=change), self.assertRaises(TransferError):
                self.recipient.receive(self.raw(envelope), 106)

    def test_future_binding_cannot_authorize_earlier_message(self):
        with self.assertRaises(TransferError): seal(self.policy, self.binding, self.plaintext, 101, 200)

    def test_message_time_boundaries(self):
        for now in (102, 200):
            with self.subTest(now=now), self.assertRaises(TransferError): self.recipient.receive(self.raw(), now)
        self.assertEqual(self.recipient.receive(self.raw(), 103)[0], self.plaintext)

    def test_size_limits_and_strict_integer_fields(self):
        for plaintext in (b'', b'x' * (lab.MAX_BYTES + 1)):
            with self.assertRaises(TransferError): seal(self.policy, self.binding, plaintext, 103, 200)
        envelope = self.exchange(b'x' * lab.MAX_BYTES)
        self.assertEqual(len(self.recipient.receive(self.raw(envelope), 106)[0]), lab.MAX_BYTES)
        for field in ('record_version', 'delivery_epoch', 'plaintext_bytes', 'issued_at'):
            envelope = copy.deepcopy(self.envelope); envelope['manifest'][field] = False
            with self.assertRaises(TransferError): self.recipient.receive(self.raw(envelope), 106)

    def test_wire_duplicate_fields_unknown_fields_and_oversize_rejected(self):
        for raw in (b'{"manifest":{},"manifest":{}}', b'[' * 1200, b'x' * (lab.MAX_WIRE + 1)):
            with self.assertRaises(TransferError): self.recipient.receive(raw, 106)
        envelope = copy.deepcopy(self.envelope); envelope['extra'] = 'not allowed'
        with self.assertRaises(TransferError): self.recipient.receive(self.raw(envelope), 106)
        envelope = copy.deepcopy(self.envelope); envelope['manifest']['extra'] = 1
        with self.assertRaises(TransferError): self.recipient.receive(self.raw(envelope), 106)

    def test_wrong_hex_lengths_and_noncanonical_hex_rejected(self):
        for value in (self.envelope['ciphertext'].upper(), '00', 'zz'):
            envelope = copy.deepcopy(self.envelope); envelope['ciphertext'] = value
            with self.assertRaises(TransferError): self.recipient.receive(self.raw(envelope), 106)

    def test_restart_preserves_receipt_and_rejects_replay(self):
        _, receipt = self.recipient.receive(self.raw(), 106)
        self.recipient.close(); self.recipient = self.open_recipient()
        with self.assertRaises(TransferError): self.recipient.receive(self.raw(), 107)
        self.assertEqual(self.recipient.get_receipt(self.envelope['manifest']['transfer_id']), receipt)

    def test_concurrent_recipient_connections_accept_once(self):
        def receive(_):
            recipient = self.open_recipient()
            try:
                recipient.receive(self.raw(), 106); return True
            except TransferError:
                return False
            finally:
                recipient.close()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(receive, range(2))), [False, True])

    def test_changed_policy_or_store_role_does_not_reset_history(self):
        for policy in (replace(self.policy, delivery_epoch=1), replace(self.policy, max_lifetime=301)):
            with self.assertRaisesRegex(TransferError, 'policy/role'):
                Recipient(self.root / 'recipient.sqlite', policy, self.keys[2], self.delivery)
        with self.assertRaisesRegex(TransferError, 'policy/role'):
            BindingRegistry(self.root / 'recipient.sqlite', self.policy)

    def test_independent_database_can_accept_again_scope_limit(self):
        self.recipient.receive(self.raw(), 106)
        other = self.open_recipient(self.root / 'independent.sqlite')
        try:
            self.assertEqual(other.receive(self.raw(), 106)[0], self.plaintext)
        finally:
            other.close()

    def test_receipt_is_recipient_claim_not_proof_of_decryption(self):
        body = receipt_body(self.envelope, self.policy, 106)
        forged_claim = dict(body=body, signature=signature(self.keys[2], 'receipt', body))
        # The identity-key holder can sign this without using the delivery key.
        self.assertTrue(verify_receipt(forged_claim, self.envelope, self.policy))

    def test_receipt_transplant_tampering_and_boolean_epoch_rejected(self):
        _, receipt = self.recipient.receive(self.raw(), 106)
        with self.assertRaises(TransferError): verify_receipt(receipt, self.exchange(b'Another fictional note'), self.policy)
        for change in ({'status': 'CHAIN_CONFIRMED'}, {'delivery_epoch': False}, {'extra': 1}):
            bad = copy.deepcopy(receipt); bad['body'].update(change)
            bad['signature'] = signature(self.keys[2], 'receipt', bad['body'])
            with self.assertRaises(TransferError): verify_receipt(bad, self.envelope, self.policy)

    def test_expiry_cannot_prevent_key_holder_decrypting_outside_api(self):
        with self.assertRaises(TransferError): self.recipient.receive(self.raw(), 300)
        self.assertEqual(self.decrypt_direct(self.envelope), self.plaintext)

    def test_later_delivery_key_compromise_exposes_recorded_messages(self):
        stolen_copy = X25519PrivateKey.from_private_bytes(self.delivery.private_bytes_raw())
        self.assertEqual(self.decrypt_direct(self.envelope, stolen_copy), self.plaintext)

    def test_demo_public_transcript_and_fixed_evidence(self):
        for result in (demo(), json.loads((Path(__file__).resolve().parents[1] / 'evidence/recipient-lab-demo.json').read_text())):
            self.assertEqual(result['mode'], lab.MODE)
            self.assertTrue(result['plaintext_match_local'] and result['wrong_delivery_key_rejected'])
            self.assertEqual(result['real_transactions'], 0)
            fields = {key: value for key, value in result['policy'].items()
                      if key not in ('version', 'mode', 'network', 'suite')}
            policy = DeliveryPolicy(**fields)
            self.assertTrue(verify_receipt(result['receipt'], result['envelope'], policy))
            self.assertNotIn(b'FICTIONAL DEMO ONLY:', canonical(result))


if __name__ == '__main__':
    unittest.main()
