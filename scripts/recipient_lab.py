#!/usr/bin/env python3
"""Local recipient-encryption experiment. No RPC, release service or R0 tickets.

HPKE encrypts to a distinct pinned X25519 delivery key. Ed25519 signatures
authenticate approval, sending, registration and receipt claims. Use fake data.
"""
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from transfer_lab import (Ed25519PrivateKey, TransferError, _signature, canonical,
                          decode as json_decode, digest, number, public, unhex)

VERSION = 'icp-recipient-lab-v0'
MODE = 'LOCAL_ONLY_RECIPIENT_ENCRYPTION_NO_CHAIN'
DOMAIN = 'icp/recipient-lab/v0/'
SUITE_NAME = 'HPKE-BASE-X25519-HKDF-SHA256-AES256GCM'
SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
MAX_BYTES = 65536
MAX_WIRE = 2 * MAX_BYTES + 8192


def require(value, message):
    if not value:
        raise TransferError(message)


def key_public(key):
    return key.public_key().public_bytes_raw().hex()


def identify(purpose, body):
    return digest(DOMAIN + purpose, body)


def signature(key, purpose, body):
    return key.sign((DOMAIN + purpose).encode() + b'\0' + bytes.fromhex(identify(purpose, body))).hex()


def verify_signature(key, sig, purpose, body):
    _signature(key, sig, DOMAIN + purpose, identify(purpose, body))


def header(policy):
    return dict(version=VERSION, mode=MODE, network='testnet-10', policy_id=policy.id)


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_WIRE, 'Wire size outside recipient-lab limit')
    return json_decode(raw)


def info(purpose, context):
    return (DOMAIN + purpose).encode() + b'\0' + canonical(context)


@dataclass(frozen=True)
class DeliveryPolicy:
    approver: str
    sender: str
    recipient: str
    delivery_key: str
    delivery_epoch: int = 0
    max_bytes: int = MAX_BYTES
    max_lifetime: int = 300

    def __post_init__(self):
        for key in (self.approver, self.sender, self.recipient, self.delivery_key):
            unhex(key, 32)
        require(len({self.approver, self.sender, self.recipient, self.delivery_key}) == 4,
                'Distinct signing roles and delivery key required')
        number(self.delivery_epoch)
        require(0 < number(self.max_bytes) <= MAX_BYTES and 0 < number(self.max_lifetime) <= 3600,
                'Invalid recipient-lab limits')
        try:
            SUITE.encrypt(b'', X25519PublicKey.from_public_bytes(unhex(self.delivery_key, 32)),
                          info=info('key-validation', asdict(self)))
        except ValueError as exc:
            raise TransferError('Invalid delivery public key') from exc

    def body(self):
        return dict(asdict(self), version=VERSION, mode=MODE, network='testnet-10', suite=SUITE_NAME)

    @property
    def id(self):
        return identify('policy', self.body())


def _open_db(path, policy, kind):
    db = sqlite3.connect(path, isolation_level=None, timeout=10)
    db.execute('PRAGMA synchronous=FULL')
    try:
        db.execute('CREATE TABLE IF NOT EXISTS recipient_lab_policy (id INTEGER PRIMARY KEY CHECK(id=1),policy TEXT,kind TEXT)')
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT policy,kind FROM recipient_lab_policy WHERE id=1').fetchone()
        require(row is None or row == (policy.id, kind), 'Recipient-lab database policy/role mismatch')
        if row is None:
            db.execute('INSERT INTO recipient_lab_policy VALUES(1,?,?)', (policy.id, kind))
        db.commit()
        return db
    except BaseException:
        db.rollback(); db.close(); raise


def _challenge(challenge, policy, now):
    fields = set(header(policy)) | {'challenge_id', 'issued_at', 'expires_at', 'encrypted_token'}
    require(type(challenge) is dict and set(challenge) == fields, 'Invalid binding challenge fields')
    require(all(challenge[key] == value for key, value in header(policy).items()), 'Binding challenge policy mismatch')
    unhex(challenge['challenge_id'], 32)
    start, end = number(challenge['issued_at']), number(challenge['expires_at'])
    require(0 < end - start <= 60 and start <= number(now) < end, 'Binding challenge expired or inactive')
    encrypted = unhex(challenge['encrypted_token'], 80)
    context = {key: value for key, value in challenge.items() if key != 'encrypted_token'}
    return context, encrypted


def answer_challenge(challenge, policy, identity_key, delivery_key, now):
    require(public(identity_key) == policy.recipient and key_public(delivery_key) == policy.delivery_key,
            'Wrong recipient signing or delivery key')
    context, encrypted = _challenge(challenge, policy, now)
    try:
        token = SUITE.decrypt(encrypted, delivery_key, info=info('binding-challenge', context))
    except (InvalidTag, ValueError) as exc:
        raise TransferError('Binding challenge decryption failed') from exc
    body = dict(header(policy), challenge_id=challenge['challenge_id'],
                challenge_hash=identify('challenge', challenge),
                token_hash=hashlib.sha256(info('binding-token', context) + token).hexdigest())
    return dict(body=body, signature=signature(identity_key, 'binding-proof', body))


class BindingRegistry:
    """Trusted local approver checks one-use encrypted possession challenges."""
    def __init__(self, path, policy):
        self.policy = policy
        self.db = _open_db(path, policy, 'binding-registry')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS binding_challenges (
            id TEXT PRIMARY KEY,body TEXT NOT NULL,token_hash TEXT NOT NULL,used INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS bound_delivery (id INTEGER PRIMARY KEY CHECK(id=1),certificate TEXT NOT NULL);''')

    def challenge(self, now):
        start = number(now)
        context = dict(header(self.policy), challenge_id=os.urandom(32).hex(), issued_at=start, expires_at=start + 60)
        number(context['expires_at'])
        token = os.urandom(32)
        encrypted = SUITE.encrypt(token, X25519PublicKey.from_public_bytes(unhex(self.policy.delivery_key, 32)),
                                  info=info('binding-challenge', context))
        body = dict(context, encrypted_token=encrypted.hex())
        self.db.execute('BEGIN IMMEDIATE')
        try:
            require(self.db.execute('SELECT COUNT(*) FROM binding_challenges').fetchone()[0] < 16,
                    'Local enrollment challenge limit reached')
            require(self.db.execute('SELECT 1 FROM bound_delivery').fetchone() is None, 'Delivery key already bound')
            self.db.execute('INSERT INTO binding_challenges(id,body,token_hash) VALUES(?,?,?)',
                            (context['challenge_id'], canonical(body).decode(),
                             hashlib.sha256(info('binding-token', context) + token).hexdigest()))
            self.db.commit()
        except BaseException:
            self.db.rollback(); raise
        return body

    def register(self, proof, approver_key, now):
        require(public(approver_key) == self.policy.approver, 'Wrong binding approver')
        require(type(proof) is dict and set(proof) == {'body', 'signature'} and type(proof['body']) is dict,
                'Invalid binding proof')
        body = proof['body']
        require(set(body) == set(header(self.policy)) | {'challenge_id', 'challenge_hash', 'token_hash'},
                'Invalid binding proof fields')
        for field in ('challenge_id', 'challenge_hash', 'token_hash'): unhex(body[field], 32)
        require(all(body[key] == value for key, value in header(self.policy).items()), 'Binding proof policy mismatch')
        verify_signature(self.policy.recipient, proof['signature'], 'binding-proof', body)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            saved = self.db.execute('SELECT body,token_hash,used FROM binding_challenges WHERE id=?',
                                    (body['challenge_id'],)).fetchone()
            require(saved is not None and not saved[2], 'Unknown or replayed binding challenge')
            challenge = json.loads(saved[0]); _challenge(challenge, self.policy, now)
            require(body['challenge_hash'] == identify('challenge', challenge)
                    and hmac.compare_digest(body['token_hash'], saved[1]), 'Delivery-key possession proof rejected')
            require(self.db.execute('SELECT 1 FROM bound_delivery').fetchone() is None, 'Delivery key already bound')
            cert_body = dict(header(self.policy), challenge_id=body['challenge_id'],
                             proof_hash=identify('binding-proof', proof), recipient=self.policy.recipient,
                             delivery_key=self.policy.delivery_key, delivery_epoch=self.policy.delivery_epoch,
                             suite=SUITE_NAME, registered_at=number(now))
            certificate = dict(body=cert_body, signature=signature(approver_key, 'binding-certificate', cert_body))
            self.db.execute('INSERT INTO bound_delivery VALUES(1,?)', (canonical(certificate).decode(),))
            self.db.execute('UPDATE binding_challenges SET used=1 WHERE id=?', (body['challenge_id'],))
            self.db.commit()
        except BaseException:
            self.db.rollback(); raise
        return certificate

    def get_binding(self):
        row = self.db.execute('SELECT certificate FROM bound_delivery WHERE id=1').fetchone()
        return json.loads(row[0]) if row else None

    def close(self):
        self.db.close()


def verify_binding(certificate, policy, now):
    require(type(certificate) is dict and set(certificate) == {'body', 'signature'}
            and type(certificate['body']) is dict, 'Invalid binding certificate')
    body = certificate['body']
    require(set(body) == set(header(policy)) | {'challenge_id', 'proof_hash', 'recipient', 'delivery_key',
            'delivery_epoch', 'suite', 'registered_at'}, 'Invalid binding certificate fields')
    for field in ('challenge_id', 'proof_hash'): unhex(body[field], 32)
    expected = dict(header(policy), recipient=policy.recipient, delivery_key=policy.delivery_key,
                    delivery_epoch=policy.delivery_epoch, suite=SUITE_NAME)
    require(all(body[key] == value for key, value in expected.items()), 'Delivery binding mismatch')
    number(body['delivery_epoch'])
    require(number(body['registered_at']) <= number(now), 'Binding certificate from the future')
    verify_signature(policy.approver, certificate['signature'], 'binding-certificate', body)
    return identify('binding', certificate)


def _material(envelope, policy):
    require(type(envelope) is dict and {'manifest', 'ciphertext', 'binding'} <= set(envelope)
            and not set(envelope) - {'manifest', 'ciphertext', 'binding', 'approval', 'sender_signature'},
            'Invalid recipient envelope fields')
    m = envelope['manifest']
    require(type(m) is dict and set(m) == set(header(policy)) | {
        'transfer_id', 'record_id', 'record_version', 'sender', 'recipient', 'delivery_key', 'delivery_epoch',
        'binding_id', 'issued_at', 'expires_at', 'plaintext_bytes', 'ciphertext_hash'}, 'Invalid recipient manifest')
    expected = dict(header(policy), sender=policy.sender, recipient=policy.recipient,
                    delivery_key=policy.delivery_key, delivery_epoch=policy.delivery_epoch)
    require(all(m[key] == value for key, value in expected.items()), 'Recipient policy or delivery binding mismatch')
    for field in ('transfer_id', 'record_id', 'binding_id', 'ciphertext_hash'): unhex(m[field], 32)
    number(m['record_version']); number(m['delivery_epoch'])
    start, end = number(m['issued_at']), number(m['expires_at'])
    require(0 < end - start <= policy.max_lifetime, 'Invalid message lifetime')
    size = number(m['plaintext_bytes'])
    require(0 < size <= policy.max_bytes, 'Message size outside policy')
    ciphertext = unhex(envelope['ciphertext'], size + 48)
    require(hashlib.sha256(ciphertext).hexdigest() == m['ciphertext_hash'], 'Ciphertext commitment mismatch')
    require(verify_binding(envelope['binding'], policy, start) == m['binding_id'], 'Certificate substitution rejected')
    return m, ciphertext


def _active(manifest, now):
    require(manifest['issued_at'] <= number(now) < manifest['expires_at'], 'Message permission inactive')


def seal(policy, binding, plaintext, issued_at, expires_at, record_id=None, record_version=1):
    require(type(plaintext) is bytes and 0 < len(plaintext) <= policy.max_bytes, 'Message size outside policy')
    context = dict(header(policy), transfer_id=os.urandom(32).hex(),
                   record_id=os.urandom(32).hex() if record_id is None else record_id,
                   record_version=number(record_version), sender=policy.sender, recipient=policy.recipient,
                   delivery_key=policy.delivery_key, delivery_epoch=policy.delivery_epoch,
                   binding_id=verify_binding(binding, policy, issued_at), issued_at=number(issued_at),
                   expires_at=number(expires_at), plaintext_bytes=len(plaintext))
    unhex(context['record_id'], 32)
    require(0 < context['expires_at'] - context['issued_at'] <= policy.max_lifetime, 'Invalid message lifetime')
    ciphertext = SUITE.encrypt(plaintext, X25519PublicKey.from_public_bytes(unhex(policy.delivery_key, 32)),
                              info=info('message', context))
    return dict(manifest=dict(context, ciphertext_hash=hashlib.sha256(ciphertext).hexdigest()),
                ciphertext=ciphertext.hex(), binding=binding)


def approve(envelope, policy, key, now):
    m, _ = _material(envelope, policy); _active(m, now)
    require(public(key) == policy.approver, 'Wrong message approver')
    return dict(envelope, approval=signature(key, 'approve', m))


def sign_send(envelope, policy, key, now):
    m, _ = _material(envelope, policy); _active(m, now)
    verify_signature(policy.approver, envelope.get('approval'), 'approve', m)
    require(public(key) == policy.sender, 'Wrong message sender')
    return dict(envelope, sender_signature=signature(key, 'send', m))


def verify_envelope(envelope, policy, now):
    m, ciphertext = _material(envelope, policy); _active(m, now)
    require(set(envelope) == {'manifest', 'ciphertext', 'binding', 'approval', 'sender_signature'}, 'Both message approvals required')
    verify_signature(policy.approver, envelope['approval'], 'approve', m)
    verify_signature(policy.sender, envelope['sender_signature'], 'send', m)
    return m, ciphertext


def receipt_body(envelope, policy, accepted_at):
    return dict(header(policy), transfer_id=envelope['manifest']['transfer_id'],
                envelope_id=identify('envelope', envelope), recipient=policy.recipient,
                delivery_epoch=policy.delivery_epoch, accepted_at=number(accepted_at),
                status='RECIPIENT_VERIFIED_LOCAL')


def verify_receipt(receipt, envelope, policy):
    require(type(receipt) is dict and set(receipt) == {'body', 'signature'} and type(receipt['body']) is dict,
            'Invalid recipient receipt')
    now = number(receipt['body'].get('accepted_at'))
    verify_envelope(envelope, policy, now)
    require(canonical(receipt['body']) == canonical(receipt_body(envelope, policy, now)),
            'Recipient receipt binding mismatch')
    verify_signature(policy.recipient, receipt['signature'], 'receipt', receipt['body'])
    return True


class Recipient:
    def __init__(self, path, policy, identity_key, delivery_key):
        require(public(identity_key) == policy.recipient and key_public(delivery_key) == policy.delivery_key,
                'Wrong recipient signing or delivery key')
        self.policy, self.identity_key, self.delivery_key = policy, identity_key, delivery_key
        self.db = _open_db(path, policy, 'recipient')
        self.db.execute('CREATE TABLE IF NOT EXISTS recipient_receipts (id TEXT PRIMARY KEY,receipt TEXT NOT NULL)')

    def receive(self, raw, now):
        envelope = decode(raw)
        m, ciphertext = verify_envelope(envelope, self.policy, now)
        context = {key: value for key, value in m.items() if key != 'ciphertext_hash'}
        try:
            plaintext = SUITE.decrypt(ciphertext, self.delivery_key, info=info('message', context))
        except (InvalidTag, ValueError) as exc:
            raise TransferError('Recipient payload authentication failed') from exc
        require(len(plaintext) == m['plaintext_bytes'], 'Plaintext size mismatch')
        body = receipt_body(envelope, self.policy, now)
        receipt = dict(body=body, signature=signature(self.identity_key, 'receipt', body))
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('INSERT INTO recipient_receipts VALUES(?,?)',
                            (m['transfer_id'], canonical(receipt).decode()))
            self.db.commit()
        except sqlite3.IntegrityError as exc:
            self.db.rollback(); raise TransferError('Message already accepted locally') from exc
        except BaseException:
            self.db.rollback(); raise
        return plaintext, receipt

    def get_receipt(self, transfer_id):
        unhex(transfer_id, 32)
        row = self.db.execute('SELECT receipt FROM recipient_receipts WHERE id=?', (transfer_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def close(self):
        self.db.close()


def demo():
    approver, sender, identity = (Ed25519PrivateKey.generate() for _ in range(3))
    delivery = X25519PrivateKey.generate()
    policy = DeliveryPolicy(public(approver), public(sender), public(identity), key_public(delivery))
    with tempfile.TemporaryDirectory() as folder:
        registry = BindingRegistry(Path(folder) / 'binding.sqlite', policy)
        challenge = registry.challenge(100)
        proof = answer_challenge(challenge, policy, identity, delivery, 101)
        binding = registry.register(proof, approver, 102)
        registry.close()
        plaintext = b'FICTIONAL DEMO ONLY: office A sends a synthetic case note to office B.'
        envelope = sign_send(approve(seal(policy, binding, plaintext, 103, 200), policy, approver, 104),
                             policy, sender, 105)
        recipient = Recipient(Path(folder) / 'recipient.sqlite', policy, identity, delivery)
        received, receipt = recipient.receive(canonical(envelope), 106)
        recipient.close()
        context = {key: value for key, value in envelope['manifest'].items() if key != 'ciphertext_hash'}
        try:
            SUITE.decrypt(bytes.fromhex(envelope['ciphertext']), X25519PrivateKey.generate(), info=info('message', context))
            raise AssertionError('Wrong delivery key unexpectedly decrypted')
        except InvalidTag:
            wrong_key_rejected = True
        require(received == plaintext and verify_receipt(receipt, envelope, policy), 'Integrated recipient demo failed')
        return dict(mode=MODE, scenario='Fictional offices; no agency integration', policy=policy.body(),
                    envelope=envelope, receipt=receipt, plaintext_match_local=True,
                    wrong_delivery_key_rejected=wrong_key_rejected, real_transactions=0)


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2, sort_keys=True))
