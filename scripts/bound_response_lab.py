#!/usr/bin/env python3
"""Delivery-key possession and durable response signatures over dummy responses.

HPKE encrypts a random enrollment challenge only. No record/content key, RPC,
transport or native transaction exists here. This is a separate lab protocol.
"""
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import release_coordinator_model as core
import signed_coordinator_lab as signed

VERSION = 'icp-bound-response-lab-v0'
MODE = 'LOCAL_DELIVERY_BINDING_ATTESTATION_SYNTHETIC_NO_CHAIN'
DOMAIN = b'icp/bound-response-lab/v0/'
SUITE_NAME = 'HPKE-BASE-X25519-HKDF-SHA256-AES256GCM'
SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
require, fields, decode = signed.require, signed.fields, signed.decode


def identify(purpose, body):
    return hashlib.sha256(DOMAIN + purpose.encode() + b'\0' + core.canonical(body)).hexdigest()


def sign(key, purpose, body):
    return key.sign(DOMAIN + purpose.encode() + b'\0' + core.canonical(body)).hex()


def verify(key, signature, purpose, body):
    try:
        signed.Ed25519PublicKey.from_public_bytes(signed.hexadecimal(key)).verify(
            signed.hexadecimal(signature, 64), DOMAIN + purpose.encode() + b'\0' + core.canonical(body))
    except (signed.InvalidSignature, ValueError) as exc:
        raise core.ModelError('Invalid bound-lab signature') from exc


def key_label(service, budget, recipient, delivery_key, epoch):
    return 'model:x25519-' + identify('delivery-pin', dict(service=service, budget=budget,
        recipient=recipient, delivery_key=delivery_key, delivery_epoch=epoch, suite=SUITE_NAME))


@dataclass(frozen=True)
class DeliveryConfig:
    policy: signed.SignedPolicy
    delivery_key: str
    delivery_epoch: int = 0

    def __post_init__(self):
        require(type(self.policy) is signed.SignedPolicy, 'Exact signed policy required')
        signed.hexadecimal(self.delivery_key); core.integer(self.delivery_epoch)
        require(self.delivery_key not in (self.policy.approver, self.policy.sender, self.policy.recipient,
                self.policy.revoker, self.policy.service_signer), 'Distinct encryption and signing keys required')
        require(self.policy.binding_label == key_label(self.policy.service, self.policy.budget,
                self.policy.recipient, self.delivery_key, self.delivery_epoch), 'Encryption key not committed by policy')
        try:
            SUITE.encrypt(b'', X25519PublicKey.from_public_bytes(bytes.fromhex(self.delivery_key)),
                          info=DOMAIN + b'key-validation\0' + core.canonical(asdict(self)))
        except ValueError as exc:
            raise core.ModelError('Invalid delivery public key') from exc

    @property
    def id(self):
        return identify('config', asdict(self))


def header(config):
    return dict(version=VERSION, mode=MODE, network='testnet-10-simulation', config_id=config.id,
                policy_id=config.policy.id, service=config.policy.service, budget=config.policy.budget)


def check_header(body, config, extra):
    fields(body, set(header(config)) | set(extra))
    require(all(body[name] == value for name, value in header(config).items()), 'Bound-lab namespace/config mismatch')


def info(context):
    return DOMAIN + b'possession-challenge\0' + core.canonical(context)


def token_hash(context, token):
    return hashlib.sha256(DOMAIN + b'possession-token\0' + core.canonical(context) + token).hexdigest()


def check_challenge(envelope, config, now=None):
    fields(envelope, ('body', 'signature'))
    body = envelope['body']
    check_header(body, config, ('nonce', 'authority', 'generation', 'issued_at', 'expires_at',
                              'recipient', 'delivery_key', 'delivery_epoch', 'suite', 'encrypted_token'))
    for name in ('nonce', 'authority'): core.label(body[name])
    for name in ('generation', 'issued_at', 'expires_at', 'delivery_epoch'): core.integer(body[name])
    require(body['recipient'] == config.policy.recipient and body['delivery_key'] == config.delivery_key
            and body['delivery_epoch'] == config.delivery_epoch and body['suite'] == SUITE_NAME, 'Delivery binding mismatch')
    require(0 < body['expires_at'] - body['issued_at'] <= config.policy.challenge_lifetime, 'Invalid enrollment lifetime')
    if now is not None:
        require(body['issued_at'] <= core.integer(now) < body['expires_at'], 'Enrollment challenge expired or inactive')
    signed.hexadecimal(body['encrypted_token'], 80)
    verify(config.policy.service_signer, envelope['signature'], 'binding-challenge', body)
    return {name: value for name, value in body.items() if name != 'encrypted_token'}


def prove_binding(config, challenge_raw, identity_key, delivery_key, now):
    envelope = decode(challenge_raw)
    context = check_challenge(envelope, config, now)
    require(signed.public(identity_key) == config.policy.recipient
            and delivery_key.public_key().public_bytes_raw().hex() == config.delivery_key, 'Wrong identity or encryption key')
    try:
        token = SUITE.decrypt(bytes.fromhex(envelope['body']['encrypted_token']), delivery_key, info=info(context))
    except (InvalidTag, ValueError) as exc:
        raise core.ModelError('Delivery challenge could not be decrypted') from exc
    require(len(token) == 32, 'Invalid challenge token length')
    body = dict(header(config), nonce=context['nonce'], challenge_hash=identify('binding-challenge', envelope),
                token_hash=token_hash(context, token))
    return core.canonical(dict(body=body, signature=sign(identity_key, 'binding-proof', body)))


def check_proof(envelope, config):
    fields(envelope, ('body', 'signature'))
    body = envelope['body']
    check_header(body, config, ('nonce', 'challenge_hash', 'token_hash'))
    core.label(body['nonce']); signed.hexadecimal(body['challenge_hash']); signed.hexadecimal(body['token_hash'])
    verify(config.policy.recipient, envelope['signature'], 'binding-proof', body)
    return body


def approve_binding(config, challenge_raw, proof_raw, approver, now):
    challenge, proof = decode(challenge_raw), decode(proof_raw)
    context = check_challenge(challenge, config, now)
    body = check_proof(proof, config)
    require(body['nonce'] == context['nonce'] and body['challenge_hash'] == identify('binding-challenge', challenge),
            'Approval proof/challenge mismatch')
    require(signed.public(approver) == config.policy.approver, 'Wrong binding approver')
    return core.canonical(dict(proof=proof, signature=sign(approver, 'binding-approval', proof)))


def check_approval(envelope, config):
    fields(envelope, ('proof', 'signature'))
    body = check_proof(envelope['proof'], config)
    verify(config.policy.approver, envelope['signature'], 'binding-approval', envelope['proof'])
    return body


def verify_binding(registration, config, now):
    fields(registration, ('certificate', 'approval', 'challenge'))
    certificate, approval, challenge = (registration[name] for name in ('certificate', 'approval', 'challenge'))
    fields(certificate, ('body', 'signature'))
    body = certificate['body']
    check_header(body, config, ('nonce', 'approval_hash', 'registered_at', 'authority', 'generation'))
    registered = core.integer(body['registered_at'])
    require(registered <= core.integer(now), 'Binding certificate from the future')
    context = check_challenge(challenge, config, registered)
    proof = check_approval(approval, config)
    require(body['nonce'] == context['nonce'] == proof['nonce'] and body['authority'] == context['authority']
            and body['generation'] == context['generation'] and core.integer(body['generation']) > 0
            and proof['challenge_hash'] == identify('binding-challenge', challenge)
            and body['approval_hash'] == identify('binding-approval', approval), 'Binding evidence mismatch')
    verify(config.policy.service_signer, certificate['signature'], 'binding-certificate', body)
    return identify('registered-binding', registration)


def record_body(config, context, response_hash, binding_hash, *, authority, generation, prepared_at, checkpoint):
    return dict(header(config), operation=[config.policy.service, config.policy.budget, context['grant']],
                context_hash=core.digest(context), permission_hash=context['permission_hash'],
                admission_hash=context['admission_hash'], response_hash=response_hash, binding_hash=binding_hash,
                delivery_key=config.delivery_key, delivery_epoch=config.delivery_epoch, suite=SUITE_NAME,
                policy_epoch=context['policy_epoch'], not_before=context['not_before'],
                deadline=min(context['expires'], context['window_end']), authority=authority,
                prepared_generation=generation, prepared_at=prepared_at, ledger_checkpoint=checkpoint)


def verify_record(envelope, config, context, response_hash, registration, now):
    fields(envelope, ('body', 'signature'))
    body = envelope['body']
    require(type(body) is dict, 'Invalid response record')
    for name in ('prepared_at', 'prepared_generation'): core.integer(body.get(name))
    core.label(body.get('authority')); signed.hexadecimal(body.get('ledger_checkpoint'))
    require(body['prepared_generation'] > 0 and body['prepared_at'] <= core.integer(now)
            and context['not_before'] <= body['prepared_at'] < min(context['expires'], context['window_end']),
            'Invalid original preparation time')
    binding_hash = verify_binding(registration, config, body['prepared_at'])
    certificate = registration['certificate']['body']
    require(body['authority'] == certificate['authority']
            and body['prepared_generation'] >= certificate['generation'], 'Response/binding deployment mismatch')
    expected = record_body(config, context, response_hash, binding_hash, authority=body['authority'],
                           generation=body['prepared_generation'], prepared_at=body['prepared_at'],
                           checkpoint=body['ledger_checkpoint'])
    require(body == expected, 'Signed response record/context mismatch')
    verify(config.policy.service_signer, envelope['signature'], 'response-record', body)
    return identify('response-record', envelope)


def verify_response(config, permission_raw, admission_raw, bundle_raw, now):
    permission, admission, bundle = decode(permission_raw), decode(admission_raw), decode(bundle_raw)
    context, permission_hash = signed.check_permission(permission, config.policy)
    proof = signed.check_answer(admission, config.policy)
    require(proof['purpose'] == 'reserve' and signed.SignedCoordinator._matches(proof, context, permission_hash),
            'Response does not match the intended admission')
    fields(bundle, ('response', 'context', 'binding', 'record'))
    expected = dict(service=config.policy.service, budget=config.policy.budget, **asdict(context),
                    permission_hash=permission_hash, admission_hash=signed.identify('admission-request', admission))
    require(bundle['context'] == expected and context.binding == config.policy.binding_label
            and context.delivery_epoch == config.delivery_epoch, 'Response approved context mismatch')
    response = bundle['response']
    fields(response, ('mode', 'operation', 'context', 'placeholder'))
    require(response['mode'] == core.MODE and response['operation'] == [config.policy.service, config.policy.budget, context.grant]
            and response['context'] == core.digest(expected), 'Synthetic response binding mismatch')
    signed.hexadecimal(response['placeholder'], 16)
    verified = verify_record(bundle['record'], config, expected, core.digest(response), bundle['binding'], now)
    body = bundle['record']['body']
    require(proof['authority'] == body['authority'] and proof['generation'] <= body['prepared_generation'],
            'Response/admission deployment mismatch')
    return verified



class BoundCoordinator(signed.SignedCoordinator):
    """One pinned encryption key, with registration and attestations checkpointed."""
    def __init__(self, root, authority_path, config, clock, service_key, **kwargs):
        require(type(config) is DeliveryConfig, 'Exact delivery configuration required')
        self.config = config
        super().__init__(root, authority_path, config.policy, clock, service_key, **kwargs)

    def _load(self, lease, reconcile=False):
        loaded = super()._load(lease, reconcile)
        ledger, vault = loaded['ledger'][0], loaded['vault'][0]
        try:
            registration = ledger.get('registered_binding')
            if registration is None:
                require(not ledger['grants'] and not vault['candidates'], 'Grants exist without verified delivery binding')
            else:
                verify_binding(registration, self.config, lease.now)
                body = registration['certificate']['body']
                saved = ledger['binding_challenges'][body['nonce']]
                proof = registration['approval']['proof']['body']
                require(body['authority'] == self._authority.id and body['generation'] <= self.generation
                        and saved['used'] and saved['challenge'] == registration['challenge']
                        and hmac.compare_digest(saved['expected'], proof['token_hash']), 'Lost or inconsistent binding claim')
            for grant, candidate in vault['candidates'].items():
                row = ledger['grants'][grant]
                verify_record(candidate['response_record'], self.config, row['context'], candidate['response_hash'], registration, lease.now)
                record = candidate['response_record']['body']
                require(record['authority'] == self._authority.id and record['prepared_generation'] <= self.generation
                        and record['ledger_checkpoint'] == candidate['ledger_checkpoint'], 'Response record authority/checkpoint mismatch')
                if row['response'] is not None:
                    require(row['response_record'] == candidate['response_record'], 'Committed response record differs from vault')
        except (core.ModelError, KeyError, TypeError) as exc:
            raise core.IntegrityError('Binding/response record integrity failure') from exc
        return loaded

    def _eligible(self, lease, ledger, row, chain=True):
        require(ledger.get('registered_binding') is not None, 'Verified encryption-key binding required')
        require(row['context']['binding'] == self.policy.binding_label
                and row['context']['delivery_epoch'] == self.config.delivery_epoch
                and ledger['delivery_epoch'] == self.config.delivery_epoch, 'Inactive delivery-key epoch')
        super()._eligible(lease, ledger, row, chain)

    def binding_challenge(self):
        with self._step() as (lease, loaded):
            ledger = loaded['ledger'][0]
            require(ledger.get('registered_binding') is None, 'Delivery key already registered')
            require(ledger['delivery_epoch'] == self.config.delivery_epoch, 'Inactive enrollment epoch')
            challenges = ledger.setdefault('binding_challenges', {})
            require(len(challenges) < self.policy.challenge_limit, 'Enrollment challenge limit reached')
            context = dict(header(self.config), nonce='model:binding-' + secrets.token_hex(16),
                           authority=self._authority.id, generation=self.generation, issued_at=lease.now,
                           expires_at=core.integer(lease.now + self.policy.challenge_lifetime), recipient=self.policy.recipient,
                           delivery_key=self.config.delivery_key, delivery_epoch=self.config.delivery_epoch, suite=SUITE_NAME)
            token = secrets.token_bytes(32)
            body = dict(context, encrypted_token=SUITE.encrypt(token, X25519PublicKey.from_public_bytes(
                bytes.fromhex(self.config.delivery_key)), info=info(context)).hex())
            envelope = dict(body=body, signature=sign(self._service_key, 'binding-challenge', body))
            challenges[context['nonce']] = dict(challenge=envelope, expected=token_hash(context, token), used=False)
            self._save(lease, loaded, 'ledger', 'binding-challenge')
        self.hook('binding-challenge:acknowledged')
        return core.canonical(envelope)

    def register_binding(self, approval_raw):
        approval = decode(approval_raw)
        proof = check_approval(approval, self.config)
        with self._step() as (lease, loaded):
            ledger = loaded['ledger'][0]
            require(ledger.get('registered_binding') is None, 'Delivery key already registered')
            saved = ledger.get('binding_challenges', {}).get(proof['nonce'])
            require(saved is not None and not saved['used'], 'Unknown or replayed enrollment challenge')
            context = check_challenge(saved['challenge'], self.config, lease.now)
            require(context['authority'] == self._authority.id and context['generation'] == self.generation
                    and ledger['delivery_epoch'] == self.config.delivery_epoch, 'Stale enrollment generation/epoch')
            require(proof['challenge_hash'] == identify('binding-challenge', saved['challenge'])
                    and hmac.compare_digest(proof['token_hash'], saved['expected']), 'Delivery-key possession rejected')
            body = dict(header(self.config), nonce=proof['nonce'], approval_hash=identify('binding-approval', approval),
                        registered_at=lease.now, authority=self._authority.id, generation=self.generation)
            registration = dict(certificate=dict(body=body, signature=sign(self._service_key, 'binding-certificate', body)),
                                approval=approval, challenge=saved['challenge'])
            ledger['registered_binding'] = registration
            saved['used'] = True
            self._save(lease, loaded, 'ledger', 'binding-registered')
        self.hook('binding:acknowledged')
        return core.canonical(registration)

    def get_binding(self):
        with self._step() as (_, loaded):
            registration = loaded['ledger'][0].get('registered_binding')
            return core.canonical(registration) if registration else None

    def _make_candidate(self, lease, loaded, row):
        candidate = super()._make_candidate(lease, loaded, row)
        binding_hash = verify_binding(loaded['ledger'][0]['registered_binding'], self.config, lease.now)
        body = record_body(self.config, row['context'], candidate['response_hash'], binding_hash,
                           authority=self._authority.id, generation=self.generation, prepared_at=lease.now,
                           checkpoint=candidate['ledger_checkpoint'])
        candidate['response_record'] = dict(body=body, signature=sign(self._service_key, 'response-record', body))
        return candidate

    def _commit_candidate(self, row, candidate):
        super()._commit_candidate(row, candidate)
        row['response_record'] = candidate['response_record']

    def _dispatch_in_step(self, lease, loaded, grant, request, nonce, response_hash, *, evidence=None):
        response = super()._dispatch_in_step(lease, loaded, grant, request, nonce, response_hash, evidence=evidence)
        row = self._row(loaded, grant)
        return core.canonical(dict(response=decode(response), context=row['context'], record=row['response_record'],
                                   binding=loaded['ledger'][0]['registered_binding']))


def demo():
    keys = [signed.Ed25519PrivateKey.generate() for _ in range(5)]
    delivery = X25519PrivateKey.generate()
    delivery_public = delivery.public_key().public_bytes_raw().hex()
    roles = dict(zip(('approver', 'sender', 'recipient', 'revoker', 'service_signer'), map(signed.public, keys)))
    policy = signed.SignedPolicy(**roles, binding_label=key_label('model:service', 'model:budget', roles['recipient'], delivery_public, 0))
    config = DeliveryConfig(policy, delivery_public)
    context = core.Context(binding=policy.binding_label)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        model = BoundCoordinator(root / 'components', root / 'authority.sqlite', config, lambda: 100, keys[4], create=True)
        model.recover()
        challenge = model.binding_challenge()
        proof = prove_binding(config, challenge, keys[2], delivery, 100)
        registration = model.register_binding(approve_binding(config, challenge, proof, keys[0], 100))
        permission = signed.permission(policy, context, keys[0], keys[1])
        admission = signed.answer(policy, permission, model.challenge(permission, 'reserve'), keys[2], 100)
        model.reserve(permission, admission); model.observe(context.grant)
        model.authorize(context.grant); model.prepare(context.grant); model.commit(context.grant)
        response_hash = model.status(context.grant)['response_hash']
        def retrieve():
            return model.dispatch(signed.answer(policy, permission, model.challenge(permission, 'retrieve'),
                                  keys[2], 100, expected_response_hash=response_hash))
        first, second = retrieve(), retrieve()
        verified = verify_response(config, permission, admission, first, 100)
        result = dict(mode=MODE, config=asdict(config), permission=decode(permission), admission=decode(admission),
                      registration=decode(registration), bundle=decode(first),
                      verified_record=verified, identical_retry=first == second, status=model.status(context.grant),
                      content_keys=0, rpc_calls=0, broadcasts=0)
        model.close()
        return result


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2, sort_keys=True))
