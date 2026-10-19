#!/usr/bin/env python3
"""Local signed admission/retrieval lab over the synthetic recovery coordinator.

Conventional signing keys only; no content keys, encryption, RPC or transport.
This lab encoding is NOT an adopted R0 wire protocol. See its dedicated guide.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import secrets
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import release_coordinator_model as core

VERSION = 'icp-signed-coordinator-lab-v0'
MODE = 'LOCAL_SIGNED_COORDINATOR_SYNTHETIC_RESPONSES_NO_CHAIN'
DOMAIN = b'icp/signed-coordinator-lab/v0/'
MAX_WIRE = 32768
ModelError = core.ModelError


def require(condition, message):
    if not condition:
        raise ModelError(message)


def hexadecimal(value, size=32):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(size * 2) + '}', value), 'Invalid lowercase hex')
    return bytes.fromhex(value)


def public(key):
    return key.public_key().public_bytes_raw().hex()


def identify(purpose, body):
    return hashlib.sha256(DOMAIN + purpose.encode() + b'\0' + core.canonical(body)).hexdigest()


def sign(key, purpose, body):
    return key.sign(DOMAIN + purpose.encode() + b'\0' + core.canonical(body)).hex()


def verify(key, signature, purpose, body):
    try:
        Ed25519PublicKey.from_public_bytes(hexadecimal(key)).verify(
            hexadecimal(signature, 64), DOMAIN + purpose.encode() + b'\0' + core.canonical(body))
    except (InvalidSignature, ValueError) as exc:
        raise ModelError('Invalid purpose-bound signature') from exc


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'Unexpected lab fields')


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_WIRE, 'Wire must be bounded bytes')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    def constant(_):
        raise ModelError('Non-finite JSON value')
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        require(core.canonical(value) == raw, 'Canonical JSON bytes required')
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ModelError('Invalid canonical lab JSON') from exc


@dataclass(frozen=True, kw_only=True)
class SignedPolicy(core.Policy):
    approver: str
    sender: str
    recipient: str
    revoker: str
    service_signer: str
    recipient_label: str = 'model:recipient'
    binding_label: str = 'model:delivery-certificate'
    challenge_lifetime: int = 30
    challenge_limit: int = 16

    def __post_init__(self):
        super().__post_init__()
        keys = (self.approver, self.sender, self.recipient, self.revoker, self.service_signer)
        for key in keys:
            hexadecimal(key)
        require(len(set(keys)) == 5, 'Five distinct signing roles required')
        core.label(self.recipient_label); core.label(self.binding_label)
        require(0 < core.integer(self.challenge_lifetime) <= 60, 'Invalid challenge lifetime')
        require(0 < core.integer(self.challenge_limit) <= 64, 'Invalid challenge issuance limit')

    @property
    def id(self):
        return identify('policy', dict(version=VERSION, mode=MODE, **asdict(self)))


def header(policy):
    return dict(version=VERSION, mode=MODE, network='testnet-10-simulation', policy_id=policy.id,
                service=policy.service, budget=policy.budget)


def check_header(body, policy, extra):
    fields(body, set(header(policy)) | set(extra))
    require(all(body[name] == value for name, value in header(policy).items()), 'Lab namespace/policy mismatch')


def permission(policy, context, approver, sender):
    require(type(context) is core.Context, 'Exact synthetic Context required')
    require(public(approver) == policy.approver and public(sender) == policy.sender, 'Wrong permission roles')
    body = dict(header(policy), context=asdict(context), recipient_key=policy.recipient)
    return core.canonical(dict(body=body, approval=sign(approver, 'approve', body),
                               sender_signature=sign(sender, 'send', body)))


def check_permission(envelope, policy):
    fields(envelope, ('body', 'approval', 'sender_signature'))
    body = envelope['body']
    check_header(body, policy, ('context', 'recipient_key'))
    fields(body['context'], core.Context.__dataclass_fields__)
    try:
        context = core.Context(**body['context'])
    except TypeError as exc:
        raise ModelError('Invalid signed context') from exc
    require(body['recipient_key'] == policy.recipient and context.recipient == policy.recipient_label
            and context.binding == policy.binding_label, 'Unregistered recipient/binding label')
    verify(policy.approver, envelope['approval'], 'approve', body)
    verify(policy.sender, envelope['sender_signature'], 'send', body)
    return context, identify('permission', envelope)


CHALLENGE_FIELDS = ('purpose', 'grant', 'permission_hash', 'request', 'recipient_key', 'binding',
                    'policy_epoch', 'delivery_epoch', 'nonce', 'authority', 'generation',
                    'issued_at', 'expires_at', 'response_hash', 'admission_hash')


def check_challenge(envelope, policy, now=None):
    fields(envelope, ('body', 'signature'))
    body = envelope['body']
    check_header(body, policy, CHALLENGE_FIELDS)
    require(body['purpose'] in ('reserve', 'retrieve'), 'Unknown challenge purpose')
    for name in ('grant', 'request', 'binding', 'nonce', 'authority'):
        core.label(body[name])
    for name in ('policy_epoch', 'delivery_epoch', 'generation', 'issued_at', 'expires_at'):
        core.integer(body[name])
    hexadecimal(body['permission_hash'])
    require(body['recipient_key'] == policy.recipient and body['binding'] == policy.binding_label,
            'Challenge recipient/binding mismatch')
    require(0 < body['expires_at'] - body['issued_at'] <= policy.challenge_lifetime, 'Invalid challenge interval')
    if now is not None:
        require(body['issued_at'] <= core.integer(now) < body['expires_at'], 'Challenge expired or inactive')
    if body['purpose'] == 'reserve':
        require(body['response_hash'] is None and body['admission_hash'] is None, 'Reservation challenge has response fields')
    else:
        hexadecimal(body['response_hash']); hexadecimal(body['admission_hash'])
    verify(policy.service_signer, envelope['signature'], 'challenge/' + body['purpose'], body)
    return body


def answer(policy, permission_raw, challenge_raw, recipient, now, *, expected_response_hash=None):
    challenge = decode(challenge_raw)
    body = check_challenge(challenge, policy, now)
    context, permission_hash = check_permission(decode(permission_raw), policy)
    require(SignedCoordinator._matches(body, context, permission_hash), 'Challenge is not the intended permission')
    if body['purpose'] == 'retrieve':
        hexadecimal(expected_response_hash)
        require(body['response_hash'] == expected_response_hash, 'Unexpected response digest')
    else:
        require(expected_response_hash is None, 'Reservation must not name a response')
    require(public(recipient) == policy.recipient, 'Wrong recipient identity key')
    return core.canonical(dict(challenge=challenge, signature=sign(recipient, 'request/' + body['purpose'], challenge)))


def check_answer(envelope, policy, now=None):
    fields(envelope, ('challenge', 'signature'))
    body = check_challenge(envelope['challenge'], policy, now)
    verify(policy.recipient, envelope['signature'], 'request/' + body['purpose'], envelope['challenge'])
    return body


def revocation(policy, permission_raw, revoker, sequence, issued_at, expires_at, nonce):
    envelope = decode(permission_raw)
    context, permission_hash = check_permission(envelope, policy)
    require(public(revoker) == policy.revoker, 'Wrong revocation role')
    body = dict(header(policy), action='revoke-grant', grant=context.grant,
                permission_hash=permission_hash, sequence=sequence, issued_at=issued_at,
                expires_at=expires_at, nonce=nonce)
    return core.canonical(dict(body=body, signature=sign(revoker, 'revocation', body)))


def check_revocation(envelope, policy):
    fields(envelope, ('body', 'signature'))
    body = envelope['body']
    check_header(body, policy, ('action', 'grant', 'permission_hash', 'sequence', 'issued_at', 'expires_at', 'nonce'))
    require(body['action'] == 'revoke-grant', 'Wrong revocation action')
    core.label(body['grant']); core.label(body['nonce']); hexadecimal(body['permission_hash'])
    for name in ('sequence', 'issued_at', 'expires_at'):
        core.integer(body[name])
    require(body['sequence'] > 0 and 0 < body['expires_at'] - body['issued_at'] <= 60, 'Invalid revocation sequence/lifetime')
    verify(policy.revoker, envelope['signature'], 'revocation', body)
    return body


class SignedCoordinator(core.Coordinator):
    """Local signed entry points; protected Python members are not host isolation."""
    def __init__(self, root, authority_path, policy, clock, service_key, **kwargs):
        require(type(policy) is SignedPolicy and public(service_key) == policy.service_signer,
                'Pinned signed policy and matching service key required')
        self._service_key = service_key
        super().__init__(root, authority_path, policy, clock, **kwargs)

    def _admission(self, row):
        evidence = row['signed_admission']
        fields(evidence, ('permission', 'request', 'accepted_at'))
        context, permission_hash = check_permission(evidence['permission'], self.policy)
        proof = check_answer(evidence['request'], self.policy, evidence['accepted_at'])
        request_hash = identify('admission-request', evidence['request'])
        expected = dict(service=self.policy.service, budget=self.policy.budget, **asdict(context),
                        permission_hash=permission_hash, admission_hash=request_hash)
        require(core.canonical(row['context']) == core.canonical(expected) and row['context_hash'] == core.digest(expected), 'Stored signed context mismatch')
        require(proof['purpose'] == 'reserve' and self._matches(proof, context, permission_hash), 'Stored admission proof mismatch')
        return context, permission_hash, request_hash

    @staticmethod
    def _matches(body, context, permission_hash):
        return all(body[name] == value for name, value in dict(grant=context.grant,
            permission_hash=permission_hash, request=context.request, binding=context.binding,
            policy_epoch=context.policy_epoch, delivery_epoch=context.delivery_epoch).items())

    def _load(self, lease, reconcile=False):
        loaded = super()._load(lease, reconcile)
        try:
            ledger, delivery = loaded['ledger'][0], loaded['delivery'][0]
            sequences = set()
            for row in ledger['grants'].values():
                self._admission(row)
                proof = row['signed_admission']['request']['challenge']
                nonce = proof['body']['nonce']
                require(proof['body']['authority'] == self._authority.id
                        and 0 < proof['body']['generation'] <= self.generation
                        and core.canonical(ledger.get('signed_challenges', {}).get(nonce)) == core.canonical(proof)
                        and nonce in ledger.get('signed_used', []), 'Stored admission challenge claim missing')
                if row['revoked']:
                    saved = row['signed_revocation']
                    body = check_revocation(saved['envelope'], self.policy)
                    require(body['grant'] == row['context']['grant'] and body['permission_hash'] == row['context']['permission_hash']
                            and body['issued_at'] <= core.integer(saved['accepted_at']) < body['expires_at']
                            and ledger.get('signed_revocations', {}).get(body['nonce']) == saved['envelope']
                            and body['sequence'] not in sequences, 'Stored revocation mismatch')
                    sequences.add(body['sequence'])
            require(sequences == set(range(1, ledger['revocations'] + 1))
                    and len(ledger.get('signed_revocations', {})) == ledger['revocations'], 'Revocation history gap')
            for nonce, saved in delivery['nonces'].items():
                evidence = saved['signed_request']
                body = check_answer(evidence['request'], self.policy, evidence['accepted_at'])
                row = ledger['grants'][body['grant']]
                context, permission_hash, admission_hash = self._admission(row)
                require(body['purpose'] == 'retrieve' and self._matches(body, context, permission_hash)
                        and body['nonce'] == nonce and body['authority'] == self._authority.id
                        and body['generation'] == saved['generation'] and 0 < saved['generation'] <= self.generation
                        and body['admission_hash'] == admission_hash
                        and body['response_hash'] == row['response_hash'] == saved['response_hash']
                        and body['grant'] == saved['grant'] and body['request'] == saved['request']
                        and core.canonical(delivery.get('signed_challenges', {}).get(nonce)) == core.canonical(evidence['request']['challenge']),
                        'Stored retrieval evidence mismatch')
        except (ModelError, KeyError, TypeError) as exc:
            raise core.IntegrityError('Stored signed authorization integrity failure') from exc
        return loaded

    def challenge(self, permission_raw, purpose):
        envelope = decode(permission_raw)
        context, permission_hash = check_permission(envelope, self.policy)
        require(purpose in ('reserve', 'retrieve'), 'Unknown challenge purpose')
        with self._step() as (lease, loaded):
            ledger = loaded['ledger'][0]
            old = ledger['grants'].get(context.grant)
            if old and old['context']['permission_hash'] != permission_hash:
                raise core.IntegrityError('Conflicting signed permission for stable operation')
            if purpose == 'reserve':
                require(old is None, 'Already reserved; reconcile saved grant instead')
                row = dict(context=asdict(context), revoked=False)
                role = 'ledger'
                response_hash = admission_hash = None
            else:
                require(old is not None and old['response'] is not None, 'Committed signed grant required')
                row, role = old, 'delivery'
                response_hash, admission_hash = row['response_hash'], row['context']['admission_hash']
            self._eligible(lease, ledger, row, chain=purpose == 'retrieve')
            challenges = loaded[role][0].setdefault('signed_challenges', {})
            require(sum(item['body']['grant'] == context.grant for item in challenges.values()) < self.policy.challenge_limit,
                    'Challenge issuance limit reached for grant/purpose')
            body = dict(header(self.policy), purpose=purpose, grant=context.grant,
                        permission_hash=permission_hash, request=context.request, recipient_key=self.policy.recipient,
                        binding=context.binding, policy_epoch=context.policy_epoch, delivery_epoch=context.delivery_epoch,
                        nonce='model:challenge-' + secrets.token_hex(16), authority=self._authority.id,
                        generation=self.generation, issued_at=lease.now,
                        expires_at=min(lease.now + self.policy.challenge_lifetime, context.expires, context.window_end),
                        response_hash=response_hash, admission_hash=admission_hash)
            challenge = dict(body=body, signature=sign(self._service_key, 'challenge/' + purpose, body))
            challenges[body['nonce']] = challenge
            self._save(lease, loaded, role, 'signed-challenge/' + purpose)
        self.hook('challenge:acknowledged')
        return core.canonical(challenge)

    def _fresh_answer(self, envelope, purpose, lease, loaded):
        body = check_answer(envelope, self.policy, lease.now)
        require(body['purpose'] == purpose and body['authority'] == self._authority.id
                and body['generation'] == self.generation, 'Wrong purpose, deployment or writer generation')
        role = 'ledger' if purpose == 'reserve' else 'delivery'
        saved = loaded[role][0].get('signed_challenges', {}).get(body['nonce'])
        require(core.canonical(saved) == core.canonical(envelope['challenge']), 'Unissued or changed challenge')
        used = loaded['ledger'][0].get('signed_used', []) if purpose == 'reserve' else loaded['delivery'][0]['nonces']
        require(body['nonce'] not in used, 'Signed request already consumed')
        return body

    def reserve(self, permission_raw, request_raw):
        envelope, request = decode(permission_raw), decode(request_raw)
        context, permission_hash = check_permission(envelope, self.policy)
        with self._step() as (lease, loaded):
            body = self._fresh_answer(request, 'reserve', lease, loaded)
            require(self._matches(body, context, permission_hash), 'Request does not match exact permission')
            old = loaded['ledger'][0]['grants'].get(context.grant)
            if old and old['context']['permission_hash'] != permission_hash:
                raise core.IntegrityError('Conflicting signed permission for stable operation')
            require(old is None, 'Grant already reserved')
            loaded['ledger'][0].setdefault('signed_used', []).append(body['nonce'])
            request_hash = identify('admission-request', request)
            self._reserve_in_step(lease, loaded, context,
                extra_context=dict(permission_hash=permission_hash, admission_hash=request_hash),
                evidence=dict(permission=envelope, request=request, accepted_at=lease.now))
        self.hook('reserve:acknowledged')

    def dispatch(self, request_raw):
        request = decode(request_raw)
        with self._step() as (lease, loaded):
            body = self._fresh_answer(request, 'retrieve', lease, loaded)
            row = self._row(loaded, body['grant'])
            context, permission_hash, admission_hash = self._admission(row)
            require(self._matches(body, context, permission_hash) and body['admission_hash'] == admission_hash,
                    'Retrieval does not match original signed admission')
            response = self._dispatch_in_step(lease, loaded, context.grant, context.request,
                body['nonce'], body['response_hash'], evidence=dict(request=request, accepted_at=lease.now))
        self.hook('dispatch:acknowledged')
        return response

    def revoke(self, revocation_raw):
        envelope = decode(revocation_raw)
        body = check_revocation(envelope, self.policy)
        with self._step() as (lease, loaded):
            ledger = loaded['ledger'][0]
            row = self._row(loaded, body['grant'])
            require(body['permission_hash'] == row['context']['permission_hash'], 'Revocation permission mismatch')
            if row['revoked']:
                require(core.canonical(row['signed_revocation']['envelope']) == core.canonical(envelope), 'Conflicting revocation retry')
                return  # Exact saved evidence may reconcile after its signing deadline.
            require(body['issued_at'] <= lease.now < body['expires_at'], 'Revocation expired or inactive')
            require(body['sequence'] == ledger['revocations'] + 1, 'Revocation sequence must be exact next value')
            nonces = ledger.setdefault('signed_revocations', {})
            require(body['nonce'] not in nonces, 'Revocation nonce already claimed')
            nonces[body['nonce']] = envelope
            row['signed_revocation'] = dict(envelope=envelope, accepted_at=lease.now)
            self._revoke_in_step(lease, loaded, body['grant'])
        self.hook('revoke:acknowledged')


def demo():
    keys = [Ed25519PrivateKey.generate() for _ in range(5)]
    policy = SignedPolicy(**dict(zip(('approver', 'sender', 'recipient', 'revoker', 'service_signer'), map(public, keys))))
    context = core.Context()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        model = SignedCoordinator(root / 'components', root / 'authority.sqlite', policy, lambda: 100, keys[4], create=True)
        model.recover()
        grant = permission(policy, context, keys[0], keys[1])
        request = answer(policy, grant, model.challenge(grant, 'reserve'), keys[2], 100)
        model.reserve(grant, request); model.observe(context.grant)
        model.authorize(context.grant); model.prepare(context.grant); model.commit(context.grant)
        response_hash = model.status(context.grant)['response_hash']
        retrieval = answer(policy, grant, model.challenge(grant, 'retrieve'), keys[2], 100, expected_response_hash=response_hash)
        first = model.dispatch(retrieval)
        second = model.dispatch(answer(policy, grant, model.challenge(grant, 'retrieve'), keys[2], 100, expected_response_hash=response_hash))
        revoked = revocation(policy, grant, keys[3], 1, 100, 130, 'model:revocation-1')
        model.revoke(revoked)
        result = dict(mode=MODE, policy=asdict(policy), permission=decode(grant), admission_request=decode(request),
                      retrieval_request=decode(retrieval), revocation=decode(revoked),
                      identical_retry=first == second, status=model.status(context.grant),
                      content_keys=0, rpc_calls=0, broadcasts=0)
        model.close()
        return result


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2, sort_keys=True))
