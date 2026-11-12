#!/usr/bin/env python3
"""File/bytes integration adapter for the existing recipient lab, not R0.

POSIX test endpoints own their keys. Only public records and encrypted envelopes
cross the file boundary. No RPC, wallet, remote key service or command execution.
"""
import argparse
from dataclasses import fields
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import time

import recipient_lab as lab

KEY_FORMAT = 'icp-recipient-endpoint-test-keys-v0'
PUBLIC_FORMAT = 'icp-recipient-endpoint-public-v0'
ROLES = ('approver', 'sender', 'recipient')


def read_bytes(path, limit, private=False):
    """Bound the read before JSON/crypto; reject symlinks and special files."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        lab.require(stat.S_ISREG(meta.st_mode), 'Input must be a regular file')
        if private:
            lab.require(meta.st_uid == os.getuid() and meta.st_mode & 0o077 == 0,
                        'Private file must be owner-only')
        lab.require(meta.st_size <= limit, 'Input exceeds adapter size limit')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        lab.require(len(raw) <= limit, 'Input exceeds adapter size limit')
        return raw
    finally:
        os.close(fd)


def read_json(path, limit=lab.MAX_WIRE, private=False):
    return lab.decode(read_bytes(path, min(limit, lab.MAX_WIRE), private))


def write_new(path, raw):
    """Publish a fully written 0600 file atomically, without replacing anything."""
    lab.require(type(raw) is bytes, 'Output must be bytes')
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.icp-write-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # Atomic no-clobber publication, including symlinks.
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def write_json(path, value):
    write_new(path, lab.canonical(value))


def private_directory(path):
    path = Path(path)
    meta = path.lstat()
    lab.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
                and meta.st_mode & 0o077 == 0, 'Endpoint directory must be owner-only, not a symlink')
    return path


def public_record(value, role):
    expected = {'format', 'role', 'signing_key'} | ({'delivery_key'} if role == 'recipient' else set())
    lab.require(type(value) is dict and set(value) == expected and value['format'] == PUBLIC_FORMAT
                and value['role'] == role, 'Invalid public role record')
    lab.unhex(value['signing_key'], 32)
    if role == 'recipient':
        lab.unhex(value['delivery_key'], 32)
    return value


def make_policy(approver, sender, recipient):
    """Caller must authenticate these public records and distribute the ID pin."""
    a, s, r = (public_record(value, role) for value, role in
               ((approver, 'approver'), (sender, 'sender'), (recipient, 'recipient')))
    return lab.DeliveryPolicy(a['signing_key'], s['signing_key'], r['signing_key'], r['delivery_key'])


def load_policy(path, expected_id):
    lab.unhex(expected_id, 32)
    body = read_json(path, 4096)
    names = {field.name for field in fields(lab.DeliveryPolicy)}
    lab.require(type(body) is dict and set(body) == names | {'version', 'mode', 'network', 'suite'},
                'Invalid adapter policy fields')
    policy = lab.DeliveryPolicy(**{name: body[name] for name in names})
    lab.require(body == policy.body() and policy.id == expected_id, 'Trusted policy pin mismatch')
    return policy


class Endpoint:
    """Reusable local API. Keys never appear in returned public records."""
    @classmethod
    def create(cls, path, role):
        lab.require(role in ROLES, 'Unknown endpoint role')
        path = Path(path)
        path.mkdir(mode=0o700)  # Existing endpoints are never overwritten.
        key = lab.Ed25519PrivateKey.generate()
        body = dict(format=KEY_FORMAT, role=role, signing_private=key.private_bytes_raw().hex())
        if role == 'recipient':
            body['delivery_private'] = lab.X25519PrivateKey.generate().private_bytes_raw().hex()
        write_json(path / 'keys.json', body)
        return cls(path)

    def __init__(self, path):
        self.path = private_directory(path)
        body = read_json(self.path / 'keys.json', 4096, private=True)
        lab.require(type(body) is dict and body.get('role') in ROLES, 'Invalid endpoint key record')
        self.role = body['role']
        expected = {'format', 'role', 'signing_private'} | (
            {'delivery_private'} if self.role == 'recipient' else set())
        lab.require(set(body) == expected and body['format'] == KEY_FORMAT, 'Invalid endpoint key fields')
        self.identity = lab.Ed25519PrivateKey.from_private_bytes(lab.unhex(body['signing_private'], 32))
        self.delivery = (lab.X25519PrivateKey.from_private_bytes(lab.unhex(body['delivery_private'], 32))
                         if self.role == 'recipient' else None)

    def public(self):
        result = dict(format=PUBLIC_FORMAT, role=self.role, signing_key=lab.public(self.identity))
        if self.delivery is not None:
            result['delivery_key'] = lab.key_public(self.delivery)
        return result

    def _check(self, role, policy):
        lab.require(self.role == role and lab.public(self.identity) == getattr(policy, role),
                    'Endpoint role/key does not match trusted policy')
        if role == 'recipient':
            lab.require(lab.key_public(self.delivery) == policy.delivery_key, 'Delivery key mismatch')

    def _state(self, policy, kind):
        # Validate permissions even when reopening an existing state database.
        private_directory(self.path)
        path = self.path / f'{kind}-{policy.id}.sqlite'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            meta = os.fstat(fd)
            lab.require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid()
                        and meta.st_mode & 0o077 == 0, 'Unsafe endpoint state file')
        finally:
            os.close(fd)
        return path

    def challenge(self, policy, now):
        self._check('approver', policy)
        registry = lab.BindingRegistry(self._state(policy, 'binding'), policy)
        try:
            return registry.challenge(now)
        finally:
            registry.close()

    def answer(self, policy, challenge, now):
        self._check('recipient', policy)
        return lab.answer_challenge(challenge, policy, self.identity, self.delivery, now)

    def bind(self, policy, proof, now):
        self._check('approver', policy)
        registry = lab.BindingRegistry(self._state(policy, 'binding'), policy)
        try:
            return registry.register(proof, self.identity, now)
        finally:
            registry.close()

    def binding(self, policy):
        self._check('approver', policy)
        registry = lab.BindingRegistry(self._state(policy, 'binding'), policy)
        try:
            certificate = registry.get_binding()
            lab.require(certificate is not None, 'No saved binding')
            return certificate
        finally:
            registry.close()

    def seal(self, policy, binding, plaintext, now):
        self._check('sender', policy)
        return lab.seal(policy, binding, plaintext, now, now + policy.max_lifetime)

    def approve(self, policy, envelope, now):
        self._check('approver', policy)
        return lab.approve(envelope, policy, self.identity, now)

    def send(self, policy, envelope, now):
        self._check('sender', policy)
        return lab.sign_send(envelope, policy, self.identity, now)

    def _receiver(self, policy):
        self._check('recipient', policy)
        return lab.Recipient(self._state(policy, 'received'), policy, self.identity, self.delivery)

    def receive(self, policy, raw, now):
        receiver = self._receiver(policy)
        try:
            return receiver.receive(raw, now)
        finally:
            receiver.close()

    def receipt(self, policy, transfer_id):
        receiver = self._receiver(policy)
        try:
            result = receiver.get_receipt(transfer_id)
            lab.require(result is not None, 'No saved receipt')
            return result
        finally:
            receiver.close()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest='command', required=True)
    keygen = commands.add_parser('keygen', help='Create unencrypted TEST keys; never use sensitive data')
    keygen.add_argument('--endpoint', required=True)
    keygen.add_argument('--role', choices=ROLES, required=True)
    keygen.add_argument('--output', required=True, help='Public role record only')
    policy = commands.add_parser('policy', help='Build public policy from independently authenticated records')
    for role in ROLES:
        policy.add_argument('--' + role, required=True)
    policy.add_argument('--output', required=True)
    for name in ('challenge', 'answer', 'bind', 'binding', 'seal', 'approve', 'send', 'receive', 'receipt', 'verify-receipt'):
        command = commands.add_parser(name)
        command.add_argument('--policy', required=True)
        command.add_argument('--policy-id', required=True, help='Previously trusted out-of-band fingerprint')
        if name != 'verify-receipt':
            command.add_argument('--endpoint', required=True)
            command.add_argument('--output', required=True)
        if name in ('answer', 'bind', 'approve', 'send', 'receive', 'verify-receipt'):
            command.add_argument('--input', required=True)
        if name == 'seal':
            command.add_argument('--binding', required=True)
            command.add_argument('--input', required=True, help='Binary plaintext, 1..65536 bytes')
        if name == 'receipt':
            command.add_argument('--transfer-id', required=True)
        if name in ('receive', 'verify-receipt'):
            command.add_argument('--receipt', required=True)
    return result


def run(args):
    if args.command == 'keygen':
        endpoint = Endpoint.create(args.endpoint, args.role)
        write_json(args.output, endpoint.public())
        return dict(mode=lab.MODE, role=endpoint.role, public_record_written=True)
    if args.command == 'policy':
        policy = make_policy(*(read_json(getattr(args, role), 4096) for role in ROLES))
        write_json(args.output, policy.body())
        return dict(mode=lab.MODE, policy_id=policy.id, authenticate_pin_out_of_band=True)
    policy = load_policy(args.policy, args.policy_id)
    if args.command == 'verify-receipt':
        lab.verify_receipt(read_json(args.receipt), read_json(args.input), policy)
        return dict(mode=lab.MODE, recipient_signature_verified=True, proof_of_reading=False)
    endpoint = Endpoint(args.endpoint)
    now = lab.number(int(time.time()))
    if args.command == 'receive':
        # Catch obvious output errors before committing local acceptance. Publication
        # is still not atomic with the SQLite receipt; never reaccept on export error.
        lab.require(Path(args.output).absolute() != Path(args.receipt).absolute(), 'Output paths must differ')
        for path in (args.output, args.receipt):
            lab.require(not os.path.lexists(path) and Path(path).parent.is_dir(), 'Output already exists or parent missing')
        plaintext, receipt = endpoint.receive(policy, read_bytes(args.input, lab.MAX_WIRE), now)
        write_new(args.output, plaintext)
        write_json(args.receipt, receipt)
        return dict(mode=lab.MODE, transfer_id=receipt['body']['transfer_id'], accepted_locally=True)
    if args.command == 'seal':
        value = endpoint.seal(policy, read_json(args.binding), read_bytes(args.input, policy.max_bytes), now)
    elif args.command == 'receipt':
        value = endpoint.receipt(policy, args.transfer_id)
    elif args.command == 'binding':
        value = endpoint.binding(policy)
    elif args.command == 'challenge':
        value = endpoint.challenge(policy, now)
    else:
        value = getattr(endpoint, args.command)(policy, read_json(args.input), now)
    write_json(args.output, value)
    return dict(mode=lab.MODE, operation=args.command, output_written=True)


def main():
    try:
        result = run(parser().parse_args())
    except (ValueError, TypeError, KeyError, OSError, sqlite3.Error):
        # Never include input data, key material, plaintext, or exception reprs.
        print('ICP adapter rejected the operation. No overwrite or automatic retry. '
              'If receive/export was interrupted, recover its saved receipt; acceptance may be committed.',
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
