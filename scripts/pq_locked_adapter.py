#!/usr/bin/env python3
"""Encrypted software keystore for the experimental PQ recipient profile.

Fictional data only. No hardware isolation, memory erasure, password recovery,
automatic key migration, endpoint-state restore or native Kaspa signing.
"""
import argparse
from contextlib import closing
import getpass
import hmac
import json
import os
from pathlib import Path
import select
import sqlite3
import stat
import sys
import time
import warnings

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

import pq_recipient_adapter as base

lab = base.lab
FORMAT = 'icp-pq-endpoint-encrypted-software-keystore-v0'
KEY_FILE = 'keys.enc.json'
MAX_STORE = 12288
MAX_RECORD = 4096
MAX_PASSWORD = 1024
GUARD_FORMAT = 'icp-pq-locked-state-presence-v0'
KDF = dict(name='Argon2id', version=19, memory_kib=65536, iterations=3, lanes=4, length=32)
DOMAIN = b'icp/pq-recipient/encrypted-software-keystore/v0\0'


def password_bytes(value):
    lab.require(type(value) is bytes and 16 <= len(value) <= MAX_PASSWORD
                and value.strip() and not any(c in value for c in (b'\0', b'\n', b'\r')),
                'Passphrase must be 16..1024 bytes without NUL or line endings')
    return value


def derive(password, salt):
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4,
                    memory_cost=65536).derive(password_bytes(password))


def decode_keys(body):
    lab.require(type(body) is dict and body.get('role') in base.ROLES, 'Invalid locked role')
    role = body['role']
    expected = {'format', 'role', 'signing_private'} | ({'delivery_private'} if role == 'recipient' else set())
    lab.require(set(body) == expected and body['format'] == base.KEY_FORMAT, 'Invalid locked key fields')
    identity = lab.SigningPrivateKey.from_seed_bytes(lab.unhex(body['signing_private'], 32))
    delivery = (lab.DeliveryPrivateKey.from_private_bytes(lab.unhex(body['delivery_private'], 96))
                if role == 'recipient' else None)
    return role, identity, delivery


def public_keys(body):
    role, identity, delivery = decode_keys(body)
    result = dict(format=base.PUBLIC_FORMAT, role=role, signing_key=lab.public(identity))
    if delivery is not None:
        result['delivery_key'] = lab.key_public(delivery)
    return result


def endpoint_id(record):
    return lab.identify('encrypted-endpoint-public', record)


def protect(body, password):
    password_bytes(password)
    public = public_keys(body)
    plaintext = lab.canonical(body)
    lab.require(len(plaintext) <= MAX_RECORD, 'Key record too large')
    salt, nonce = os.urandom(16), os.urandom(12)
    header = dict(format=FORMAT, suite=lab.SUITE_NAME, kdf=dict(KDF), aead='AES-256-GCM',
                  endpoint_id=endpoint_id(public), salt=salt.hex(), nonce=nonce.hex())
    encrypted = AESGCM(derive(password, salt)).encrypt(nonce, plaintext, DOMAIN + lab.canonical(header))
    return lab.canonical(dict(header, ciphertext=encrypted.hex()))


def unlock(raw, password, expected_id=None):
    password_bytes(password)
    lab.require(type(raw) is bytes and 0 < len(raw) <= MAX_STORE, 'Keystore outside size limit')
    body = lab.decode(raw)
    fields = {'format', 'suite', 'kdf', 'aead', 'endpoint_id', 'salt', 'nonce', 'ciphertext'}
    lab.require(type(body) is dict and set(body) == fields and body['format'] == FORMAT
                and body['suite'] == lab.SUITE_NAME and body['aead'] == 'AES-256-GCM'
                and body['kdf'] == KDF, 'Unsupported keystore profile')
    lab.unhex(body['endpoint_id'], 48)
    if expected_id is not None:
        lab.unhex(expected_id, 48)
        lab.require(hmac.compare_digest(body['endpoint_id'], expected_id), 'Wrong encrypted endpoint')
    salt, nonce = lab.unhex(body['salt'], 16), lab.unhex(body['nonce'], 12)
    encoded = body['ciphertext']
    lab.require(type(encoded) is str and 32 < len(encoded) <= 2 * (MAX_RECORD + 16)
                and len(encoded) % 2 == 0, 'Invalid keystore ciphertext size')
    ciphertext = lab.unhex(encoded, len(encoded) // 2)
    header = {k: v for k, v in body.items() if k != 'ciphertext'}
    try:
        clear = AESGCM(derive(password, salt)).decrypt(nonce, ciphertext, DOMAIN + lab.canonical(header))
    except InvalidTag as exc:
        raise lab.TransferError('Keystore unlock rejected') from exc
    keys = lab.decode(clear)
    lab.require(hmac.compare_digest(endpoint_id(public_keys(keys)), body['endpoint_id']),
                'Keystore identity binding mismatch')
    return keys


class LockedEndpoint(base.Endpoint):
    @classmethod
    def create(cls, path, role, password):
        password_bytes(password)
        lab.require(role in base.ROLES, 'Unknown endpoint role')
        identity = lab.SigningPrivateKey.generate()
        body = dict(format=base.KEY_FORMAT, role=role, signing_private=identity.private_bytes_raw().hex())
        if role == 'recipient':
            body['delivery_private'] = lab.DeliveryPrivateKey.generate().private_bytes_raw().hex()
        encrypted = protect(body, password)  # No plaintext temporary file.
        path = Path(path)
        path.mkdir(mode=0o700)
        base.private_directory(path)
        base.write_new(path / KEY_FILE, encrypted)
        instance = cls.__new__(cls)
        instance.path = path
        instance.role, instance.identity, instance.delivery = decode_keys(body)
        return instance

    def __init__(self, path, password):
        self.path = base.private_directory(path)
        # Never import an ordinary test-key endpoint, even if a locked file was added.
        lab.require(not os.path.lexists(self.path / 'keys.json'), 'Mixed plaintext/locked endpoint rejected')
        raw = base.read_bytes(self.path / KEY_FILE, MAX_STORE, private=True)
        self.role, self.identity, self.delivery = decode_keys(unlock(raw, password))

    def _state(self, policy, kind):
        # A separate durable marker makes accidental DB loss fail closed. It is
        # not a monotonic counter and cannot detect rollback of the whole store.
        lab.require(kind in ('binding', 'received'), 'Unknown locked state kind')
        base.private_directory(self.path)
        path = self.path / f'{kind}-{policy.id}.sqlite'
        guard = self.path / f'{kind}-{policy.id}.icp-state-guard'
        expected = dict(format=GUARD_FORMAT, policy_id=policy.id, kind=kind)
        created = False
        if not os.path.lexists(guard):
            lab.require(not os.path.lexists(path), 'Unrecognized state without presence marker')
            try:
                base.write_json(guard, expected)  # Must persist before DB initialization.
                created = True
            except FileExistsError:
                pass  # A concurrent opener must validate the marker and initialized DB.
        lab.require(base.read_json(guard, 1024, private=True) == expected, 'State presence marker mismatch')
        if not created:
            # Validate without creating a missing DB or repairing absent tables.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                meta = os.fstat(fd)
                lab.require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid()
                            and meta.st_mode & 0o077 == 0 and meta.st_size > 0, 'Locked state unavailable')
            finally:
                os.close(fd)
            # mode=rw refuses absent files while allowing SQLite to roll back a
            # hot journal after an interrupted transaction. mode=ro can block
            # that recovery and strand an otherwise intact replay history.
            with closing(sqlite3.connect(path.absolute().as_uri() + '?mode=rw', uri=True, timeout=10)) as db:
                expected_role = 'recipient' if kind == 'received' else 'binding-registry'
                lab.require(db.execute('SELECT policy,kind FROM recipient_lab_policy WHERE id=1').fetchone()
                            == (policy.id, expected_role), 'Locked state policy mismatch')
                tables = ('recipient_receipts',) if kind == 'received' else ('binding_challenges', 'bound_delivery')
                for table in tables:
                    lab.require(db.execute('SELECT 1 FROM sqlite_master WHERE type=? AND name=?',
                                           ('table', table)).fetchone() is not None, 'Incomplete locked state')
        return super()._state(policy, kind)

    def backup_key(self, output, password, expected_id):
        base.private_directory(self.path)
        raw = base.read_bytes(self.path / KEY_FILE, MAX_STORE, private=True)
        keys = unlock(raw, password, expected_id)
        lab.require(public_keys(keys) == self.public(), 'Endpoint changed while unlocked')
        base.write_new(output, raw)  # Encrypted keys only; never copies or resets state.


def read_password(fd=None, *, confirm=False):
    if fd is None:
        lab.require(sys.stdin.isatty(), 'TTY or explicit passphrase FD required')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = getpass.getpass('Keystore passphrase: ').encode('utf-8')
            if confirm:
                other = getpass.getpass('Confirm passphrase: ').encode('utf-8')
                lab.require(hmac.compare_digest(value, other), 'Passphrases differ')
        return password_bytes(value)
    lab.require(type(fd) is int and 0 <= fd <= 2 ** 31 - 1, 'Invalid passphrase descriptor')
    meta = os.fstat(fd)
    lab.require((stat.S_ISREG(meta.st_mode) or stat.S_ISFIFO(meta.st_mode))
                and meta.st_uid == os.getuid() and meta.st_mode & 0o077 == 0,
                'Passphrase FD must be an owner-only regular file or pipe')
    raw = bytearray()
    deadline = time.monotonic() + 10
    while True:
        remaining = deadline - time.monotonic()
        lab.require(remaining > 0 and select.select([fd], [], [], remaining)[0], 'Passphrase input timed out')
        chunk = os.read(fd, min(256, MAX_PASSWORD + 1 - len(raw)))
        if not chunk:
            return password_bytes(bytes(raw))
        raw.extend(chunk)
        lab.require(len(raw) <= MAX_PASSWORD, 'Passphrase input too large')


class LockedParser(argparse.ArgumentParser):
    def error(self, message):
        # Unknown options may contain a mistakenly supplied secret. Do not echo
        # argument values, even though no password argument is supported.
        self.print_usage(sys.stderr)
        self.exit(2, 'ICP locked adapter rejected command arguments.\n')


def parser():
    result = base.parser(keygen_help='Create fresh encrypted experiment keys; no plaintext migration',
                         parser_class=LockedParser)
    result.description = __doc__
    result.add_argument('--passphrase-fd', type=int, help='Owner-only file/pipe FD; raw bytes until EOF, no newline')
    commands = next(a for a in result._actions if isinstance(a, argparse._SubParsersAction))
    commands.choices['keygen'].description = 'Create fresh encrypted experiment keys; no plaintext migration'
    public = commands.add_parser('public', help='Recover the public record from an unlocked endpoint')
    public.add_argument('--endpoint', required=True)
    public.add_argument('--output', required=True)
    for name in ('backup-key', 'check-backup'):
        command = commands.add_parser(name, help='Encrypted key backup only; does not restore endpoint replay state')
        command.add_argument('--endpoint-id', required=True, help='Previously authenticated public endpoint fingerprint')
        if name == 'backup-key':
            command.add_argument('--endpoint', required=True)
            command.add_argument('--output', required=True)
        else:
            command.add_argument('--input', required=True)
    return result


def run(args):
    if args.command in ('policy', 'verify-receipt'):
        lab.require(args.passphrase_fd is None, 'This public command needs no passphrase')
        return base.run(args)
    password = read_password(args.passphrase_fd, confirm=args.command == 'keygen')
    if args.command == 'keygen':
        endpoint = LockedEndpoint.create(args.endpoint, args.role, password)
        base.write_json(args.output, endpoint.public())
        return dict(mode=lab.MODE, role=endpoint.role, public_record_written=True,
                    endpoint_id=endpoint_id(endpoint.public()))
    if args.command == 'public':
        endpoint = LockedEndpoint(args.endpoint, password)
        base.write_json(args.output, endpoint.public())
        return dict(mode=lab.MODE, public_record_written=True, endpoint_id=endpoint_id(endpoint.public()))
    if args.command == 'backup-key':
        endpoint = LockedEndpoint(args.endpoint, password)
        endpoint.backup_key(args.output, password, args.endpoint_id)
        return dict(mode=lab.MODE, encrypted_key_backup_written=True, endpoint_state_backed_up=False)
    if args.command == 'check-backup':
        unlock(base.read_bytes(args.input, MAX_STORE, private=True), password, args.endpoint_id)
        return dict(mode=lab.MODE, encrypted_key_backup_verified=True, endpoint_state_restored=False)
    return base.run(args, open_endpoint=lambda p: LockedEndpoint(p, password))


def main():
    try:
        result = run(parser().parse_args())
    except (ValueError, TypeError, KeyError, OSError, EOFError, sqlite3.Error,
            UnsupportedAlgorithm, MemoryError, RecursionError, getpass.GetPassWarning):
        print('ICP locked adapter rejected the operation. No automatic retry or state reset. '
              'Recover the saved receipt after interrupted receive/export.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
