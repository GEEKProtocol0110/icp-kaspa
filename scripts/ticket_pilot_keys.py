#!/usr/bin/env python3
"""Offline TN10 P0 test-key setup; no transaction signing, RPC or funding."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from native_ticket_observer import canonical, decode

ROOT = Path(__file__).resolve().parents[1]
MODE = 'TN10_P0_TEST_KEYS_NO_FUNDING_OR_AUTHORIZATION'
DOMAIN = b'icp/p0/test-key-possession/v0\0'
RUNS = ('consume', 'refund')
ROLES = ('funding', 'ticket', 'return')
NAMES = {'manifest.json'} | {f'{run}/{role}.key' for run in RUNS for role in ROLES}
HEX32 = re.compile(r'[0-9a-f]{64}\Z')


class KeyError(ValueError):
    pass


def require(condition):
    if not condition:
        raise KeyError('Test-key session validation failed')


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def new_dir(path):
    path = Path(path).absolute()
    require(path.resolve() == path)  # Reject symlink ancestors, including destination.
    path.mkdir(mode=0o700)
    fsync_dir(path.parent)
    return path


def write_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fsync_dir(Path(path).parent)


def read_private(path, limit):
    path = Path(path).absolute()
    require(path.resolve() == path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        require(stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600
                and s.st_uid == os.getuid() and s.st_nlink == 1 and s.st_size <= limit)
        raw = f.read(limit + 1)
    require(len(raw) <= limit)
    return raw


def public_key(key):
    return dict(x_only=key.public_key().public_numbers().x.to_bytes(32, 'big').hex(),
                compressed=key.public_key().public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex())


class Addresses:
    """Only public keys reach the pinned native address process."""
    def __init__(self, binary=None):
        self.binary = Path(binary or ROOT / 'target/debug/examples/ticket_pilot_review').resolve()
        self.fingerprint = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def get(self, roles):
        require(hashlib.sha256(self.binary.read_bytes()).hexdigest() == self.fingerprint)
        request = {role + '_key': roles[role]['x_only'] for role in ROLES}
        r = subprocess.run([str(self.binary), 'addresses'], input=canonical(request),
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           env={'PATH': '/usr/bin:/bin'}, timeout=20)
        require(r.returncode == 0 and len(r.stdout) <= 4096)
        v = decode(r.stdout)
        closed(v, ('mode', 'network', 'roles'))
        require(v['mode'] == 'TN10_P0_PUBLIC_ADDRESSES_NO_SOURCE_OR_AUTHORIZATION'
                and v['network'] == 'testnet-10')
        closed(v['roles'], ROLES)
        require(all(type(a) is str and a.startswith('kaspatest:') for a in v['roles'].values()))
        return v['roles']


def challenge(manifest, run, role):
    entry = manifest['runs'][run]['roles'][role]
    return DOMAIN + canonical(dict(mode=MODE, network='testnet-10',
        session_id=manifest['session_id'], run=run, role=role,
        run_nonce=manifest['runs'][run]['run_nonce'],
        public={k: entry[k] for k in ('x_only', 'compressed', 'address')}))


def verify_material(files, native):
    """Verify archived bytes and fresh possession, without a transaction digest."""
    require(set(files) == NAMES and len(files['manifest.json']) <= 16384)
    m = decode(files['manifest.json'])
    require(canonical(m) == files['manifest.json'])
    closed(m, ('mode', 'network', 'session_id', 'runs'))
    require(m['mode'] == MODE and m['network'] == 'testnet-10'
            and type(m['session_id']) is str and HEX32.fullmatch(m['session_id']))
    closed(m['runs'], RUNS)
    keys, nonces = set(), set()
    for run in RUNS:
        r = m['runs'][run]
        closed(r, ('run_nonce', 'roles'))
        require(type(r['run_nonce']) is str and HEX32.fullmatch(r['run_nonce'])
                and r['run_nonce'] not in ('00' * 32, '44' * 32) and r['run_nonce'] not in nonces)
        nonces.add(r['run_nonce'])
        closed(r['roles'], ROLES)
        for role in ROLES:
            entry = r['roles'][role]
            closed(entry, ('x_only', 'compressed', 'address', 'proof'))
            raw = files[f'{run}/{role}.key']
            require(len(raw) == 64 and HEX32.fullmatch(raw.decode('ascii')))
            key = ec.derive_private_key(int(raw, 16), ec.SECP256K1())
            p = public_key(key)
            require(entry['x_only'] == p['x_only'] and entry['compressed'] == p['compressed']
                    and p['x_only'] not in keys)
            keys.add(p['x_only'])
            proof = bytes.fromhex(entry['proof'])
            require(proof.hex() == entry['proof'] and len(proof) <= 72)
            key.public_key().verify(proof, challenge(m, run, role), ec.ECDSA(hashes.SHA256()))
            # A fresh challenge proves the restored secret, not just a saved signature.
            fresh = DOMAIN + b'restore\0' + secrets.token_bytes(32) + challenge(m, run, role)
            key.public_key().verify(key.sign(fresh, ec.ECDSA(hashes.SHA256())),
                                    fresh, ec.ECDSA(hashes.SHA256()))
        require(native.get(r['roles']) == {role: r['roles'][role]['address'] for role in ROLES})
    return m


def read_session(root):
    root = Path(root).absolute()
    require(root == root.resolve() and stat.S_IMODE(root.stat().st_mode) == 0o700
            and root.stat().st_uid == os.getuid())
    found = {str(p.relative_to(root)) for p in root.rglob('*') if not p.is_dir()}
    require(found == NAMES)
    for run in RUNS:
        p = root / run
        require(not p.is_symlink() and stat.S_IMODE(p.stat().st_mode) == 0o700
                and p.stat().st_uid == os.getuid())
    return {name: read_private(root / name, 16384 if name == 'manifest.json' else 64) for name in NAMES}


def restore(archive, destination, expected_sha256, native=None):
    require(type(expected_sha256) is str and HEX32.fullmatch(expected_sha256))
    raw = read_private(archive, 65536)
    require(hashlib.sha256(raw).hexdigest() == expected_sha256)
    import io
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        entries = z.infolist()
        require(len(entries) == len(NAMES) and {i.filename for i in entries} == NAMES)
        require(all(i.file_size <= (16384 if i.filename == 'manifest.json' else 64)
                    and i.compress_type == zipfile.ZIP_STORED for i in entries))
        files = {i.filename: z.read(i) for i in entries}
    native = native or Addresses()
    m = verify_material(files, native)
    dest = new_dir(destination)
    for run in RUNS:
        new_dir(dest / run)
    for name, data in files.items():
        write_private(dest / name, data)
    require(read_session(dest) == files)
    verify_material(read_session(dest), native)
    return m


def create(root, backup, native=None):
    native = native or Addresses()
    root = new_dir(root)
    m = dict(mode=MODE, network='testnet-10', session_id=secrets.token_hex(32), runs={})
    for run in RUNS:
        new_dir(root / run)
        m['runs'][run] = dict(run_nonce=secrets.token_hex(32), roles={})
        for role in ROLES:
            key = ec.generate_private_key(ec.SECP256K1())
            write_private(root / run / (role + '.key'),
                          f'{key.private_numbers().private_value:064x}'.encode('ascii'))
            m['runs'][run]['roles'][role] = public_key(key)
        roles = m['runs'][run]['roles']
        for role, addr in native.get(roles).items():
            roles[role]['address'] = addr
        for role in ROLES:
            raw = read_private(root / run / (role + '.key'), 64)
            key = ec.derive_private_key(int(raw, 16), ec.SECP256K1())
            roles[role]['proof'] = key.sign(challenge(m, run, role), ec.ECDSA(hashes.SHA256())).hex()
    write_private(root / 'manifest.json', canonical(m))
    files = read_session(root)
    verify_material(files, native)
    backup = Path(backup).absolute()
    require(backup == backup.resolve())
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        with zipfile.ZipFile(f, 'w', compression=zipfile.ZIP_STORED) as z:
            for name in sorted(files):
                z.writestr(name, files[name])
        f.flush()
        os.fsync(f.fileno())
    fsync_dir(backup.parent)
    digest = hashlib.sha256(read_private(backup, 65536)).hexdigest()
    with tempfile.TemporaryDirectory(prefix='icp-p0-restore-') as temp:
        restored = restore(backup, Path(temp) / 'session', digest, native)
        require(restored == m)
    return dict(mode=MODE, network='testnet-10', session_id=m['session_id'],
                manifest_sha256=hashlib.sha256(files['manifest.json']).hexdigest(),
                backup_sha256=digest, native_binary_sha256=native.fingerprint,
                distinct_keys=6, restored_keys_verified=6,
                proof_suite='secp256k1 ECDSA/SHA256, possession only; not transaction signatures',
                funding_addresses={run: m['runs'][run]['roles']['funding']['address'] for run in RUNS},
                source_observed=False, transactions_signed=0, rpc_calls=0, broadcasts=0,
                backup_retention='LOCAL_ONLY_MUST_PERSIST_BEFORE_FUNDING_REQUEST')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    c = sub.add_parser('create')
    c.add_argument('new_session_directory')
    c.add_argument('new_private_zip')
    r = sub.add_parser('restore')
    r.add_argument('private_zip')
    r.add_argument('new_session_directory')
    r.add_argument('expected_sha256')
    args = parser.parse_args()
    try:
        if args.command == 'create':
            result = create(args.new_session_directory, args.new_private_zip)
        else:
            m = restore(args.private_zip, args.new_session_directory, args.expected_sha256)
            result = dict(mode=MODE, session_id=m['session_id'], restored_keys_verified=6)
    except Exception:
        # Deliberately exclude exception details, key input and subprocess output.
        raise SystemExit('Test-key setup failed; preserve partial files and investigate. Do not fund.') from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
