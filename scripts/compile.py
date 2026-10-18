#!/usr/bin/env python3
"""Fetch the checksum-pinned Linux x86_64 compiler and compile real bytecode."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
URL = 'https://github.com/kaspanet/silverscript/releases/download/v1.0.0/silverc-linux-x86_64.tar.gz'
ARCHIVE_SHA = '058ffa17a390526f27280752f864b1bd680217cded14dfc5b7fd168d7e943fb5'
BINARY_SHA = '4d205f9bb095ae6c9027cebdcf748f7ea472f8785b054e94d8124ee7bafb84cc'

def compiler():
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
        raise SystemExit('This bootstrap pins Linux x86_64. Use a Linux Codespace or build the exact pinned source revision.')
    dest = ROOT / 'tools' / 'silverc'
    if not dest.exists():
        data = urllib.request.urlopen(URL, timeout=60).read()
        if hashlib.sha256(data).hexdigest() != ARCHIVE_SHA:
            raise SystemExit('Compiler archive checksum mismatch')
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            member = next(m for m in archive.getmembers() if m.name.rstrip('/').split('/')[-1] == 'silverc' and m.isfile())
            dest.parent.mkdir(exist_ok=True)
            dest.write_bytes(archive.extractfile(member).read())
        dest.chmod(0o755)
    if hashlib.sha256(dest.read_bytes()).hexdigest() != BINARY_SHA:
        raise SystemExit('Compiler binary checksum mismatch')
    return dest

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--args', type=Path, help='JSON array of five public constructor parameters, without the pending flag')
    p.add_argument('--output', type=Path, default=Path('artifacts'))
    ns = p.parse_args()
    os.chdir(ROOT)
    binary = compiler()
    ns.output.mkdir(parents=True, exist_ok=True)
    public = json.loads(ns.args.read_text()) if ns.args else None
    for state, pending in [('idle', False), ('pending', True)]:
        args = ns.output / (state + '.args.json')
        if public is not None:
            if len(public) != 5:
                raise SystemExit('Expected owner, recovery, recipient, delay_daa and max_fee')
            args.write_text(json.dumps(public + [{'kind': 'bool', 'value': pending}], indent=2) + '\n')
        subprocess.run([str(binary), 'contracts/icp_vault.sil', '--constructor-args', str(args), '-o', str(ns.output / (state + '.json'))], check=True)
    if public is None:
        base = json.loads((ns.output / 'pending.args.json').read_text())
        other_key = list(bytes.fromhex('e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13'))
        for name, index, value in [('changed_recipient', 2, other_key), ('changed_recovery', 1, other_key), ('short_delay', 3, 1), ('large_fee', 4, 10000000)]:
            args = json.loads(json.dumps(base))
            args[index]['value'] = value
            with tempfile.TemporaryDirectory() as directory:
                src = Path(directory) / 'args.json'
                src.write_text(json.dumps(args))
                subprocess.run([str(binary), 'contracts/icp_vault.sil', '--constructor-args', str(src), '-o', str(ns.output / (name + '.json'))], check=True)
    print('Compiled idle and pending bytecode with checksum-pinned SilverScript v1.0.0 release (artifact version 0.1.0).')

if __name__ == '__main__':
    main()
