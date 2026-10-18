#!/usr/bin/env python3
"""Compile the separate v1 candidate using the existing checksum-pinned compiler."""
import argparse
import json
from pathlib import Path
import subprocess
from compile import ROOT, compiler

STATES = {'idle': 0, 'pending': 1, 'quarantined': 2}

def arguments(policy, stage):
    return ([{'kind': 'bytes', 'value': list(bytes.fromhex(policy[k]))}
             for k in ('owner', 'recovery', 'recipient', 'cold')]
            + [{'kind': 'int', 'value': policy[k]}
               for k in ('delay_daa', 'cold_delay_daa', 'max_fee')]
            + [{'kind': 'int', 'value': stage}])

def compile_one(binary, args, path):
    src = path.with_suffix('.args.json')
    src.write_text(json.dumps(args, indent=2) + '\n')
    subprocess.run([str(binary), 'contracts/icp_protected.sil',
                    '--constructor-args', str(src), '-o', str(path)],
                   cwd=ROOT, check=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--policy', type=Path, default=ROOT/'artifacts/protected/policy.json')
    p.add_argument('--output', type=Path, default=ROOT/'artifacts/protected')
    p.add_argument('--fixtures', action='store_true')
    a = p.parse_args()
    policy = json.loads(a.policy.read_text())
    if policy['network'] != 'testnet-10' or policy['version'] != 'protected-v1':
        raise SystemExit('Expected protected-v1 testnet-10 policy')
    binary = compiler()
    a.output = a.output.resolve()
    a.output.mkdir(parents=True, exist_ok=True)
    for name, stage in STATES.items():
        compile_one(binary, arguments(policy, stage), a.output/(name+'.json'))
    if a.fixtures:
        base = arguments(policy, 2)
        other = list(bytes.fromhex('2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4'))
        for name, index, value in [('changed_cold', 3, other),
                                   ('changed_trigger', 1, other),
                                   ('changed_recipient', 2, other),
                                   ('short_cold_delay', 5, 601),
                                   ('large_fee', 6, 10000000),
                                   ('invalid_stage', 7, 3),
                                   ('shared_cold', 3, base[0]['value'])]:
            args = json.loads(json.dumps(base))
            args[index]['value'] = value
            compile_one(binary, args, a.output/(name+'.json'))
    print('Compiled protected-v1 (idle, pending, quarantined).')

if __name__ == '__main__':
    main()
