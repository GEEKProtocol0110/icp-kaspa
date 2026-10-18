#!/usr/bin/env python3
"""Run the live TN10 acceptance sequence after funding a fresh test-only session.

No secrets are handled here. The native CLI owns signing and network gating.
Never silently restarts a partial pilot or treats a transport error as rejection.
"""
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'runtime'
CLI = ROOT / 'bin/icp'
if not CLI.exists():
    CLI = ROOT / 'target/debug/icp'
JOURNAL = RUNTIME / 'pilot.json'

def cli(*args):
    r = subprocess.run([str(CLI), *args], cwd=ROOT, text=True, capture_output=True, timeout=35)
    return r

def snapshot():
    r = cli('status')
    if r.returncode:
        raise RuntimeError(r.stderr or r.stdout)
    return json.loads((RUNTIME / 'last-status.json').read_text())

def observe(txid, index, timeout=90):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        s = snapshot()
        found = next((u for u in s['utxos'] if u['outpoint']['transactionId'] == txid and u['outpoint']['index'] == index), None)
        if found:
            return s, found
        time.sleep(1)
    raise RuntimeError(f'No accepted-chain UTXO observed for {txid}:{index}; inspect receipts before retrying')

def main():
    RUNTIME.mkdir(exist_ok=True)
    # Exclusive creation prevents accidental second deposits or overlapping pilots.
    with JOURNAL.open('x') as f:
        json.dump({'status': 'STARTED', 'steps': []}, f)
    journal = json.loads(JOURNAL.read_text())
    def save():
        JOURNAL.write_text(json.dumps(journal, indent=2) + '\n')
    def action(label, *args, early=False):
        before = set(RUNTIME.glob('*.json'))
        r = cli(*args)
        files = [p for p in set(RUNTIME.glob('*.json')) - before if p.name != 'pilot.json']
        receipts = [json.loads(p.read_text()) for p in files if 'transaction' in json.loads(p.read_text())]
        receipt = receipts[-1] if receipts else None
        journal['steps'].append({'step': label, 'returncode': r.returncode, 'receipt': receipt, 'output': r.stdout, 'error': r.stderr})
        save()
        if early:
            message = (receipt or {}).get('error', '').lower()
            if r.returncode == 0 or 'sequence lock' not in message:
                raise RuntimeError('Expected an explicit NODE sequence-lock rejection; transport failure is not sufficient')
            print('NODE rejected early execution for sequence locks.', flush=True)
            return None
        if r.returncode or not receipt or receipt['status'] != 'MEMPOOL_ACCEPTED':
            raise RuntimeError(f'{label} failed or is ambiguous. Inspect runtime receipts; do not create another deposit blindly')
        txid = receipt['id']
        s, u = observe(txid, 0)
        journal['steps'][-1]['accepted_chain_observation'] = {'node': s['node'], 'utxo': u}
        save()
        print(f'{label}: accepted-chain output observed: {txid}:0', flush=True)
        return txid
    try:
        snapshot()  # Network guard and UTXO index must pass before any spend.
        deposit = action('deposit', 'deposit')
        first = action('initiate_for_execution', 'initiate', f'{deposit}:0')
        action('early_execute_rejected', 'execute', f'{first}:0', early=True)
        second = action('initiate_for_recovery', 'initiate', f'{deposit}:1')
        action('recover_pending', 'recover', f'{second}:0')
        deadline = time.monotonic() + 180
        while True:
            s, u = observe(first, 0)
            age = s['node']['virtualDaaScore'] - u['utxoEntry']['blockDaaScore']
            if age >= 600 + 10:
                break
            if time.monotonic() > deadline:
                raise RuntimeError('Pending withdrawal did not mature within the test deadline')
            time.sleep(2)
        action('execute_after_delay', 'execute', f'{first}:0')
        journal['status'] = 'LIVE_PATHS_OBSERVED'
        journal['limitations'] = 'UTXO observations from one node; reorganization remains possible. No external audit or quantum-security claim.'
        save()
        print('Live deposit, pending, early rejection, recovery and delayed payout observed. Evidence: runtime/pilot.json', flush=True)
    except Exception as error:
        journal['status'] = 'STOPPED_REQUIRES_INSPECTION'
        journal['failure'] = str(error)
        save()
        raise

if __name__ == '__main__':
    main()
