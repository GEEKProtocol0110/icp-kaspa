#!/usr/bin/env python3
"""Journal one TN10 test anchor; `observe` never prepares or broadcasts.

Funding keys stay in the native preparation subprocess. Public transfers use
fresh disposable lab roles and synthetic data. No chain-governed key release.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.parse import urlsplit

from transfer_anchor import AnchorTracker, commitment
from transfer_lab import Policy, TransferError, canonical, demo, number, verify_envelope
from watchtower import ROOT, guard, point, txid

FEE = 2_000_000


def durable(path, value, exclusive=False):
    data = canonical(value) + b'\n'
    path = Path(path)
    if exclusive:
        with path.open('xb') as file:
            os.chmod(path, 0o600); file.write(data); file.flush(); os.fsync(file.fileno())
    else:
        temporary = path.with_suffix(path.suffix + '.tmp')
        with temporary.open('wb') as file:
            os.chmod(temporary, 0o600); file.write(data); file.flush(); os.fsync(file.fileno())
        temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def validate_config(config):
    if type(config) is not dict or set(config) != {'network', 'funding', 'nodes'} or config['network'] != 'testnet-10':
        raise TransferError('Expected exact TN10 pilot configuration')
    funding = config['funding']
    if type(funding) is not dict or set(funding) != {'policy', 'source_outpoint', 'source_amount'}:
        raise TransferError('Invalid public funding pin')
    source, index = funding['source_outpoint'].split(':')
    txid(source)
    if str(number(int(index))) != index or not 0 <= int(index) < 2**32:
        raise TransferError('Noncanonical source index')
    if not 12_000_000 <= number(funding['source_amount']) <= 100_000_000:
        raise TransferError('Source must be 0.12 to 1 test KAS')
    if type(config['nodes']) is not list or len(config['nodes']) != 2:
        raise TransferError('Exactly two pinned TN10 endpoints required')
    hosts = []
    for value in config['nodes']:
        parsed = urlsplit(value)
        if parsed.scheme != 'wss' or parsed.path != '/kaspa/testnet-10/wrpc/borsh' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise TransferError('Expected a public TN10 TLS Borsh endpoint')
        hosts.append(parsed.hostname)
    if len(set(hosts)) != 2:
        raise TransferError('Second observation must use another host')


def transfer_policy(transcript):
    p = transcript['policy']
    return Policy(p['approver'], p['sender'], p['recipient'], p['max_bytes'], p['max_lifetime'])


def check_prepared(value, plan):
    if value.get('status') != 'PREPARED' or value.get('network') != 'testnet-10' or value.get('plan') != plan or value.get('fee') != FEE:
        raise TransferError('Prepared anchor does not match pinned plan')
    txid(value['id']); guard(value['node'])
    source = value['source']; entry = source['utxoEntry']; tx = value['transaction']
    if point(source['outpoint']) != plan['source_outpoint'] or entry['amount'] != plan['source_amount'] or entry.get('covenantId') is not None or entry['isCoinbase'] is not False:
        raise TransferError('Prepared source mismatch')
    check_transaction(tx, plan, entry['scriptPublicKey'])


def check_transaction(tx, plan, script):
    if (tx['version'], tx['lockTime'], tx['subnetworkId'], tx['gas'], tx['payload']) != (1, 0, '00' * 20, 0, plan['payload']):
        raise TransferError('Anchor header or payload mismatch')
    if len(tx['inputs']) != 1 or point(tx['inputs'][0]['previousOutpoint']) != plan['source_outpoint'] or tx['inputs'][0]['sequence'] != 0:
        raise TransferError('Anchor input mismatch')
    if len(tx['outputs']) != 1:
        raise TransferError('Anchor must have one self-return output')
    out = tx['outputs'][0]
    if out['value'] != plan['source_amount'] - FEE or out['scriptPublicKey'] != script or out.get('covenant') is not None:
        raise TransferError('Anchor output or fee mismatch')


class Node:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def _run(self, binary, args, signing=False, json_output=True):
        env = dict(os.environ, ICP_UPSTREAM_URL=self.endpoint)
        env.pop('ICP_RPC_URL', None)
        if not signing: env.pop('ICP_SIGNER_KEY_FILE', None)
        command = [sys.executable, str(ROOT / 'scripts/with_proxy.py'), str(binary), *map(str, args)]
        p = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = p.communicate(timeout=50)
        except BaseException:
            # Stop the relay AND its native child; an ambiguous broadcast still
            # requires read-only reconciliation even after the process exits.
            try: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            p.communicate()
            raise
        if p.returncode:
            raise TransferError(stderr.strip() or 'Native anchor operation failed')
        return json.loads(stdout) if json_output else stdout

    def call(self, *args, json_output=True):
        if args[0] not in ('anchor', 'scan', 'broadcast'):
            raise TransferError('Unexpected pilot operation')
        return self._run(ROOT / 'target/debug/icp', args, json_output=json_output)

    def prepare(self, plan, receipt):
        return self._run(ROOT / 'target/debug/examples/prepare_transfer_anchor',
                         ['prepare', plan, receipt], signing=True)


def claim(run_dir, source):
    directory = run_dir.parent / 'transfer-anchor-claims'
    directory.mkdir(mode=0o700, exist_ok=True)
    name = hashlib.sha256(source.encode('ascii')).hexdigest() + '.json'
    durable(directory / name, {'source_outpoint': source, 'run': run_dir.name}, exclusive=True)


def observe(run_dir, nodes, clock=time.time, monotonic=time.monotonic, sleep=time.sleep, timeout=120):
    """Read-only restart/reconciliation; uses the original signed bytes and pins."""
    run_dir = Path(run_dir)
    journal_path = run_dir / 'journal.json'
    journal = json.loads(journal_path.read_text())
    config = journal['config']; validate_config(config)
    if [n.endpoint for n in nodes] != config['nodes']:
        raise TransferError('Observation endpoints changed')
    prepared = json.loads((run_dir / 'prepared.json').read_text())
    plan = json.loads((run_dir / 'plan.json').read_text())
    check_prepared(prepared, plan)
    transcript = json.loads((run_dir / 'exchange.json').read_text())
    policy = transfer_policy(transcript)
    if commitment(transcript['envelope'], policy) != plan['payload']:
        raise TransferError('Exchange commitment changed')
    if {k: plan[k] for k in config['funding']} != config['funding']:
        raise TransferError('Funding pins changed')
    trackers = []
    sequence = number(journal.get('scan_sequence', 0))
    try:
        for i in range(2):
            trackers.append(AnchorTracker(run_dir / f'node-{i}.sqlite', policy,
                transcript['envelope'], prepared['id'], journal['bootstraps'][i]['anchor']))
        deadline = monotonic() + timeout
        while monotonic() < deadline:
            for tracker in trackers: tracker.unavailable()
            cursors = [tracker.tip for tracker in trackers]
            def fetch(i):
                at = int(clock())
                return at, nodes[i].call('scan', cursors[i])
            # Independent RPCs overlap; apply SQLite changes on this thread.
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(fetch, i) for i in range(2)]
                results = [future.result() for future in futures]
            for i, (at, response) in enumerate(results):
                sequence += 1
                durable(run_dir / f'scan-{sequence:06d}-node-{i}.json',
                        {'endpoint': nodes[i].endpoint, 'fetched_at': at, 'response': response}, exclusive=True)
                for block in response['changes']['chainBlockAcceptedTransactions']:
                    for tx in block['acceptedTransactions']:
                        if tx['verboseData']['transactionId'] == prepared['id']:
                            check_transaction(tx, plan, prepared['source']['utxoEntry']['scriptPublicKey'])
                trackers[i].apply(response, at)
            states = [tracker.status(int(clock())) for tracker in trackers]
            journal.update(status='OBSERVING', observations=states, scan_sequence=sequence)
            durable(journal_path, journal)
            if all(s['state'] == 'OBSERVED_COMMITMENT' for s in states):
                journal['status'] = 'TWO_NODE_ANCHOR_OBSERVED'
                durable(journal_path, journal)
                return journal
            if any(s['state'] == 'PERMISSION_INACTIVE' for s in states):
                raise TransferError('Exchange expired; historical reconciliation is still required')
            sleep(0 if any(s['state'] == 'CHAIN_BACKLOG' for s in states) else 1)
        raise TimeoutError('Anchor observation incomplete; reconcile without rebroadcasting')
    except Exception as error:
        journal.update(status='OBSERVATION_INCOMPLETE', scan_sequence=sequence, error=str(error))
        durable(journal_path, journal)
        raise
    finally:
        for tracker in trackers: tracker.close()


def run(run_dir, config, nodes, clock=time.time, prepare=None, transcript_factory=demo,
        observer=observe):
    validate_config(config)
    if [n.endpoint for n in nodes] != config['nodes']:
        raise TransferError('Configured nodes do not match adapters')
    run_dir = Path(run_dir)
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    journal_path = run_dir / 'journal.json'
    journal = {'version': 'icp-transfer-anchor-pilot-v0', 'status': 'PREFLIGHT', 'config': config}
    durable(journal_path, journal, exclusive=True)
    attempted = False
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(n.call, 'anchor') for n in nodes]
            anchors = [f.result() for f in futures]
        for anchor in anchors: guard(anchor['node']); txid(anchor['anchor'])
        journal['bootstraps'] = anchors
        transcript = transcript_factory(); policy = transfer_policy(transcript)
        verify_envelope(transcript['envelope'], policy, int(clock()))
        plan = dict(config['funding'], version='icp-transfer-anchor-v0', network='testnet-10',
                    payload=commitment(transcript['envelope'], policy))
        durable(run_dir / 'exchange.json', transcript, exclusive=True)
        durable(run_dir / 'plan.json', plan, exclusive=True)
        claim(run_dir, plan['source_outpoint'])
        journal['status'] = 'PREPARING'; durable(journal_path, journal)
        (prepare or nodes[0].prepare)(run_dir / 'plan.json', run_dir / 'prepared.json')
        # The on-disk, fsynced receipt is authoritative, not subprocess stdout.
        prepared = json.loads((run_dir / 'prepared.json').read_text())
        check_prepared(prepared, plan)
        verify_envelope(transcript['envelope'], policy, int(clock()))
        journal.update(status='SUBMITTING', transaction_id=prepared['id'])
        attempted = True
        durable(journal_path, journal)
        # Exactly one attempt. Persist ambiguous intent BEFORE the side effect.
        output = nodes[0].call('broadcast', str(run_dir / 'prepared.json'), json_output=False)
        journal.update(status='SUBMITTED_NOT_CONFIRMED', broadcast_output=output)
        durable(journal_path, journal)
    except Exception as error:
        journal.update(status='SUBMISSION_UNKNOWN' if attempted else 'FAILED_PRE_SUBMISSION', error=str(error))
        durable(journal_path, journal)
        raise
    return observer(run_dir, nodes, clock=clock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('run', 'observe'))
    parser.add_argument('config', type=Path)
    parser.add_argument('name', help='New or existing run name below runtime/')
    args = parser.parse_args()
    if not args.name or args.name in ('.', '..') or Path(args.name).name != args.name:
        parser.error('Expected a single run directory name')
    config = json.loads(args.config.read_text()); validate_config(config)
    nodes = [Node(endpoint) for endpoint in config['nodes']]
    path = ROOT / 'runtime' / args.name
    if args.operation == 'run':
        result = run(path, config, nodes)
    else:
        if json.loads((path / 'journal.json').read_text())['config'] != config:
            raise TransferError('Configuration changed; reconcile original run')
        result = observe(path, nodes)
    print(json.dumps({'status': result['status'], 'transaction_id': result.get('transaction_id'),
                      'observations': result.get('observations')}, indent=2))


if __name__ == '__main__':
    main()
