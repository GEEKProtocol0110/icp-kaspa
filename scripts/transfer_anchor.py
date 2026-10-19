#!/usr/bin/env python3
"""Read-only TN10 commitment observations. No signing, broadcast or key release.

Consumes trusted-node `icp scan HASH` responses, not SPV/consensus proofs.
Callers must fetch a new response after opening the tracker and before relying
on status. Recorded scan files do not establish current chain membership.
"""
import json
from pathlib import Path
import sqlite3
import tempfile

from transfer_lab import Policy, TransferError, canonical, digest, number, verify_envelope
from watchtower import guard, txid

PREFIX = b'ICP-XFER-TN10-V0\0'


def commitment(envelope, policy):
    """Bind the complete signed encrypted envelope and trusted policy.

    Validate signatures at the manifest's claimed issue time. This permits
    historical inspection; status() separately checks the current permission.
    """
    verify_envelope(envelope, policy, envelope['manifest']['issued_at'])
    body = {'version': 'icp-transfer-anchor-v0', 'network': 'testnet-10',
            'policy': policy.body(), 'envelope': envelope}
    return (PREFIX + bytes.fromhex(digest('icp/lab/anchor/v0', body))).hex()


class AnchorTracker:
    """One pinned exchange/transaction, durable selected-chain undo history.

    The local DB, clock, policy, bootstrap hash and RPC source are trusted.
    Successors are selected-chain entries after the ACCEPTING block, not DAA
    increments, elapsed seconds, parallel blocks or a finality guarantee.
    """
    def __init__(self, path, policy, envelope, transaction_id, bootstrap,
                 min_successors=10, max_scan_age=30):
        self.ready = False
        self.policy = policy
        # Copy caller-owned material so later mutation cannot change the pin.
        self.envelope = json.loads(canonical(envelope))
        self.payload = commitment(self.envelope, policy)
        self.transaction_id = txid(transaction_id)
        self.bootstrap = txid(bootstrap)
        self.min_successors = number(min_successors)
        self.max_scan_age = number(max_scan_age)
        if not 1 <= self.min_successors <= 100000 or not 1 <= self.max_scan_age <= 3600:
            raise TransferError('Invalid observation policy')
        config = canonical({'payload': self.payload, 'transaction_id': transaction_id,
                            'bootstrap': bootstrap, 'min_successors': min_successors,
                            'max_scan_age': max_scan_age}).decode('ascii')
        self.db = sqlite3.connect(path, timeout=5)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS anchor_meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS anchor_blocks(
            position INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE,
            matched INTEGER NOT NULL CHECK(matched IN (0,1)));
        ''')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            previous = self._get('config')
            if previous is not None and previous != config:
                raise TransferError('Anchor database configuration mismatch')
            self._put('config', config)
            self.db.commit()
        except Exception:
            self.db.rollback(); self.db.close(); raise

    def _get(self, key):
        row = self.db.execute('SELECT v FROM anchor_meta WHERE k=?', (key,)).fetchone()
        return row[0] if row else None

    def _put(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO anchor_meta VALUES(?,?)', (key, str(value)))

    @property
    def tip(self):
        row = self.db.execute('SELECT hash FROM anchor_blocks ORDER BY position DESC LIMIT 1').fetchone()
        return row[0] if row else self.bootstrap

    def unavailable(self):
        """Invalidate cached status BEFORE any RPC attempt (including timeouts)."""
        self.ready = False

    def apply(self, response, observed_at):
        """Atomically apply one complete bounded native scan page.

        observed_at is the trusted caller's LOCAL fetch time, never a value
        extracted from an untrusted scan file. Any failure disables status.
        """
        self.unavailable()
        observed_at = number(observed_at)
        guard(response['node'])
        start = txid(response['from']); target = txid(response['target'])
        changes = response['changes']
        added = changes['addedChainBlockHashes']
        removed = changes['removedChainBlockHashes']
        blocks = changes['chainBlockAcceptedTransactions']
        if not all(type(v) is list for v in (added, removed, blocks)):
            raise TransferError('Invalid scan lists')
        if len(added) > 4096 or len(removed) > 2048 or len(blocks) != len(added):
            raise TransferError('Scan page exceeds local budget or is incomplete')
        for value in added + removed: txid(value)
        if len(set(added)) != len(added) or len(set(removed)) != len(removed):
            raise TransferError('Duplicate chain entries')
        if [b['chainBlockHeader']['hash'] for b in blocks] != added:
            raise TransferError('Incomplete or unordered accepted-chain response')
        total = 0; matches = []; seen = set()
        for block in blocks:
            transactions = block['acceptedTransactions']
            if type(transactions) is not list:
                raise TransferError('Missing accepted transactions')
            total += len(transactions)
            if total > 100000:
                raise TransferError('Scan transaction budget exceeded')
            matched = False
            for transaction in transactions:
                ident = txid(transaction['verboseData']['transactionId'])
                if ident in seen:
                    raise TransferError('Duplicate accepted transaction')
                seen.add(ident)
                if ident == self.transaction_id:
                    if transaction.get('payload') != self.payload:
                        raise TransferError('Pinned transaction commitment mismatch')
                    matched = True
            matches.append(matched)
        if not added and not removed and start != target:
            raise TransferError('Scan made no progress toward sampled target')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            if start != self.tip:
                raise TransferError('Stale scan cursor')
            prior_time = self._get('observed_at')
            if prior_time is not None and observed_at < int(prior_time):
                raise TransferError('Observation clock moved backwards')
            for value in removed:
                if value != self.tip or value == self.bootstrap:
                    raise TransferError('Reorg crosses bootstrap or removes wrong tip; reconcile history')
                self.db.execute('DELETE FROM anchor_blocks WHERE hash=?', (value,))
            row = self.db.execute('SELECT MAX(position) FROM anchor_blocks').fetchone()
            position = row[0] or 0
            for value, matched in zip(added, matches):
                if value == self.bootstrap:
                    raise TransferError('Bootstrap cannot be added again')
                if matched and self.db.execute('SELECT 1 FROM anchor_blocks WHERE matched=1').fetchone():
                    raise TransferError('Transaction already accepted on tracked branch')
                position += 1
                self.db.execute('INSERT INTO anchor_blocks VALUES(?,?,?)', (position, value, int(matched)))
            reached = target == self.bootstrap or bool(self.db.execute(
                'SELECT 1 FROM anchor_blocks WHERE hash=?', (target,)).fetchone())
            self._put('observed_at', observed_at)
            self._put('target', target)
            self._put('target_reached', int(reached))
            self.db.commit()
        except Exception:
            self.db.rollback(); raise
        self.ready = True

    def status(self, now):
        now = number(now)
        row = self.db.execute('SELECT position,hash FROM anchor_blocks WHERE matched=1').fetchone()
        top = self.db.execute('SELECT MAX(position) FROM anchor_blocks').fetchone()[0] or 0
        successors = top - row[0] if row else 0
        observed = self._get('observed_at')
        state = 'SCAN_REQUIRED'
        if self.ready and observed is not None:
            if not 0 <= now - int(observed) <= self.max_scan_age:
                state = 'STALE'
            elif self._get('target_reached') != '1':
                state = 'CHAIN_BACKLOG'
            else:
                try:
                    verify_envelope(self.envelope, self.policy, now)
                except TransferError:
                    state = 'PERMISSION_INACTIVE'
                else:
                    state = ('NOT_FOUND' if not row else 'WAITING_SUCCESSORS'
                             if successors < self.min_successors else 'OBSERVED_COMMITMENT')
        return {'mode': 'TRUSTED_NODE_OBSERVATION_ONLY', 'state': state,
                'network': 'testnet-10', 'sampled_target': self._get('target'),
                'transaction_id': self.transaction_id, 'payload': self.payload,
                'accepting_block': row[1] if row else None, 'tip': self.tip,
                'selected_chain_successors': successors,
                'required_successors': self.min_successors,
                'observed_at': int(observed) if observed is not None else None}

    def scan(self, native, clock):
        """Fetch ONLY `scan`, invalidating status before a possibly failing RPC.

        Use the repository's Native read adapter and a trusted integer clock.
        No recovery, signing, broadcasting or receipt/key delivery is invoked.
        """
        self.unavailable()
        try:
            started = number(clock())
            response = native.call('scan', self.tip)
            self.apply(response, started)
            return self.status(clock())
        except Exception:
            self.unavailable(); raise

    def close(self):
        self.ready = False
        self.db.close()


def demo():
    """Replay the public exchange against explicitly fabricated chain entries."""
    source = Path(__file__).resolve().parents[1] / 'evidence/transfer-lab-demo.json'
    transcript = json.loads(source.read_text())
    p = transcript['policy']
    policy = Policy(p['approver'], p['sender'], p['recipient'], p['max_bytes'], p['max_lifetime'])
    envelope = transcript['envelope']
    at = envelope['manifest']['issued_at'] + 1  # Historical simulated clock.
    def fake_id(n): return f'{n:064x}'
    def page(start, added, removed=(), transactions=()):
        return {'node': {'networkId': 'testnet-10', 'isSynced': True,
                         'hasUtxoIndex': True, 'virtualDaaScore': 467579700},
                'from': fake_id(start), 'target': fake_id(added[-1]),
                'changes': {'addedChainBlockHashes': [fake_id(n) for n in added],
                            'removedChainBlockHashes': [fake_id(n) for n in removed],
                            'chainBlockAcceptedTransactions': [
                                {'chainBlockHeader': {'hash': fake_id(n)},
                                 'acceptedTransactions': list(transactions) if n == 1 else []}
                                for n in added]}}
    with tempfile.TemporaryDirectory() as directory:
        tracker = AnchorTracker(Path(directory) / 'anchor.sqlite', policy, envelope,
                                fake_id(900), fake_id(0), min_successors=2)
        try:
            transaction = {'verboseData': {'transactionId': fake_id(900)}, 'payload': tracker.payload}
            snapshots = [tracker.status(at)]
            for response in (page(0, [1], transactions=[transaction]),
                             page(1, [2, 3]), page(3, [4], removed=[3, 2, 1])):
                tracker.apply(response, at)
                snapshots.append(tracker.status(at))
            if [s['state'] for s in snapshots] != [
                    'SCAN_REQUIRED', 'WAITING_SUCCESSORS', 'OBSERVED_COMMITMENT', 'NOT_FOUND']:
                raise TransferError('Synthetic anchor demo failed')
            return {'mode': 'SYNTHETIC_CHAIN_NO_RPC_NO_FUNDS',
                    'source': 'evidence/transfer-lab-demo.json', 'snapshots': snapshots}
        finally:
            tracker.close()


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2))
