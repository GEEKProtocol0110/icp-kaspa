#!/usr/bin/env python3
"""Read-only trusted-node ticket history. No signer, broadcast or release API."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from watchtower import guard, txid, integer, WatchError

ROOT = Path(__file__).resolve().parents[1]
MODE = 'TRUSTED_NODE_TICKET_OBSERVATION_ONLY'


class ObservationError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def decode(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result: raise ObservationError('Duplicate JSON field')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ObservationError('Invalid JSON constant')))


def point(value):
    ident, index = txid(value['transactionId']), integer(value['index'])
    if index >= 2**32: raise ObservationError('Invalid output index')
    return ident, index


def endpoint_host(endpoint):
    p = urlsplit(endpoint)
    if p.scheme != 'wss' or not p.hostname or p.path != '/kaspa/testnet-10/wrpc/borsh' or p.username or p.password or p.query or p.fragment:
        raise ObservationError('Expected a public TN10 TLS Borsh endpoint')
    return p.hostname


class Reader:
    """One binary exposes only project/scan/utxos. Never uses the private worker."""
    def __init__(self, endpoint=None, binary=None):
        self.endpoint = endpoint
        if endpoint is not None: endpoint_host(endpoint)
        self.binary = Path(binary or ROOT / 'target/debug/examples/ticket_read').resolve()
        try: self.fingerprint = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        except OSError as exc: raise ObservationError('Build the read-only ticket_read example first') from exc

    def _run(self, args, raw=None, network=False):
        if hashlib.sha256(self.binary.read_bytes()).hexdigest() != self.fingerprint:
            raise ObservationError('Pinned read-only binary changed')
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY')}
        command = [str(self.binary), *args]
        if network:
            if self.endpoint is None: raise ObservationError('No pinned endpoint')
            env['ICP_UPSTREAM_URL'] = self.endpoint
            command = [sys.executable, str(ROOT / 'scripts/with_proxy.py'), *command]
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try: stdout, _ = process.communicate(raw, timeout=55 if network else 15)
        except BaseException:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.communicate(); raise
        if process.returncode or len(stdout) > (32_000_000 if network else 262_144):
            raise ObservationError('Read-only native call failed or exceeded local reply limit')
        return decode(stdout)

    def project(self, transaction):
        raw = canonical(transaction)
        if len(raw) > 262_144: raise ObservationError('Relevant native transaction too large')
        return self._run(['project'], raw)

    def project_p0(self, transaction):
        raw = canonical(transaction)
        if len(raw) > 262_144: raise ObservationError('Relevant P0 transaction too large')
        return self._run(['project-p0'], raw)

    def scan(self, cursor):
        return self._run(['scan', txid(cursor)], network=True)

    def utxos(self, public_key):
        txid(public_key)
        return self._run(['utxos', public_key], network=True)

    def snapshot_p0(self, cursor, funding_key, ticket_key):
        request = dict(cursor=txid(cursor), funding_key=txid(funding_key), ticket_key=txid(ticket_key))
        if funding_key == ticket_key: raise ObservationError('Distinct snapshot roles required')
        value = self._run(['observe-p0'], canonical(request), network=True)
        try:
            if (type(value) is not dict or set(value) != {'mode','source','ticket','scan'}
                or value['mode'] != 'TN10_P0_READ_SNAPSHOT_V1'):
                raise ObservationError('Wrong P0 snapshot profile')
            source,ticket,scan = (value[k] for k in ('source','ticket','scan'))
            if (source['publicKey'] != funding_key or ticket['publicKey'] != ticket_key
                or scan['from'] != cursor or scan['target'] != source['target']
                or source['from'] != ticket['from'] or source['target'] != ticket['target']
                or source['node'] != ticket['node'] or source['node'] != scan['node']):
                raise ObservationError('Snapshot roles, brackets or node samples differ')
            guard(scan['node'])
        except (KeyError,TypeError,WatchError) as exc:
            raise ObservationError('Malformed P0 snapshot') from exc
        return value

    def bootstrap_p0(self):
        value = self._run(['bootstrap-p0'], network=True)
        try:
            if (type(value) is not dict
                or set(value) != {'mode','node','bootstrap','sampled_sink','parent_steps','scope'}
                or value['mode'] != 'TN10_P0_BOOTSTRAP_CANDIDATE_V1'
                or type(value['parent_steps']) is not int or value['parent_steps'] != 20
                or value['scope'] != 'TRUSTED_NODE_CANDIDATE_NOT_FINALITY'):
                raise ObservationError('Wrong P0 bootstrap profile')
            guard(value['node']); txid(value['bootstrap']); txid(value['sampled_sink'])
            if value['bootstrap'] == value['sampled_sink']:
                raise ObservationError('Bootstrap must precede sampled sink')
        except (KeyError,TypeError,WatchError) as exc:
            raise ObservationError('Malformed P0 bootstrap candidate') from exc
        return value


def expected(summary):
    """Trusted fixture pins, not authorization. Project RPC candidates independently."""
    p = summary['plan']
    if p['network'] != 'testnet-10' or summary['mode'] != 'OFFLINE_NATIVE_FIXTURES_NO_CHAIN_NO_AUTHORIZATION':
        raise ObservationError('Expected explicit native fixture pins')
    return dict(transaction_id=txid(summary['transaction_id']), version=1,
                inputs=[dict(transaction_id=txid(summary['input']['transaction_id']),
                             index=integer(summary['input']['index']), sequence=0)],
                outputs=[dict(value=integer(o['amount']), script_version=0, script=o['script'], covenant=None)
                         for o in summary['outputs']], lock_time=0, subnetwork_id='00' * 20,
                gas=0, payload=summary['payload'])


class TicketTracker:
    observation_mode = MODE

    def __init__(self, path, summaries, endpoint, bootstrap, *, reader=None, min_successors=10, max_age=30):
        self.path = Path(path).resolve()
        self.endpoint, self.host = endpoint, endpoint_host(endpoint)
        self.reader = reader or Reader(endpoint)
        self.bootstrap = txid(bootstrap)
        self.depth, self.max_age = integer(min_successors), integer(max_age)
        if not 1 <= self.depth <= 100000 or not 1 <= self.max_age <= 300:
            raise ObservationError('Invalid ticket observation policy')
        self.summaries = deepcopy(summaries)
        self.pins, self.ticket_key = self._prepare_pins(self.summaries)
        if self.pins['issue']['outputs'][0]['script'] != '20' + self.ticket_key + 'ac':
            raise ObservationError('Ticket query key differs from pinned output script')
        self.issue_id = self.pins['issue']['transaction_id']
        self.funding = self.pins['issue']['inputs'][0]
        self.ticket = (self.issue_id, 0)
        if len(self.pins['issue']['outputs']) != 2 or any(len(self.pins[a]['outputs']) != 1 for a in ('consume', 'refund')):
            raise ObservationError('Wrong fixture output layout')
        if any((self.pins[a]['inputs'][0]['transaction_id'], self.pins[a]['inputs'][0]['index']) != self.ticket for a in ('consume', 'refund')):
            raise ObservationError('Terminal pins do not spend exact ticket')
        self.pin_id = hashlib.sha256(canonical(self._pin_identity())).hexdigest()
        config = canonical(dict(mode=self.observation_mode, pin=self.pin_id, endpoint=endpoint, bootstrap=bootstrap,
                                reader=self.reader.fingerprint)).decode()
        self.ready, self.utxo_sample = False, None
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS ticket_meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS ticket_blocks(position INTEGER PRIMARY KEY,hash TEXT UNIQUE NOT NULL,events TEXT NOT NULL);''')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            if self._get('config') not in (None, config): raise ObservationError('Observer database configuration changed')
            self._put('config', config)
            # A newly opened handle invalidates older handles and cached samples.
            self.session = os.urandom(16).hex(); self._put('session', self.session)
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); self.db.close(); raise

    def _prepare_pins(self, summaries):
        if set(summaries) != {'issue', 'consume', 'refund'}:
            raise ObservationError('Exactly three native fixture pins required')
        pins = {a: expected(s) for a, s in summaries.items()}
        if any(s['action'] != a or s['plan']['action'] != a for a, s in summaries.items()) or len({p['transaction_id'] for p in pins.values()}) != 3:
            raise ObservationError('Distinct correctly labeled transaction pins required')
        return pins, txid(summaries['issue']['plan']['ticket_key'])

    def _pin_identity(self):
        return dict(pins=self.pins, depth=self.depth, age=self.max_age)

    def _project(self, transaction):
        return self.reader.project(transaction)

    def _get(self, key):
        r = self.db.execute('SELECT v FROM ticket_meta WHERE k=?', (key,)).fetchone()
        return r[0] if r else None

    def _put(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO ticket_meta VALUES(?,?)', (key, str(value)))

    def _clock(self, now):
        now = integer(now)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if self._get('session') != self.session: raise ObservationError('Observer handle superseded; reopen and rescan')
            previous = self._get('clock')
            halted = self._get('clock_halted') == '1' or previous is not None and now < int(previous)
            if halted: self._put('clock_halted', 1)
            else: self._put('clock', now)
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); raise
        if halted:
            self.unavailable(); raise ObservationError('Observation clock continuity lost')
        return now

    @property
    def tip(self):
        r = self.db.execute('SELECT hash FROM ticket_blocks ORDER BY position DESC LIMIT 1').fetchone()
        return r[0] if r else self.bootstrap

    def unavailable(self):
        self.ready, self.utxo_sample = False, None

    def _history(self):
        state = dict(issue=None, funding=None, spend=None)
        for position, block, raw in self.db.execute('SELECT position,hash,events FROM ticket_blocks ORDER BY position'):
            for event in decode(raw): self._event(state, event, position, block)
        return state

    def _event(self, state, event, position, block):
        kind, ident = event['kind'], event['transaction_id']
        if kind in ('issue', 'unexpected_funding'):
            if state['funding'] is not None: raise ObservationError('Conflicting accepted funding spends')
            state['funding'] = ident
            if kind == 'issue': state['issue'] = dict(position=position, block=block, transaction_id=ident)
        else:
            if state['issue'] is None or state['spend'] is not None:
                raise ObservationError('Missing creation history or conflicting ticket spends')
            state['spend'] = dict(kind=kind, position=position, block=block, transaction_id=ident)

    def apply(self, response, observed_at):
        self.unavailable(); at = self._clock(observed_at)
        try:
            guard(response['node']); start, target = txid(response['from']), txid(response['target'])
            changes = response['changes']; added = changes['addedChainBlockHashes']; removed = changes['removedChainBlockHashes']
            blocks = changes['chainBlockAcceptedTransactions']
            if any(type(v) is not list for v in (added, removed, blocks)) or len(added) > 4096 or len(removed) > 2048 or len(blocks) != len(added):
                raise ObservationError('Incomplete or oversized scan page')
            for b in added + removed: txid(b)
            if len(set(added)) != len(added) or len(set(removed)) != len(removed) or [b['chainBlockHeader']['hash'] for b in blocks] != added:
                raise ObservationError('Duplicate/unordered chain blocks')
            if not added and not removed and start != target: raise ObservationError('No progress to sampled target')
            seen, total, relevant, parsed = set(), 0, 0, []
            for block in blocks:
                txs = block['acceptedTransactions']
                if type(txs) is not list: raise ObservationError('Missing accepted transactions')
                total += len(txs)
                if total > 100000: raise ObservationError('Scan transaction limit')
                events = []
                for tx in txs:
                    ident = txid(tx['verboseData']['transactionId'])
                    if ident in seen: raise ObservationError('Duplicate accepted transaction')
                    seen.add(ident)
                    if type(tx['inputs']) is not list: raise ObservationError('Missing native inputs')
                    inputs = [point(i['previousOutpoint']) for i in tx['inputs']]
                    hits = [a for a, p in self.pins.items() if p['transaction_id'] == ident]
                    funding_hit = (self.funding['transaction_id'], self.funding['index']) in inputs
                    ticket_hit = self.ticket in inputs
                    if not hits and not funding_hit and not ticket_hit: continue
                    relevant += 1
                    if relevant > 32: raise ObservationError('Too many relevant spends in one page')
                    projection = self._project(tx)
                    if hits:
                        action = hits[0]
                        if canonical(projection) != canonical(self.pins[action]): raise ObservationError('Pinned native transaction body mismatch')
                        kind = action
                    else:
                        kind = 'unexpected_funding' if funding_hit else 'unexpected_ticket'
                    events.append(dict(kind=kind, transaction_id=projection['transaction_id']))
                # Acceptance lists need not order a parent before its child within one block.
                events.sort(key=lambda e: e['kind'] != 'issue')
                parsed.append(events)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                if self._get('session') != self.session: raise ObservationError('Observer superseded while parsing scan')
                if start != self.tip: raise ObservationError('Stale observer scan cursor')
                for ident in removed:
                    if ident == self.bootstrap or ident != self.tip: raise ObservationError('Wrong reorg order or missing bootstrap history')
                    self.db.execute('DELETE FROM ticket_blocks WHERE hash=?', (ident,))
                state = self._history()
                position = self.db.execute('SELECT MAX(position) FROM ticket_blocks').fetchone()[0] or 0
                for ident, events in zip(added, parsed):
                    if ident == self.bootstrap: raise ObservationError('Bootstrap cannot be added')
                    position += 1
                    for event in events: self._event(state, event, position, ident)
                    self.db.execute('INSERT INTO ticket_blocks VALUES(?,?,?)', (position, ident, canonical(events).decode()))
                reached = target == self.bootstrap or self.db.execute('SELECT 1 FROM ticket_blocks WHERE hash=?', (target,)).fetchone()
                self._put('target', target); self._put('reached', int(bool(reached))); self._put('observed_at', at)
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK'); raise
            self.ready = True
        except (KeyError, TypeError, WatchError) as exc:
            raise ObservationError('Malformed or unhealthy native scan') from exc

    def apply_utxos(self, response, observed_at):
        self.utxo_sample = None; at = self._clock(observed_at)
        try:
            guard(response['node'])
            if response['publicKey'] != self.ticket_key or type(response['utxos']) is not list or len(response['utxos']) > 100000:
                raise ObservationError('Wrong UTXO query or oversized reply')
            before, after = txid(response['from']), txid(response['target'])
            found, seen = False, set()
            for value in response['utxos']:
                outpoint = point(value['outpoint'])
                if outpoint in seen: raise ObservationError('Duplicate UTXO')
                seen.add(outpoint)
                if outpoint == self.ticket:
                    u = value['utxoEntry']; expected = self.pins['issue']['outputs'][0]
                    if integer(u['amount']) != expected['value'] or u['scriptPublicKey'] != '0000' + expected['script'] or u['isCoinbase'] is not False or u.get('covenantId') is not None:
                        raise ObservationError('Exact live ticket UTXO mismatch')
                    found = True
            self.utxo_sample = dict(at=at, before=before, after=after, found=found)
        except (KeyError, TypeError, WatchError) as exc:
            raise ObservationError('Malformed or unhealthy UTXO sample') from exc

    def _position(self, ident):
        if ident == self.bootstrap: return 0
        r = self.db.execute('SELECT position FROM ticket_blocks WHERE hash=?', (ident,)).fetchone()
        return r[0] if r else None

    def status(self, now):
        now = self._clock(now); state = self._history()
        top = self._position(self.tip); issue, spend = state['issue'], state['spend']
        depth = top - issue['position'] if issue else 0
        terminal_depth = top - spend['position'] if spend else 0
        at = self._get('observed_at'); label = 'SCAN_REQUIRED'
        u = self.utxo_sample
        sample_ok = u is not None and 0 <= now - u['at'] <= self.max_age
        positions = [self._position(u[k]) for k in ('before', 'after')] if sample_ok else [None, None]
        sample_ok = sample_ok and None not in positions and positions[0] <= positions[1]
        if self.ready and at is not None:
            if not 0 <= now - int(at) <= self.max_age: label = 'STALE'
            elif self._get('reached') != '1': label = 'CHAIN_BACKLOG'
            elif issue is None: label = 'UNEXPECTED_FUNDING_SPEND' if state['funding'] else 'ISSUE_NOT_FOUND'
            elif spend and spend['kind'] == 'unexpected_ticket': label = 'UNEXPECTED_TICKET_SPEND'
            elif depth < self.depth or spend and terminal_depth < self.depth: label = 'WAITING_SUCCESSORS'
            elif spend:
                label = 'CONSUMPTION_OBSERVED' if spend['kind'] == 'consume' else 'REFUND_OBSERVED'
                if sample_ok and u['found'] and spend['position'] <= positions[0]: label = 'INCONSISTENT_UTXO_VIEW'
            elif not sample_ok: label = 'UTXO_SAMPLE_REQUIRED'
            elif not u['found']: label = 'TICKET_NOT_UNSPENT'
            elif issue['position'] > positions[0]: label = 'UTXO_SAMPLE_PREDATES_ISSUE'
            else: label = 'ISSUED_UNSPENT_OBSERVED'
        return dict(mode=self.observation_mode, state=label, endpoint=self.endpoint, pin_id=self.pin_id, tip=self.tip,
                    sampled_target=self._get('target'), observed_at=int(at) if at else None,
                    issue=issue, spend=spend, issue_successors=depth, terminal_successors=terminal_depth,
                    required_successors=self.depth, utxo_sample=deepcopy(u))

    def poll(self, native, clock):
        self.unavailable()
        if type(native) is not Reader or native.endpoint != self.endpoint or native.fingerprint != self.reader.fingerprint:
            raise ObservationError('Wrong read-only endpoint/adapter')
        try:
            at = integer(clock()); utxos = native.utxos(self.ticket_key)
            started = integer(clock()); scan = native.scan(self.tip)
            self.apply_utxos(utxos, at); sample = self.utxo_sample
            self.apply(scan, started); self.utxo_sample = sample
            return self.status(clock())
        except BaseException:
            self.unavailable(); raise

    def close(self):
        self.unavailable(); self.db.close()


def combined(first, second, now):
    if any(type(t) is not TicketTracker for t in (first, second)):
        raise ObservationError('LAB0 combination requires exact fixture trackers')
    if first.path == second.path or first.host == second.host or first.pin_id != second.pin_id:
        raise ObservationError('Two distinct pinned node hosts/databases with matching policy required')
    a, b = first.status(now), second.status(now)
    eligible = a['state'] == b['state'] and a['state'] in ('ISSUED_UNSPENT_OBSERVED', 'CONSUMPTION_OBSERVED', 'REFUND_OBSERVED')
    return dict(mode=MODE, state='TWO_NODE_' + a['state'] if eligible else 'TWO_NODE_GATE_BLOCKED', observations=[a, b])


def fixture_pins():
    data = decode((ROOT / 'evidence/native-ticket-lab-demo.json').read_bytes())
    return {x['action']: x for x in data['examples']}


def fixture_rpc(summary):
    """Unsigned fabricated RPC body; native ID excludes these signature bytes."""
    p = expected(summary)
    return dict(version=p['version'], inputs=[dict(previousOutpoint=dict(transactionId=i['transaction_id'], index=i['index']),
                sequence=i['sequence'], signatureScript='', computeBudget=100, sigOpCount=0, verboseData=None) for i in p['inputs']],
                outputs=[dict(value=o['value'], scriptPublicKey='0000'+o['script'], covenant=None, verboseData=None) for o in p['outputs']],
                lockTime=0, subnetworkId='00'*20, gas=0, payload=p['payload'], storageMass=summary['storage_mass'],
                verboseData=dict(transactionId=p['transaction_id']))


def fake_id(n):
    return f'{n:064x}'


def fixture_scan(start, added=(), removed=(), transactions=None, target=None):
    return dict(node=dict(networkId='testnet-10', isSynced=True, hasUtxoIndex=True, virtualDaaScore=467579700),
                **{'from':fake_id(start)}, target=fake_id(target if target is not None else added[-1] if added else start),
                changes=dict(addedChainBlockHashes=[fake_id(n) for n in added], removedChainBlockHashes=[fake_id(n) for n in removed],
                chainBlockAcceptedTransactions=[dict(chainBlockHeader=dict(hash=fake_id(n)),
                    acceptedTransactions=(transactions or {}).get(n, [])) for n in added]))


def fixture_utxos(pins, before=1, after=None, found=True):
    output = pins['issue']['outputs'][0]
    return dict(node=fixture_scan(0)['node'], publicKey=pins['issue']['plan']['ticket_key'],
                **{'from':fake_id(before)}, target=fake_id(before if after is None else after),
                utxos=[dict(outpoint=dict(transactionId=pins['issue']['transaction_id'],index=0),
                    utxoEntry=dict(amount=output['amount'], scriptPublicKey='0000'+output['script'],
                                   isCoinbase=False, covenantId=None, blockDaaScore=467579700))] if found else [])


def demo():
    pins = fixture_pins(); reader = Reader()
    with tempfile.TemporaryDirectory() as tmp:
        trackers = [TicketTracker(Path(tmp)/f'node-{i}.sqlite', pins,
                    f'wss://synthetic-{i}.invalid/kaspa/testnet-10/wrpc/borsh', fake_id(0), reader=reader, min_successors=2) for i in range(2)]
        try:
            for t in trackers:
                t.apply(fixture_scan(0,[1,2,3], transactions={1:[fixture_rpc(pins['issue'])]}),100)
                t.apply_utxos(fixture_utxos(pins),100)
            issued = combined(*trackers,100)
            for t in trackers:
                t.apply(fixture_scan(3,[4,5,6],transactions={4:[fixture_rpc(pins['consume'])]}),101)
            consumed = combined(*trackers,101)
            for t in trackers:
                t.apply(fixture_scan(6,[7,8,9],removed=[6,5,4],transactions={7:[fixture_rpc(pins['refund'])]}),102)
            refunded = combined(*trackers,102)
            assert [s['state'] for s in (issued,consumed,refunded)] == [
                'TWO_NODE_ISSUED_UNSPENT_OBSERVED','TWO_NODE_CONSUMPTION_OBSERVED','TWO_NODE_REFUND_OBSERVED']
            return dict(mode='SYNTHETIC_TICKET_SCANS_NO_RPC_NO_FUNDS', rpc_calls=0,broadcasts=0,signatures_created=0,
                        snapshots=[issued,consumed,refunded])
        finally:
            for t in trackers: t.close()


if __name__ == '__main__':
    print(json.dumps(demo(),indent=2,sort_keys=True))
