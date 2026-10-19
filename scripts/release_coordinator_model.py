#!/usr/bin/env python3
"""Synthetic recovery model. No keys, encryption, signatures, RPC or transport.

All four stores and the independent authority are trusted local SQLite fakes.
Model labels stand in for already-authorized identity, record and ticket inputs.
See docs/RELEASE-COORDINATOR-MODEL.md before interpreting the results.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile

MODE = 'SYNTHETIC_COORDINATOR_NO_KEYS_NO_CHAIN'
ROLES = ('ledger', 'vault', 'delivery')


class ModelError(ValueError):
    pass


class IntegrityError(ModelError):
    pass


class RecoveryRequired(ModelError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(b'icp/coordinator-model/v0\0' + canonical(value)).hexdigest()


def integer(value):
    if type(value) is not int or not 0 <= value < 2**53:
        raise ModelError('Invalid model integer')
    return value


def label(value):
    if not isinstance(value, str) or not re.fullmatch(r'model:[a-zA-Z0-9_./:-]{1,90}', value):
        raise ModelError('Synthetic model labels required')
    return value


@dataclass(frozen=True)
class Policy:
    service: str = 'model:service'
    budget: str = 'model:budget'
    count_limit: int = 4
    byte_limit: int = 1024
    freshness: int = 5

    def __post_init__(self):
        label(self.service); label(self.budget)
        for value in (self.count_limit, self.byte_limit, self.freshness):
            if not integer(value):
                raise ModelError('Positive model limit required')

    @property
    def id(self):
        return digest({'mode': MODE, 'policy': asdict(self)})


@dataclass(frozen=True)
class Context:
    """Trusted harness admission, NOT a signed grant or an accepted-chain proof."""
    grant: str = 'model:grant'
    record: str = 'model:record/version-1'
    cipher: str = 'model:cipher-digest'
    request: str = 'model:approved-recipient-request'
    recipient: str = 'model:recipient'
    binding: str = 'model:delivery-certificate'
    ticket: str = 'model:issue/outpoint-0'
    consume: str = 'model:exact-consume'
    challenge: str = 'model:request-challenge'
    size: int = 128
    policy_epoch: int = 0
    delivery_epoch: int = 0
    not_before: int = 100
    expires: int = 200
    window_start: int = 100
    window_end: int = 180

    def __post_init__(self):
        for name, value in asdict(self).items():
            label(value) if name in ('grant', 'record', 'cipher', 'request', 'recipient',
                                    'binding', 'ticket', 'consume', 'challenge') else integer(value)
        if not self.size or not self.window_start <= self.not_before < min(self.expires, self.window_end):
            raise ModelError('Invalid original budget window/deadline')


def connect(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.execute('PRAGMA synchronous=FULL')
    return db


@dataclass
class Lease:
    authority: object
    generation: int
    now: int
    active: bool = True

    def check(self):
        if not self.active or not self.authority.db.in_transaction:
            raise ModelError('Inactive enforcing-boundary lease')
        generation, halted = self.authority.db.execute('SELECT generation,halted FROM meta').fetchone()
        if halted or generation != self.generation:
            raise ModelError('Halted authority or fenced writer')


class Authority:
    """Independent trusted serialization/checkpoint fake; never restore with stores."""
    def __init__(self, path, policy, clock, create=False):
        self.clock = clock
        if not create and not Path(path).is_file():
            raise IntegrityError('Missing independent authority; no automatic reset')
        self.db = connect(path)
        if create:
            self.db.executescript('''CREATE TABLE meta(policy TEXT,generation INTEGER,
                last_clock INTEGER,halted INTEGER,ready INTEGER,identity TEXT);
                CREATE TABLE checkpoints(role TEXT,seq INTEGER,hash TEXT,
                PRIMARY KEY(role,seq));''')
            self.db.execute('INSERT INTO meta VALUES(?,0,0,0,0,?)',
                            (policy.id, 'model:authority-' + secrets.token_hex(16)))
        if self.db.execute('SELECT policy FROM meta').fetchone() != (policy.id,):
            self.db.close()
            raise IntegrityError('Authority policy mismatch')
        self.id = self.db.execute('SELECT identity FROM meta').fetchone()[0]

    def _time(self):
        try:
            now = integer(self.clock())
        except Exception as exc:
            self.db.execute('UPDATE meta SET halted=1')
            raise ModelError('Uncertain clock; authority halted') from exc
        previous = self.db.execute('SELECT last_clock FROM meta').fetchone()[0]
        if now < previous:
            self.db.execute('UPDATE meta SET halted=1')
            raise ModelError('Backward clock; authority halted')
        self.db.execute('UPDATE meta SET last_clock=?', (now,))
        return now

    @contextmanager
    def serial(self, generation=None, recovery=False):
        self.db.execute('BEGIN IMMEDIATE')
        lease = None
        try:
            current, halted, ready = self.db.execute('SELECT generation,halted,ready FROM meta').fetchone()
            if halted or (generation is not None and generation != current):
                raise ModelError('Halted authority or fenced writer')
            now = self._time()
            if not recovery and not ready:
                raise RecoveryRequired('Recovery verification required')
            lease = Lease(self, current, now)
            yield lease
        except IntegrityError:
            self.db.execute('UPDATE meta SET halted=1,ready=0')
            raise
        finally:
            try:
                if lease is not None:
                    lease.active = False
                    self._time()
            finally:
                # Accepted checkpoints and observed clock progress survive failed requests.
                # An actual process crash before COMMIT leaves the local event unacknowledged.
                self.db.execute('COMMIT')

    def acquire(self):
        with self.serial(recovery=True):
            self.db.execute('UPDATE meta SET generation=generation+1,ready=0')
            return self.db.execute('SELECT generation FROM meta').fetchone()[0]

    def checkpoint(self, lease, role, seq, event_hash):
        lease.check()
        old = self.db.execute('SELECT hash FROM checkpoints WHERE role=? AND seq=?', (role, seq)).fetchone()
        if old and old != (event_hash,):
            raise IntegrityError('Conflicting independent checkpoint')
        self.db.execute('INSERT OR IGNORE INTO checkpoints VALUES(?,?,?)', (role, seq, event_hash))


class Journal:
    """Private component state snapshots with a hash-chained append-only history."""
    def __init__(self, path, role, policy, authority_id, initial, create=False):
        self.role, self.policy, self.authority_id = role, policy.id, authority_id
        if not create and not Path(path).is_file():
            raise IntegrityError('Missing component store')
        self.db = connect(path)
        if create:
            self.db.executescript('''CREATE TABLE meta(role TEXT,policy TEXT,authority TEXT);
                CREATE TABLE events(seq INTEGER PRIMARY KEY,body TEXT,hash TEXT);''')
            self.db.execute('INSERT INTO meta VALUES(?,?,?)', (role, policy.id, authority_id))
            body = self._body(0, '', 'genesis', initial)
            self.db.execute('INSERT INTO events VALUES(0,?,?)', (canonical(body).decode(), digest(body)))
        if self.db.execute('SELECT role,policy,authority FROM meta').fetchone() != (role, policy.id, authority_id):
            self.db.close()
            raise IntegrityError('Component role/policy/authority mismatch')

    def _body(self, seq, previous, kind, state):
        return dict(mode=MODE, role=self.role, policy=self.policy, authority=self.authority_id, seq=seq,
                    previous=previous, kind=kind, state=state)

    def _check(self, lease):
        lease.check()
        if lease.authority.id != self.authority_id:
            raise IntegrityError('Foreign fencing/checkpoint authority')

    def load(self, lease, reconcile=False):
        self._check(lease)
        rows = self.db.execute('SELECT seq,body,hash FROM events ORDER BY seq').fetchall()
        previous = ''
        for index, (seq, raw, event_hash) in enumerate(rows):
            try:
                body = json.loads(raw)
                expected = self._body(index, previous, body['kind'], body['state'])
                if (seq != index or body != expected or type(body['state']) is not dict
                        or digest(body) != event_hash):
                    raise IntegrityError('Broken component history')
            except (ValueError, KeyError, TypeError) as exc:
                raise IntegrityError('Broken component history') from exc
            previous = event_hash
        if not rows:
            raise IntegrityError('Empty component history')
        acknowledged = lease.authority.db.execute(
            'SELECT seq,hash FROM checkpoints WHERE role=? ORDER BY seq', (self.role,)).fetchall()
        if not acknowledged or any(seq >= len(rows) or rows[seq][2] != event_hash
                                   for seq, event_hash in acknowledged):
            raise IntegrityError('Restored or conflicting component history')
        if len(acknowledged) != len(rows):
            if not reconcile:
                raise RecoveryRequired('Unacknowledged component event; recover same journal')
            for seq, _, event_hash in rows:
                lease.authority.checkpoint(lease, self.role, seq, event_hash)
        return json.loads(rows[-1][1])['state'], (rows[-1][0], rows[-1][2])

    def save(self, lease, state, kind, previous, hook):
        self._check(lease)
        seq, old_hash = previous
        body = self._body(seq + 1, old_hash, kind, state)
        event_hash = digest(body)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if self.db.execute('SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1').fetchone() != previous:
                raise IntegrityError('Component changed outside serialized writer')
            self.db.execute('INSERT INTO events VALUES(?,?,?)',
                            (seq + 1, canonical(body).decode(), event_hash))
            hook(self.role + ':before_commit')
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise
        hook(self.role + ':saved')
        lease.authority.checkpoint(lease, self.role, seq + 1, event_hash)
        return event_hash


class Coordinator:
    """Trusted in-process coordinator; the public response path is dispatch only."""
    def __init__(self, root, authority_path, policy, clock, *, create=False, hook=None):
        self.root = Path(root)
        self.policy = policy
        self.hook = hook or (lambda stage: None)
        paths = [Path(authority_path)] + [self.root / (role + '.sqlite') for role in ROLES]
        if len({p.resolve() for p in paths}) != 4:
            raise ModelError('Four distinct durable stores required')
        if create and any(p.exists() for p in paths):
            raise ModelError('Refuse to initialize over existing state')
        self.root.mkdir(parents=True, exist_ok=True)
        Path(authority_path).parent.mkdir(parents=True, exist_ok=True)
        self._authority = Authority(authority_path, policy, clock, create)
        initial = {'ledger': dict(grants={}, charges={}, challenges=[], tickets=[],
                                   policy_epoch=0, delivery_epoch=0, revocations=0),
                   'vault': dict(candidates={}), 'delivery': dict(nonces={})}
        self._stores = {}
        try:
            for role in ROLES:
                self._stores[role] = Journal(self.root / (role + '.sqlite'), role, policy,
                                            self._authority.id, initial[role], create)
            if create:
                with self._authority.serial(recovery=True) as lease:
                    for role, store in self._stores.items():
                        seq, event_hash = store.db.execute('SELECT seq,hash FROM events').fetchone()
                        self._authority.checkpoint(lease, role, seq, event_hash)
            self.generation = self._authority.acquire()
        except BaseException:
            self.close()
            raise
        self._observations = {}  # Never restore chain eligibility from a saved cache.

    def close(self):
        for store in self._stores.values():
            store.db.close()
        self._authority.db.close()

    def _load(self, lease, reconcile=False):
        loaded = {role: store.load(lease, reconcile) for role, store in self._stores.items()}
        ledger, vault = loaded['ledger'][0], loaded['vault'][0]
        ledger_history = {event_hash: json.loads(raw)['state'] for raw, event_hash
                          in self._stores['ledger'].db.execute('SELECT body,hash FROM events')}
        for grant, candidate in vault['candidates'].items():
            row = ledger['grants'].get(grant)
            if (not row or row['context_hash'] != candidate['context_hash']
                    or row['authorization'] != candidate['authorization']
                    or candidate['ledger_checkpoint'] not in ledger_history):
                raise IntegrityError('Vault candidate does not match original authorization')
            authorized_row = ledger_history[candidate['ledger_checkpoint']]['grants'].get(grant)
            if (not authorized_row or authorized_row['context_hash'] != row['context_hash']
                    or authorized_row['authorization'] != candidate['authorization']):
                raise IntegrityError('Candidate checkpoint did not authorize this exact operation')
            response = candidate['response']
            if (set(response) != {'mode', 'operation', 'context', 'placeholder'}
                    or response['mode'] != MODE
                    or response['operation'] != [self.policy.service, self.policy.budget, grant]
                    or response['context'] != row['context_hash']
                    or not isinstance(response['placeholder'], str)
                    or not re.fullmatch('[0-9a-f]{32}', response['placeholder'])
                    or digest(response) != candidate['response_hash']):
                raise IntegrityError('Vault response/context digest mismatch')
        for grant, row in ledger['grants'].items():
            if row['response'] is not None:
                candidate = vault['candidates'].get(grant)
                if not candidate or row['response'] != candidate['response'] or row['response_hash'] != candidate['response_hash']:
                    raise IntegrityError('Committed response lacks matching private vault candidate')
        return loaded

    def recover(self):
        with self._authority.serial(self.generation, recovery=True) as lease:
            self._load(lease, reconcile=True)
            self._authority.db.execute('UPDATE meta SET ready=1')
        self._observations.clear()
        self.hook('recovery:acknowledged')

    @contextmanager
    def _step(self):
        with self._authority.serial(self.generation) as lease:
            yield lease, self._load(lease)

    def _save(self, lease, loaded, role, kind):
        state, previous = loaded[role]
        return self._stores[role].save(lease, state, kind, previous, self.hook)

    def _eligible(self, lease, ledger, row, chain=True):
        context = row['context']
        if row['revoked'] or (context['policy_epoch'], context['delivery_epoch']) != (ledger['policy_epoch'], ledger['delivery_epoch']):
            raise ModelError('Revoked grant or inactive policy/delivery epoch')
        if not context['not_before'] <= lease.now < min(context['expires'], context['window_end']):
            raise ModelError('Original deadline/window not eligible')
        if chain:
            sample = self._observations.get(context['grant'])
            if not sample or sample[1] != (True, True) or not 0 <= lease.now - sample[0] <= self.policy.freshness:
                raise ModelError('Two fresh exact synthetic observations required')

    def reserve(self, context):
        if type(context) is not Context:
            raise ModelError('Exact synthetic Context required')
        with self._step() as (lease, loaded):
            ledger = loaded['ledger'][0]
            body = dict(service=self.policy.service, budget=self.policy.budget, **asdict(context))
            context_hash = digest(body)
            old = ledger['grants'].get(context.grant)
            if old:
                if old['context_hash'] != context_hash:
                    raise IntegrityError('Conflicting context for stable grant operation')
                return  # Idempotent reconciliation, never new permission or a quota charge.
            row = dict(context=body, context_hash=context_hash, revoked=False,
                       authorization=None, response=None, response_hash=None,
                       used=False, possible_disclosure=False)
            self._eligible(lease, ledger, row, chain=False)
            if context.challenge in ledger['challenges'] or context.ticket in ledger['tickets']:
                raise ModelError('Challenge or exact ticket already claimed')
            # A single immutable window identity is pinned by its start; no overlapping
            # relabeling or policy-epoch budget reset is accepted.
            window = str(context.window_start)
            for start, charge in ledger['charges'].items():
                if int(start) < context.window_end and context.window_start < charge['end'] and start != window:
                    raise ModelError('Overlapping budget window')
            charge = ledger['charges'].setdefault(window, dict(end=context.window_end, count=0, bytes=0))
            if charge['end'] != context.window_end:
                raise ModelError('Budget window changed')
            if charge['count'] + 1 > self.policy.count_limit or charge['bytes'] + context.size > self.policy.byte_limit:
                raise ModelError('Original budget exhausted')
            charge['count'] += 1; charge['bytes'] += context.size
            ledger['grants'][context.grant] = row
            ledger['challenges'].append(context.challenge); ledger['tickets'].append(context.ticket)
            self._save(lease, loaded, 'ledger', 'reserve')
        self.hook('reserve:acknowledged')

    def observe(self, grant, views=(True, True)):
        label(grant)
        if type(views) is not tuple or len(views) != 2 or any(type(v) is not bool for v in views):
            raise ModelError('Two boolean synthetic views required')
        with self._step() as (lease, loaded):
            self._row(loaded, grant)
            self._observations[grant] = (lease.now, views)

    @staticmethod
    def _row(loaded, grant):
        try:
            return loaded['ledger'][0]['grants'][grant]
        except KeyError as exc:
            raise ModelError('Unknown synthetic grant') from exc

    def authorize(self, grant):
        with self._step() as (lease, loaded):
            row = self._row(loaded, grant)
            self._eligible(lease, loaded['ledger'][0], row)
            if row['authorization'] is None:
                row['authorization'] = digest(dict(purpose='prepare', operation=[
                    self.policy.service, self.policy.budget, grant], context=row['context_hash']))
                self._save(lease, loaded, 'ledger', 'authorize')
        self.hook('authorize:acknowledged')

    def prepare(self, grant):
        with self._step() as (lease, loaded):
            row = self._row(loaded, grant)
            self._eligible(lease, loaded['ledger'][0], row)
            if row['authorization'] is None:
                raise ModelError('Acknowledged preparation authorization required')
            candidates = loaded['vault'][0]['candidates']
            if grant not in candidates:
                response = dict(mode=MODE, operation=[self.policy.service, self.policy.budget, grant],
                                context=row['context_hash'], placeholder=secrets.token_hex(16))
                candidates[grant] = dict(context_hash=row['context_hash'], authorization=row['authorization'],
                                         ledger_checkpoint=loaded['ledger'][1][1],
                                         response=response, response_hash=digest(response))
                self._save(lease, loaded, 'vault', 'private-candidate')
        self.hook('prepare:acknowledged')

    def commit(self, grant):
        with self._step() as (lease, loaded):
            row = self._row(loaded, grant)
            self._eligible(lease, loaded['ledger'][0], row)
            candidate = loaded['vault'][0]['candidates'].get(grant)
            if candidate is None:
                raise ModelError('Private acknowledged candidate required')
            if row['response'] is None:
                row.update(response=candidate['response'], response_hash=candidate['response_hash'],
                           used=True, possible_disclosure=True)
                self._save(lease, loaded, 'ledger', 'response-committed')
        self.hook('commit:acknowledged')

    def dispatch(self, grant, request, nonce, response_hash):
        label(request); label(nonce)
        with self._step() as (lease, loaded):
            ledger = loaded['ledger'][0]
            row = self._row(loaded, grant)
            self._eligible(lease, ledger, row)
            if row['response'] is None or row['context']['request'] != request or row['response_hash'] != response_hash:
                raise ModelError('Committed response and exact authenticated-request stub required')
            nonces = loaded['delivery'][0]['nonces']
            if nonce in nonces:
                raise ModelError('Dispatch nonce already consumed')
            nonces[nonce] = dict(grant=grant, request=request, response_hash=response_hash,
                                 generation=self.generation, revocations=ledger['revocations'],
                                 policy_epoch=ledger['policy_epoch'], delivery_epoch=ledger['delivery_epoch'],
                                 deadline=min(row['context']['expires'], row['context']['window_end']))
            self._save(lease, loaded, 'delivery', 'dispatch-accepted')
            response = canonical(row['response'])
        # Final-sample-to-arrival race is deliberate: accepted bytes cannot be recalled.
        self.hook('dispatch:acknowledged')
        return response

    def revoke(self, grant):
        with self._step() as (lease, loaded):
            row = self._row(loaded, grant)
            if not row['revoked']:
                row['revoked'] = True
                loaded['ledger'][0]['revocations'] += 1
                self._save(lease, loaded, 'ledger', 'revoke')
        self.hook('revoke:acknowledged')

    def advance_epochs(self, policy_epoch, delivery_epoch):
        integer(policy_epoch); integer(delivery_epoch)
        with self._step() as (lease, loaded):
            ledger = loaded['ledger'][0]
            if policy_epoch < ledger['policy_epoch'] or delivery_epoch < ledger['delivery_epoch']:
                raise ModelError('Epoch rollback forbidden')
            if (policy_epoch, delivery_epoch) != (ledger['policy_epoch'], ledger['delivery_epoch']):
                ledger.update(policy_epoch=policy_epoch, delivery_epoch=delivery_epoch)
                self._save(lease, loaded, 'ledger', 'epochs')

    def status(self, grant):
        with self._step() as (_, loaded):
            row = self._row(loaded, grant)
            return dict(mode=MODE, grant=grant, reserved=True, prepared=grant in loaded['vault'][0]['candidates'],
                        committed=row['response'] is not None, response_hash=row['response_hash'],
                        revoked=row['revoked'], used=row['used'], possible_disclosure=row['possible_disclosure'],
                        charges=loaded['ledger'][0]['charges'])


def demo():
    with tempfile.TemporaryDirectory() as root:
        base = Path(root)
        model = Coordinator(base / 'components', base / 'authority.sqlite', Policy(), lambda: 100, create=True)
        model.recover()
        context = Context()
        model.reserve(context); model.observe(context.grant)
        model.authorize(context.grant); model.prepare(context.grant); model.commit(context.grant)
        status = model.status(context.grant)
        first = model.dispatch(context.grant, context.request, 'model:retrieve-1', status['response_hash'])
        second = model.dispatch(context.grant, context.request, 'model:retrieve-2', status['response_hash'])
        model.revoke(context.grant)
        result = dict(mode=MODE, identical_retry=first == second, status=model.status(context.grant),
                      real_keys=0, rpc_calls=0, broadcasts=0)
        model.close()
        return result


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2, sort_keys=True))
