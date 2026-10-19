#!/usr/bin/env python3
"""Synthetic state model. No Kaspa transactions, content keys or key encryption.

SQLite serializes one local database; copied/restored databases are NOT fenced.
FakeChain observations are trusted test inputs, never proof of real acceptance.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from cryptography.exceptions import InvalidSignature
from transfer_lab import (Ed25519PrivateKey, Ed25519PublicKey, TransferError,
                          canonical, digest, number, public, unhex)

MODE = 'SYNTHETIC_RELEASE_MODEL_NO_KEYS_NO_CHAIN'
DOMAIN = 'icp/model-release/v0/'


def require(condition, message):
    if not condition:
        raise TransferError(message)


def sign(key, purpose, body):
    return key.sign((DOMAIN + purpose).encode() + b'\0' + canonical(body)).hex()


def verify(key, signature, purpose, body):
    try:
        Ed25519PublicKey.from_public_bytes(unhex(key, 32)).verify(
            unhex(signature, 64), (DOMAIN + purpose).encode() + b'\0' + canonical(body))
    except InvalidSignature as exc:
        raise TransferError('Model signature rejected') from exc


@dataclass(frozen=True)
class ModelPolicy:
    service: str
    budget: str
    approver: str
    sender: str
    epoch: int = 0
    origin: int = 0
    window: int = 600
    max_grants: int = 10
    max_bytes: int = 1048576
    challenge_lifetime: int = 60
    min_successors: int = 2
    max_scan_age: int = 10

    def __post_init__(self):
        for value in (self.service, self.budget, self.approver, self.sender):
            unhex(value, 32)
        require(self.approver != self.sender, 'Distinct authorities required')
        for name in ('epoch', 'origin', 'window', 'max_grants', 'max_bytes',
                     'challenge_lifetime', 'min_successors', 'max_scan_age'):
            number(getattr(self, name))
        require(0 < self.window <= 86400 and 0 < self.challenge_lifetime <= 3600,
                'Invalid clock limits')
        require(0 < self.max_grants <= 1000000 and 0 < self.max_bytes <= 2**40
                and 0 < self.min_successors <= 1000000
                and 0 < self.max_scan_age <= 3600, 'Invalid policy limits')

    @property
    def id(self):
        return digest(DOMAIN + 'policy', asdict(self))


class FakeChain:
    """Two labeled, mutable synthetic observations; deliberately no RPC API."""
    def __init__(self, now):
        self.views = [dict(at=now, online=True, caught_up=True, issues={}, spends={})
                      for _ in range(2)]
        self.submissions = []
        self.lose_reply = False

    def accept_issue(self, plan, depth=2):
        for view in self.views:
            view['issues'][plan['ticket']] = (plan['commitment'], depth)

    def accept_consume(self, plan, depth=2):
        for view in self.views:
            view['spends'][plan['ticket']] = (plan['id'], plan['commitment'], depth)

    def submit(self, plan):
        self.submissions.append(dict(plan))
        if self.lose_reply:
            raise OSError('Synthetic reply lost')

    def check(self, issue, consume, policy, now):
        require(len(self.views) == 2, 'Two model views required')
        for view in self.views:
            age = now - number(view['at'])
            require(view['online'] is True and view['caught_up'] is True
                    and 0 <= age <= policy.max_scan_age, 'Unavailable model observation')
            binding, depth = view['issues'].get(issue['ticket'], (None, 0))
            require(binding == issue['commitment'] and number(depth) >= policy.min_successors,
                    'Exact model issuance required')
            spend = view['spends'].get(issue['ticket'])
            if consume is None:
                require(spend is None, 'Model ticket already spent')
            else:
                require(spend is not None and spend[:2] == (consume['id'], consume['commitment'])
                        and number(spend[2]) >= policy.min_successors,
                        'Exact model consumption required')


class ReleaseLedger:
    def __init__(self, path, policy, clock, fault=None):
        require(type(policy) is ModelPolicy, 'Model policy required')
        self.policy, self.clock = policy, clock
        self.fault = fault or (lambda stage: None)
        self.db = sqlite3.connect(path, isolation_level=None, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1),
                policy TEXT NOT NULL, last_clock INTEGER NOT NULL, halted INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS records (scope TEXT PRIMARY KEY, body TEXT NOT NULL,
                fake_key_tag TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, intent TEXT NOT NULL,
                ticket TEXT NOT NULL UNIQUE, issue TEXT NOT NULL, state TEXT NOT NULL,
                consume TEXT, request TEXT, deadline INTEGER, window INTEGER,
                attempts INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
                response BLOB, response_hash TEXT, possible_disclosure INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS challenges (nonce TEXT PRIMARY KEY, grant_id TEXT NOT NULL,
                body TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS quotas (window INTEGER PRIMARY KEY,
                grants INTEGER NOT NULL, bytes INTEGER NOT NULL);
        ''')
        try:
            with self._transaction(initializing=True) as now:
                row = self.db.execute('SELECT * FROM meta').fetchone()
                if row is None:
                    self.db.execute('INSERT INTO meta VALUES(1,?,?,0)', (policy.id, now))
                else:
                    require(row['policy'] == policy.id, 'Database policy mismatch; no reset')
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    @contextmanager
    def _transaction(self, initializing=False):
        self.db.execute('BEGIN IMMEDIATE')
        rollback_clock = False
        observed_clock = 0
        try:
            row = self.db.execute('SELECT * FROM meta').fetchone()
            try:
                now = number(self.clock())
            except Exception:
                rollback_clock = True
                raise TransferError('Uncertain clock; ledger halted') from None
            observed_clock = now
            if row:
                require(not row['halted'] or initializing, 'Ledger halted; explicit recovery required')
                rollback_clock = now < row['last_clock']
                require(not rollback_clock, 'Clock rollback; ledger halted')
            self._deadline = None
            self._checks = []
            yield now
            try:
                end = number(self.clock())
            except Exception:
                rollback_clock = True
                raise TransferError('Uncertain clock; ledger halted') from None
            observed_clock = max(observed_clock, end)
            rollback_clock = end < now
            require(not rollback_clock, 'Clock rollback; ledger halted')
            require(self._deadline is None or end < self._deadline, 'Deadline crossed before commit')
            for check in self._checks:
                check(end)
            self.db.execute('UPDATE meta SET last_clock=? WHERE id=1', (end,))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            # A denied operation must not erase an already observed later clock.
            # Preserve only clock/halt metadata; grant/nonce/quota writes roll back.
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('UPDATE meta SET last_clock=MAX(last_clock,?),halted=MAX(halted,?) WHERE id=1',
                            (observed_clock, int(rollback_clock)))
            self.db.commit()
            raise

    def _grant(self, grant):
        row = self.db.execute('SELECT * FROM grants WHERE id=?', (grant,)).fetchone()
        require(row is not None, 'Unknown model grant')
        return row

    def _gates(self, row, now, reserved=False):
        intent = json.loads(row['intent'])
        require(not row['revoked'], 'Grant revoked')
        deadline = row['deadline'] if reserved else intent['expires']
        require(deadline is not None, 'No reservation deadline')
        require(intent['not_before'] <= now < deadline, 'Grant outside original deadline')
        self._deadline = min(self._deadline or deadline, deadline)
        return intent

    def _chain(self, row, chain, now, consumed=False):
        require(type(chain) is FakeChain, 'Only FakeChain is supported')
        chain.check(json.loads(row['issue']), json.loads(row['consume']) if consumed else None,
                    self.policy, now)
        self._checks.append(lambda end: chain.check(
            json.loads(row['issue']), json.loads(row['consume']) if consumed else None,
            self.policy, end))

    def register_record(self, record, fake_key_tag):
        require(type(record) is dict and set(record) == {'id', 'version', 'cipher_hash', 'bytes', 'context'},
                'Invalid model record')
        for name in ('id', 'cipher_hash', 'context'):
            unhex(record[name], 32)
        number(record['version']); unhex(fake_key_tag, 32)
        require(16 < number(record['bytes']) <= 1048592, 'Invalid ciphertext size')
        scope = record['id'] + ':' + str(record['version'])
        with self._transaction():
            self.db.execute('INSERT INTO records VALUES(?,?,?)',
                            (scope, canonical(record).decode(), fake_key_tag))

    def issue(self, intent, approval, sender_signature):
        require(type(intent) is dict and set(intent) == {
            'mode', 'network', 'policy', 'grant', 'record', 'recipient', 'delivery_tag',
            'delivery_epoch', 'controller_tag', 'not_before', 'expires', 'uses'}, 'Invalid intent fields')
        require((intent['mode'], intent['network'], intent['policy'], intent['uses']) ==
                (MODE, 'testnet-10-model', self.policy.id, 1) and type(intent['uses']) is int,
                'Wrong model domain or policy')
        for field in ('grant', 'recipient', 'delivery_tag', 'controller_tag'):
            unhex(intent[field], 32)
        number(intent['delivery_epoch'])
        require(intent['recipient'] not in (self.policy.approver, self.policy.sender), 'Distinct recipient required')
        require(0 < number(intent['expires']) - number(intent['not_before']) <= 3600,
                'Invalid grant lifetime')
        verify(self.policy.approver, approval, 'approve', intent)
        verify(self.policy.sender, sender_signature, 'send', intent)
        body = canonical(intent).decode()
        commitment = digest(DOMAIN + 'issue', intent)
        plan = dict(mode=MODE, ticket='model:' + commitment + ':0', commitment=commitment)
        with self._transaction() as now:
            require(now < intent['expires'], 'Expired grant')
            self._deadline = intent['expires']
            record = intent['record']
            require(type(record) is dict and type(record.get('version')) is int, 'Invalid record reference')
            scope = str(record.get('id')) + ':' + str(record['version'])
            saved = self.db.execute('SELECT body FROM records WHERE scope=?', (scope,)).fetchone()
            require(saved is not None and saved['body'] == canonical(record).decode(), 'Immutable record mismatch')
            self.db.execute('INSERT INTO grants(id,intent,ticket,issue,state) VALUES(?,?,?,?,?)',
                            (intent['grant'], body, plan['ticket'], canonical(plan).decode(), 'ISSUING'))
        return plan

    def confirm_issue(self, grant, chain):
        with self._transaction() as now:
            row = self._grant(grant); self._gates(row, now)
            require(row['state'] == 'ISSUING', 'Issuance already reconciled')
            self._chain(row, chain, now)
            self.db.execute("UPDATE grants SET state='ISSUED' WHERE id=?", (grant,))

    def challenge(self, grant, purpose):
        require(purpose in ('request', 'retrieve'), 'Invalid challenge purpose')
        with self._transaction() as now:
            row = self._grant(grant)
            intent = self._gates(row, now, reserved=purpose == 'retrieve')
            require(row['state'] == ('ISSUED' if purpose == 'request' else 'RESPONSE_COMMITTED'),
                    'Invalid challenge state')
            count = self.db.execute('SELECT COUNT(*) FROM challenges WHERE grant_id=?', (grant,)).fetchone()[0]
            require(count < 64, 'Model challenge limit reached')
            expiry = min(now + self.policy.challenge_lifetime,
                         row['deadline'] if purpose == 'retrieve' else intent['expires'])
            self._deadline = expiry
            body = dict(mode=MODE, policy=self.policy.id, service=self.policy.service,
                        network='testnet-10-model', grant=grant, ticket=row['ticket'],
                        recipient=intent['recipient'], delivery_tag=intent['delivery_tag'],
                        delivery_epoch=intent['delivery_epoch'], purpose=purpose,
                        nonce=os.urandom(32).hex(), issued=now, expires=expiry,
                        request=row['request'], response_hash=row['response_hash'])
            self.db.execute('INSERT INTO challenges(nonce,grant_id,body) VALUES(?,?,?)',
                            (body['nonce'], grant, canonical(body).decode()))
        return body

    def _authenticate(self, body, signature, purpose, now):
        require(type(body) is dict, 'Invalid challenge')
        saved = self.db.execute('SELECT * FROM challenges WHERE nonce=?', (body.get('nonce'),)).fetchone()
        require(saved is not None and not saved['used'] and saved['body'] == canonical(body).decode(),
                'Unknown, changed or replayed challenge')
        require(body['purpose'] == purpose and body['issued'] <= now < body['expires'],
                'Wrong purpose or expired challenge')
        verify(body['recipient'], signature, purpose, body)
        self._deadline = min(self._deadline or body['expires'], body['expires'])
        self.db.execute('UPDATE challenges SET used=1 WHERE nonce=?', (body['nonce'],))
        return self._grant(body['grant'])

    def reserve(self, body, signature, chain):
        with self._transaction() as now:
            row = self._authenticate(body, signature, 'request', now)
            intent = self._gates(row, now)
            require(row['state'] == 'ISSUED', 'Grant already claimed')
            self._chain(row, chain, now)
            require(now >= self.policy.origin, 'Before budget origin')
            window = (now - self.policy.origin) // self.policy.window
            deadline = min(intent['expires'], body['expires'],
                           self.policy.origin + (window + 1) * self.policy.window)
            self._deadline = deadline
            used = self.db.execute('SELECT * FROM quotas WHERE window=?', (window,)).fetchone()
            count, size = (used['grants'], used['bytes']) if used else (0, 0)
            require(count + 1 <= self.policy.max_grants and size + intent['record']['bytes'] <= self.policy.max_bytes,
                    'Budget exhausted')
            self.db.execute('INSERT OR REPLACE INTO quotas VALUES(?,?,?)',
                            (window, count + 1, size + intent['record']['bytes']))
            request = digest(DOMAIN + 'request', body)
            material = dict(mode=MODE, grant=row['id'], ticket=row['ticket'], request=request,
                            policy=self.policy.id, budget=self.policy.budget, window=window,
                            delivery_tag=intent['delivery_tag'], delivery_epoch=intent['delivery_epoch'])
            commitment = digest(DOMAIN + 'consume', material)
            plan = dict(material, commitment=commitment, id='model:' + commitment)
            self.db.execute("UPDATE grants SET state='RESERVED',consume=?,request=?,deadline=?,window=? WHERE id=?",
                            (canonical(plan).decode(), request, deadline, window, row['id']))
            self.fault('reserve_before_commit')
        self.fault('reserve_after_commit')
        return plan

    def submit(self, grant, chain):
        require(type(chain) is FakeChain, 'Only FakeChain is supported')
        with self._transaction() as now:
            row = self._grant(grant); self._gates(row, now, True)
            require(row['state'] == 'RESERVED' and row['attempts'] == 0, 'Submission already claimed; reconcile only')
            plan = json.loads(row['consume'])
            self.db.execute("UPDATE grants SET state='SUBMITTING',attempts=1 WHERE id=?", (grant,))
        self.fault('submit_intent_committed')
        try:
            chain.submit(plan)
            self.fault('submit_effect_finished')
            state = 'AWAITING_CHAIN'
        except OSError:
            state = 'UNKNOWN'
        with self._transaction():
            self.db.execute("UPDATE grants SET state=? WHERE id=? AND state='SUBMITTING'", (state, grant))

    def commit_response(self, grant, chain):
        with self._transaction() as now:
            row = self._grant(grant); intent = self._gates(row, now, True)
            require(row['state'] in ('SUBMITTING', 'UNKNOWN', 'AWAITING_CHAIN', 'RESPONSE_COMMITTED'),
                    'Consumption submission required')
            self._chain(row, chain, now, True)
            if row['response'] is None:
                context = dict(mode=MODE, kind='NON_SECRET_RESPONSE_PLACEHOLDER',
                               network='testnet-10-model', recipient=intent['recipient'],
                               policy=self.policy.id, service=self.policy.service, grant=grant,
                               ticket=row['ticket'], consumption=json.loads(row['consume'])['id'],
                               request=row['request'], record=intent['record'],
                               delivery_tag=intent['delivery_tag'], delivery_epoch=intent['delivery_epoch'],
                               nonce=os.urandom(16).hex())
                response = canonical(context)
                self.db.execute("UPDATE grants SET state='RESPONSE_COMMITTED',response=?,response_hash=?,possible_disclosure=1 WHERE id=?",
                                (response, hashlib.sha256(response).hexdigest(), grant))
            self.fault('response_before_commit')
        self.fault('response_after_commit')
        return self.status(grant)

    def retrieve(self, body, signature, chain):
        with self._transaction() as now:
            row = self._authenticate(body, signature, 'retrieve', now)
            self._gates(row, now, True)
            require(row['state'] == 'RESPONSE_COMMITTED', 'No committed response')
            self._chain(row, chain, now, True)
            response = bytes(row['response'])
            self.fault('retrieve_before_commit')
        self.fault('retrieve_after_commit')
        # Recheck after the durable authentication claim. No database operation can
        # make the final observation and an external delivery atomic.
        with self._transaction() as now:
            row = self._grant(body['grant']); self._gates(row, now, True)
            self._chain(row, chain, now, True)
        return response

    def revoke(self, grant):
        with self._transaction():
            self._grant(grant)
            self.db.execute('UPDATE grants SET revoked=1 WHERE id=?', (grant,))

    def halt(self):
        self.db.execute('BEGIN IMMEDIATE')
        self.db.execute('UPDATE meta SET halted=1 WHERE id=1')
        self.db.commit()

    def status(self, grant):
        row = self._grant(grant)
        return {key: row[key] for key in ('id', 'state', 'request', 'deadline', 'window',
                                         'attempts', 'revoked', 'response_hash', 'possible_disclosure')}

    def outbox(self, grant):
        row = self._grant(grant)
        return {name: json.loads(row[name]) if row[name] else None for name in ('issue', 'consume')}


def demo():
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    policy = ModelPolicy('01' * 32, '02' * 32, public(keys[0]), public(keys[1]))
    record = dict(id='03' * 32, version=1, cipher_hash='04' * 32, bytes=128, context='05' * 32)
    intent = dict(mode=MODE, network='testnet-10-model', policy=policy.id, grant='06' * 32,
                  record=record, recipient=public(keys[2]), delivery_tag='07' * 32,
                  delivery_epoch=0, controller_tag='08' * 32, not_before=100, expires=200, uses=1)
    with tempfile.TemporaryDirectory() as folder:
        ledger = ReleaseLedger(Path(folder) / 'model.sqlite', policy, lambda: 100)
        ledger.register_record(record, '09' * 32)
        issue = ledger.issue(intent, sign(keys[0], 'approve', intent), sign(keys[1], 'send', intent))
        chain = FakeChain(100); chain.accept_issue(issue)
        grant = intent['grant']; ledger.confirm_issue(grant, chain)
        request = ledger.challenge(grant, 'request')
        consume = ledger.reserve(request, sign(keys[2], 'request', request), chain)
        ledger.submit(grant, chain); chain.accept_consume(consume)
        ledger.commit_response(grant, chain)
        request = ledger.challenge(grant, 'retrieve')
        response = ledger.retrieve(request, sign(keys[2], 'retrieve', request), chain)
        result = dict(mode=MODE, response=json.loads(response), status=ledger.status(grant),
                      fake_submissions=len(chain.submissions), keys_delivered=0,
                      real_transactions=0)
        ledger.close()
        return result


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2, sort_keys=True))
