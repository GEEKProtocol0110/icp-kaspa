#!/usr/bin/env python3
"""Offline P0 private signing journal. No node, transport, funding or key generation."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from native_ticket_observer import canonical, decode
from ticket_pilot_review import Reviewer
import release_coordinator_model as core

ROOT = Path(__file__).resolve().parents[1]
MODE = 'OFFLINE_P0_PRIVATE_JOURNAL_NO_CHAIN_NO_AUTHORIZATION'
NATIVE_MODE = 'OFFLINE_P0_PRIVATE_SIGNED_NOT_CHAIN_PROOF'
Error = core.ModelError
IntegrityError = core.IntegrityError
RecoveryRequired = core.RecoveryRequired


def sha(raw): return hashlib.sha256(raw).hexdigest()


def private_file(path, create=False):
    path = Path(path)
    if create:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fsync(fd); os.close(fd)
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise Error('Private owned regular file required')
    return path


def load_key(path):
    """One raw lowercase 32-byte secret, never command-line text or public receipt."""
    private_file(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise Error('Private key file changed')
        raw = os.read(fd, 66)
    finally: os.close(fd)
    if len(raw) != 64 or any(c not in b'0123456789abcdef' for c in raw):
        raise Error('Exact private key encoding required')
    return raw.decode('ascii')


class NativeRejected(Error):
    pass


class Worker:
    def __init__(self, path=None):
        self.path = Path(path or ROOT/'target/debug/examples/ticket_pilot_private').resolve()
        self.fingerprint = sha(self.path.read_bytes())

    def check(self):
        if sha(self.path.read_bytes()) != self.fingerprint:
            raise IntegrityError('Pinned private worker changed')

    def run(self, operation, value):
        raw = canonical(value)
        if len(raw) > 65536 or operation not in ('prepare', 'verify'):
            raise Error('Bounded private prepare/verify request required')
        self.check()
        try:
            r = subprocess.run([str(self.path), operation], input=raw, capture_output=True,
                               timeout=20, env={'PATH': '/usr/bin:/bin'})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RecoveryRequired('Private worker unavailable; retain journal') from exc
        if r.returncode or len(r.stdout) > 65536:
            raise NativeRejected('Private native request rejected')
        return decode(r.stdout)

    def prepare(self, plan, action, entry, secret):
        return self.run('prepare', dict(plan=plan, action=action, entry=entry, secret_key=secret))

    def verify(self, record):
        try: result = self.run('verify', record)
        except NativeRejected as exc: raise IntegrityError('Saved native record rejected') from exc
        if result.get('mode') != NATIVE_MODE or result.get('vm_verified') is not True:
            raise IntegrityError('Invalid native verification result')
        return result


@dataclass(frozen=True)
class Policy:
    review_raw: str
    reviewer_hash: str
    worker_hash: str
    claims_path: str

    @property
    def id(self): return sha(canonical(dict(mode=MODE, **self.__dict__)))


def initial():
    return dict(mode=MODE, branch=None, issue_started=False, issue_entry=None, issue_record=None,
                terminal_started=False, terminal_entry=None, terminal_record=None)


class Controller:
    """Trusted local offline coordinator, using independent checkpoint/claim stores.

    Its local signing policy is bypassable by a caller holding the private key.
    No claim here establishes an existing UTXO or accepted-chain observation.
    """
    def __init__(self, root, authority_path, claims_path, review, clock, *, create=False,
                 reviewer=None, worker=None, hook=None):
        self.reviewer = reviewer or Reviewer(); self.worker = worker or Worker()
        self.review = decode(canonical(review)); self.reviewer.verify(self.review)
        self.plan = self.review['plan']
        if self.plan['purpose'] != 'operator-unsigned-review':
            raise Error('Public fixture cannot open a private pilot journal')
        self.root = Path(root); self.hook = hook or (lambda stage: None)
        authority_path, claims_path = Path(authority_path), Path(claims_path)
        paths = [authority_path, claims_path, self.root/'pilot.sqlite']
        if len({p.resolve() for p in paths}) != 3: raise Error('Three distinct stores required')
        if any(self.root.resolve() == p.resolve() or self.root.resolve() in p.resolve().parents
               for p in (authority_path, claims_path)):
            raise Error('Authority and registry must be outside component backup directory')
        self.policy = Policy(canonical(self.review).decode(), self.reviewer.fingerprint,
                             self.worker.fingerprint, str(claims_path.resolve()))
        self._authority = self._journal = self._claims = None
        if create and any(p.exists() for p in (authority_path, paths[2])):
            raise Error('Refuse existing authority or journal')
        for p in (authority_path, paths[2]): private_file(p, create)
        # A shared registry is explicitly initialized once, never silently recreated on reopen.
        private_file(claims_path)
        try:
            self._claims = core.connect(claims_path)
            if self._claims.execute('SELECT mode FROM registry').fetchone() != (MODE,):
                raise IntegrityError('Wrong private claim registry')
            self._authority = core.Authority(authority_path, self.policy, clock, create)
            self._journal = core.Journal(paths[2], 'p0-private', self.policy,
                                         self._authority.id, initial(), create)
            if create:
                with self._authority.serial(recovery=True) as lease:
                    seq, h = self._journal.db.execute('SELECT seq,hash FROM events').fetchone()
                    self._authority.checkpoint(lease, self._journal.role, seq, h)
            self.generation = self._authority.acquire()
        except BaseException:
            self.close(); raise

    @staticmethod
    def create_claims(path):
        path = private_file(path, True); db = core.connect(path)
        try:
            db.executescript('CREATE TABLE registry(mode TEXT); CREATE TABLE claims(source TEXT PRIMARY KEY,owner TEXT,policy TEXT);')
            db.execute('INSERT INTO registry VALUES(?)', (MODE,))
        finally: db.close()

    def close(self):
        for obj in (self._journal, self._authority):
            if obj is not None: obj.db.close()
        if self._claims is not None: self._claims.close()

    def _claim(self, create=False):
        p = self.plan['source']; source = 'testnet-10:' + p['transaction_id'] + ':' + str(p['index'])
        self._claims.execute('BEGIN IMMEDIATE')
        try:
            row = self._claims.execute('SELECT owner,policy FROM claims WHERE source=?', (source,)).fetchone()
            expected = (self._authority.id, self.policy.id)
            if row is None and create:
                self._claims.execute('INSERT INTO claims VALUES(?,?,?)', (source, *expected)); row = expected
            if row != expected: raise IntegrityError('Missing or conflicting permanent source claim')
        finally: self._claims.execute('COMMIT')

    def _load(self, lease, reconcile=False):
        if (canonical(self.review).decode() != self.policy.review_raw
            or self.reviewer.fingerprint != self.policy.reviewer_hash
            or self.worker.fingerprint != self.policy.worker_hash):
            raise IntegrityError('Pinned private policy changed')
        self.reviewer.verify(self.review)
        self.worker.check()
        state, previous = self._journal.load(lease, reconcile)
        old = None; verified = {}
        for raw, in self._journal.db.execute('SELECT body FROM events ORDER BY seq'):
            body = json.loads(raw); row = body['state']
            if set(row) != set(initial()) or row['mode'] != MODE:
                raise IntegrityError('Wrong private journal shape')
            if row['branch'] not in (None, 'consume', 'refund'):
                raise IntegrityError('Invalid permanent branch')
            for phase in ('issue', 'terminal'):
                started, entry, record = (row[phase + suffix] for suffix in ('_started','_entry','_record'))
                if type(started) is not bool or started != (entry is not None) or (record is not None and not started):
                    raise IntegrityError('Missing signing reservation')
                if started: self._claim()
                if phase == 'terminal' and started and row['branch'] is None:
                    raise IntegrityError('Terminal signing without permanent choice')
                if record is not None:
                    encoded = canonical(record)
                    if encoded not in verified: verified[encoded] = self.worker.verify(record)
                    info = verified[encoded]; action = 'issue' if phase == 'issue' else row['branch']
                    if (record['plan'] != self.plan or record['action'] != action
                        or record['entry'] != entry or info['review_id'] != self.review['review']['review_id']):
                        raise IntegrityError('Saved outbox differs from reservation')
            if row['branch'] is not None and row['issue_record'] is None:
                raise IntegrityError('Branch requires saved issuance')
            if old is None:
                if row != initial() or body['kind'] != 'genesis': raise IntegrityError('Wrong private genesis')
            else:
                changed = {k for k in row if row[k] != old[k]}
                kind = body['kind']
                valid = False
                if kind == 'choose':
                    valid = (changed == {'branch'} and old['branch'] is None
                             and old['issue_record'] is not None)
                for phase in ('issue','terminal'):
                    if kind == phase+'-signing-intent':
                        valid = (changed == {phase+'_started',phase+'_entry'}
                                 and not old[phase+'_started'] and row[phase+'_started']
                                 and (phase == 'issue' or old['branch'] is not None))
                    if kind == phase+'-outbox':
                        valid = (changed == {phase+'_record'} and old[phase+'_started']
                                 and old[phase+'_record'] is None and row[phase+'_record'] is not None)
                if not valid: raise IntegrityError('Private event skipped its durable reservation or choice')
                for k in ('branch','issue_entry','issue_record','terminal_entry','terminal_record'):
                    if old[k] is not None and old[k] != row[k]:
                        raise IntegrityError('Permanent private state changed')
                for phase in ('issue','terminal'):
                    if old[phase+'_started'] and not row[phase+'_started']:
                        raise IntegrityError('Signing intent regressed')
            old = row
        return state, previous

    def recover(self):
        with self._authority.serial(self.generation, recovery=True) as lease:
            self._load(lease, True)
            self._authority.db.execute('UPDATE meta SET ready=1')
        self.hook('recovery:acknowledged')

    @contextmanager
    def _step(self):
        with self._authority.serial(self.generation) as lease:
            state, previous = self._load(lease)
            yield lease, state, previous

    def choose(self, branch):
        if branch not in ('consume', 'refund'): raise Error('Expected consume or refund')
        with self._step() as (lease, state, previous):
            if state['issue_record'] is None: raise Error('Save issuance before branch choice')
            if state['branch'] not in (None, branch): raise Error('Terminal branch is permanent')
            if state['branch'] is None:
                state['branch'] = branch
                self._journal.save(lease, state, 'choose', previous, self.hook)
        return self.status()

    def prepare(self, phase, entry, key_path):
        if phase not in ('issue','terminal'): raise Error('Invalid signing phase')
        # Reserve before any signer/key access. Unknown outcomes never trigger automatic re-signing.
        with self._step() as (lease, state, previous):
            if state[phase+'_record'] is not None: return self._summary(state)
            if state[phase+'_started']: raise RecoveryRequired('Signing outcome unknown; reconcile saved state only')
            if phase == 'terminal' and state['branch'] is None: raise Error('Choose terminal branch first')
            self._claim(create=True)
            state[phase+'_started'] = True; state[phase+'_entry'] = decode(canonical(entry))
            self._journal.save(lease, state, phase+'-signing-intent', previous, self.hook)
        self.hook('signing:reserved')
        # A new lease fences a competing recovery before accessing a key or signer.
        with self._step() as (lease, state, previous):
            if state[phase+'_record'] is not None: return self._summary(state)
            action = 'issue' if phase == 'issue' else state['branch']
            record = self.worker.prepare(self.plan, action, state[phase+'_entry'], load_key(key_path))
            self.worker.verify(record)
            if record['plan'] != self.plan or record['action'] != action or record['entry'] != state[phase+'_entry']:
                raise IntegrityError('Signer reply differs from durable reservation')
            self.hook('signing:returned')
            state[phase+'_record'] = record
            self._journal.save(lease, state, phase+'-outbox', previous, self.hook)
        self.hook('outbox:acknowledged')
        return self.status()

    @staticmethod
    def _summary(state):
        return dict(mode=MODE, branch=state['branch'], source_observed=False, broadcasts=0,
            **{phase:dict(signing_started=state[phase+'_started'],
                 outbox_sha256=sha(canonical(state[phase+'_record'])) if state[phase+'_record'] is not None else None)
               for phase in ('issue','terminal')})

    def status(self):
        with self._step() as (_, state, __): return self._summary(state)
