#!/usr/bin/env python3
"""Persistent native fixture controller. No RPC, funded coins or release keys."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import release_coordinator_model as core

MODE = 'OFFLINE_NATIVE_CONTROLLER_FIXTURES_NO_CHAIN_NO_AUTHORIZATION'
NATIVE_MODE = 'OFFLINE_NATIVE_FIXTURES_NO_CHAIN_NO_AUTHORIZATION'
ROOT = Path(__file__).resolve().parents[1]
ModelError = core.ModelError
IntegrityError = core.IntegrityError
RecoveryRequired = core.RecoveryRequired


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class WorkerUnavailable(ModelError):
    pass


class InvalidFixture(ModelError):
    pass


class Worker:
    """Pinned local executable, with private bounded fixture stdin/stdout only."""
    def __init__(self, path=None):
        self.path = Path(path or ROOT / 'target/debug/examples/native_ticket_worker').resolve()
        try:
            self.fingerprint = sha(self.path.read_bytes())
        except OSError as exc:
            raise WorkerUnavailable('Build the offline native_ticket_worker example first') from exc

    def run(self, operation, raw):
        if type(raw) is not bytes or len(raw) > 65_536:
            raise ModelError('Bounded private fixture bytes required')
        try:
            if sha(self.path.read_bytes()) != self.fingerprint:
                raise WorkerUnavailable('Native worker changed; do not replace pinned code')
            reply = subprocess.run([str(self.path), operation], input=raw,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=20, env={'PATH': '/usr/bin:/bin'})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WorkerUnavailable('Native worker unavailable; retain all existing state') from exc
        if reply.returncode or len(reply.stdout) > 65_536 or not reply.stdout.isascii():
            raise InvalidFixture('Native worker rejected fixture or returned invalid bytes')
        return reply.stdout

    def validate(self, plan):
        raw = core.canonical(plan)
        if self.run('validate', raw) != raw:
            raise InvalidFixture('Native plan encoding changed')
        return json.loads(raw)

    def terminal(self, issue, action):
        if action not in ('consume', 'refund'):
            raise ModelError('Expected terminal fixture action')
        return json.loads(self.run(action + '-plan', core.canonical(issue)))

    def pin(self, plan):
        return json.loads(self.run('pin', core.canonical(plan)))

    def prepare(self, plan):
        raw = self.run('prepare', core.canonical(plan))
        self.verify(raw.decode())
        return raw.decode()

    def verify(self, record):
        if type(record) is not str:
            raise InvalidFixture('Missing exact saved fixture')
        summary = json.loads(self.run('verify', record.encode()))
        if summary.get('mode') != NATIVE_MODE or summary.get('vm_verified') is not True:
            raise InvalidFixture('Unexpected native fixture summary')
        return summary


@dataclass(frozen=True)
class Policy:
    issue_raw: str
    worker_hash: str
    freshness: int = 5
    observation_pin: str | None = None

    def __post_init__(self):
        if type(self.freshness) is not int or not 1 <= self.freshness <= 30:
            raise ModelError('Invalid fixture freshness')

    @property
    def id(self):
        value = dict(mode=MODE, issue=self.issue_raw, worker=self.worker_hash, freshness=self.freshness)
        if self.observation_pin is not None: value['observation_pin'] = self.observation_pin
        return sha(core.canonical(value))


class FakeNode:
    """Mutable synthetic acceptance map, never a native RPC adapter."""
    def __init__(self, *, apply=True, lose_reply=False):
        self.accepted = {}
        self.calls = 0
        self.apply = apply
        self.lose_reply = lose_reply

    def accept(self, summary):
        self.accepted[summary['transaction_id']] = summary['native_hash']

    def submit(self, summary):
        self.calls += 1
        if self.apply:
            self.accept(summary)
        if self.lose_reply:
            raise ModelError('Synthetic submission reply lost')
        return 'SYNTHETIC_REPLY_NOT_CONFIRMATION'


def initial():
    return dict(mode=MODE, issue_record=None, issue_attempt='NONE', branch=None,
                terminal_plan=None, terminal_record=None, terminal_attempt='NONE', charge=None)


class Controller:
    """One fixture lifecycle. Shared authority serializes every component operation."""
    def __init__(self, root, authority_path, issue, clock, *, create=False, worker=None, hook=None):
        self.worker = worker or Worker()
        self.issue = self.worker.validate(issue)
        if self.issue['action'] != 'issue':
            raise ModelError('Controller requires its original fixture issue plan')
        self.policy = self._make_policy()
        self.root = Path(root)
        authority_path = Path(authority_path)
        ledger_path = self.root / 'ticket.sqlite'
        if self.root.resolve() in authority_path.resolve().parents or authority_path.resolve() == ledger_path.resolve():
            raise ModelError('Independent authority must be outside component backup directory')
        self.hook = hook or (lambda stage: None)
        self.samples = {}
        self.generation = None
        self._authority = None
        self._journal = None
        if create:
            self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
            authority_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            # Exclusive creation also prevents a failed partial initialization reset.
            for path in (authority_path, ledger_path):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
        try:
            self._authority = core.Authority(authority_path, self.policy, clock, create)
            self._journal = core.Journal(ledger_path, 'native-ticket', self.policy,
                                         self._authority.id, initial(), create)
            if create:
                with self._authority.serial(recovery=True) as lease:
                    seq, event_hash = self._journal.db.execute('SELECT seq,hash FROM events').fetchone()
                    self._authority.checkpoint(lease, self._journal.role, seq, event_hash)
        except BaseException:
            self.close()
            raise

    def _make_policy(self):
        return Policy(core.canonical(self.issue).decode(), self.worker.fingerprint)

    def close(self):
        if self._journal is not None:
            self._journal.db.close()
        if self._authority is not None:
            self._authority.db.close()

    def recover(self):
        self.generation = self._authority.acquire()
        self.samples.clear()
        with self._authority.serial(self.generation, recovery=True) as lease:
            self._load(lease, reconcile=True)
            self._authority.db.execute('UPDATE meta SET ready=1')

    @contextmanager
    def step(self):
        if self.generation is None:
            raise RecoveryRequired('Recover the original fixture stores first')
        with self._authority.serial(self.generation) as lease:
            state, previous = self._load(lease)
            yield lease, state, previous

    def _load(self, lease, reconcile=False):
        if core.canonical(self.issue).decode() != self.policy.issue_raw or self.worker.fingerprint != self.policy.worker_hash:
            raise IntegrityError('Pinned controller plan or native worker identity changed')
        state, previous = self._journal.load(lease, reconcile)
        old = None
        verified = {}
        def verify(record):
            if record not in verified:
                verified[record] = self.worker.verify(record)
            return verified[record]
        try:
            for raw, in self._journal.db.execute('SELECT body FROM events ORDER BY seq'):
                row = json.loads(raw)['state']
                if set(row) != set(initial()) or row['mode'] != MODE:
                    raise IntegrityError('Unexpected fixture journal state')
                for phase in ('issue', 'terminal'):
                    attempt, record = row[phase + '_attempt'], row[phase + '_record']
                    if attempt not in ('NONE', 'STARTED', 'OBSERVED') or (attempt != 'NONE' and record is None):
                        raise IntegrityError('Missing saved transaction or invalid attempt')
                    if record is not None:
                        info = verify(record)
                        plan = self.issue if phase == 'issue' else row['terminal_plan']
                        if core.canonical(info['plan']) != core.canonical(plan):
                            raise IntegrityError('Saved transaction has another plan')
                branch, plan = row['branch'], row['terminal_plan']
                if branch is None:
                    if any(row[k] is not None for k in ('terminal_plan', 'terminal_record', 'charge')):
                        raise IntegrityError('Terminal state without permanent choice')
                elif branch in ('consume', 'refund') and row['issue_attempt'] == 'OBSERVED':
                    self.worker.validate(plan)
                    if plan['action'] != branch or core.canonical(self._base(plan)) != core.canonical(self.issue):
                        raise IntegrityError('Terminal plan differs from original operation')
                    charge = None if branch == 'refund' else dict(count=1, bytes=self.issue['context']['ciphertext_bytes'],
                        window_start=plan['admission']['window_start'], window_end=plan['admission']['window_end'])
                    if core.canonical(row['charge']) != core.canonical(charge):
                        raise IntegrityError('Fixture reservation charge changed')
                else:
                    raise IntegrityError('Invalid branch or missing observed issuance')
                if old is None:
                    if core.canonical(row) != core.canonical(initial()):
                        raise IntegrityError('Invalid controller genesis')
                else:
                    for field in ('issue_record', 'branch', 'terminal_plan', 'terminal_record', 'charge'):
                        if old[field] is not None and core.canonical(old[field]) != core.canonical(row[field]):
                            raise IntegrityError('Permanent native fixture state changed')
                    order = {'NONE': 0, 'STARTED': 1, 'OBSERVED': 2}
                    if any(not 0 <= order[row[p + '_attempt']] - order[old[p + '_attempt']] <= 1 for p in ('issue', 'terminal')):
                        raise IntegrityError('Native attempt history regressed or skipped intent')
                old = row
        except WorkerUnavailable:
            raise
        except (InvalidFixture, KeyError, TypeError, ValueError) as exc:
            raise IntegrityError('Corrupt native fixture history') from exc
        return state, previous

    @staticmethod
    def _base(plan):
        p = dict(plan)
        p.update(action='issue', issuance=None, admission=None, closure=None)
        return p

    def _save(self, lease, state, previous, stage):
        self._journal.save(lease, state, stage, previous,
                           lambda suffix: self.hook(stage + ':' + suffix.split(':')[-1]))

    def _summary(self, state, phase):
        record = state[phase + '_record']
        if record is None:
            raise ModelError('No saved fixture transaction')
        return self.worker.verify(record)

    def _fresh_issue(self, lease, state):
        sample = self.samples.get('issue')
        if not sample or not sample[1] or lease.now - sample[0] > self.policy.freshness:
            raise ModelError('Fresh matching synthetic issue views required')
        if state['issue_attempt'] != 'OBSERVED':
            raise ModelError('Original issue not reconciled')

    def _deadline(self, lease, plan):
        c = plan['context']
        if plan['action'] == 'consume':
            a = plan['admission']
            if not max(c['not_before'], a['window_start']) <= lease.now < min(c['expires'], a['window_end'], a['original_deadline']):
                raise ModelError('Original consume deadline/window closed')
        elif plan['action'] == 'refund':
            if plan['closure']['reason'] == 'expired' and lease.now < c['expires']:
                raise ModelError('Fixture expiry closure is premature')
        elif not c['not_before'] <= lease.now < c['expires']:
            raise ModelError('Issue outside original fixture lifetime')

    def choose(self, plan):
        plan = self.worker.validate(plan)
        if plan['action'] not in ('consume', 'refund') or core.canonical(self._base(plan)) != core.canonical(self.issue):
            raise ModelError('Terminal plan must bind original fixture issue')
        with self.step() as (lease, state, previous):
            if state['branch'] is not None:
                if state['branch'] != plan['action']:
                    raise ModelError('Permanent terminal branch already selected')
                if core.canonical(state['terminal_plan']) != core.canonical(plan):
                    raise IntegrityError('Conflicting context for same terminal operation')
                return self._public(state)
            self._fresh_issue(lease, state)
            self._deadline(lease, plan)
            state['branch'], state['terminal_plan'] = plan['action'], plan
            if plan['action'] == 'consume':
                a = plan['admission']
                state['charge'] = dict(count=1, bytes=self.issue['context']['ciphertext_bytes'],
                                       window_start=a['window_start'], window_end=a['window_end'])
            self._save(lease, state, previous, 'branch')
        self.hook('branch:acknowledged')
        return self.status()

    def prepare(self, phase):
        if phase not in ('issue', 'terminal'):
            raise ModelError('Unknown native fixture phase')
        with self.step() as (lease, state, previous):
            if state[phase + '_record'] is not None:
                return self._summary(state, phase)
            plan = self.issue if phase == 'issue' else state['terminal_plan']
            if plan is None:
                raise ModelError('Choose terminal branch before signing')
            if phase == 'terminal':
                self._fresh_issue(lease, state)
            self._deadline(lease, plan)
            record = self.worker.prepare(plan)
            self.hook(phase + ':signed')
            state[phase + '_record'] = record
            self._save(lease, state, previous, phase + '-outbox')
            result = self.worker.verify(record)
        self.hook(phase + '-outbox:acknowledged')
        return result

    def submit_fake(self, phase, node):
        if phase not in ('issue', 'terminal') or type(node) is not FakeNode:
            raise ModelError('Only exact synthetic node/phase supported')
        with self.step() as (lease, state, previous):
            info = self._summary(state, phase)
            if state[phase + '_attempt'] != 'NONE':
                return 'RECONCILE_ONLY'
            plan = self.issue if phase == 'issue' else state['terminal_plan']
            self._deadline(lease, plan)
            if phase == 'terminal':
                self._fresh_issue(lease, state)
            state[phase + '_attempt'] = 'STARTED'
            self._save(lease, state, previous, phase + '-intent')
        self.hook(phase + '-intent:acknowledged')
        # The prior intent/checkpoint has committed. A new enforcing lease blocks
        # another generation while this strictly local fake effect is accepted.
        with self.step() as (lease, state, _):
            if state[phase + '_attempt'] != 'STARTED':
                return 'RECONCILE_ONLY'
            self._deadline(lease, info['plan'])
            if phase == 'terminal':
                self._fresh_issue(lease, state)
            self.hook(phase + ':before_effect')
            reply = node.submit(info)
            self.hook(phase + ':after_effect')
            return reply

    def observe_fake(self, phase, first, second):
        if phase not in ('issue', 'terminal') or first is second or any(type(n) is not FakeNode for n in (first, second)):
            raise ModelError('Two distinct synthetic views required')
        with self.step() as (lease, state, previous):
            self.samples.pop(phase, None)
            info = self._summary(state, phase)
            if state[phase + '_attempt'] == 'NONE':
                raise ModelError('No durable submission intent')
            exact = all(n.accepted.get(info['transaction_id']) == info['native_hash'] for n in (first, second))
            self.samples[phase] = (lease.now, exact)
            if exact and state[phase + '_attempt'] != 'OBSERVED':
                state[phase + '_attempt'] = 'OBSERVED'
                self._save(lease, state, previous, phase + '-observed')
            return exact

    def _public(self, state):
        return dict(mode=MODE, branch=state['branch'], charge=state['charge'],
                    issue_attempt=state['issue_attempt'], terminal_attempt=state['terminal_attempt'],
                    issue_outbox_hash=sha(state['issue_record'].encode()) if state['issue_record'] else None,
                    terminal_outbox_hash=sha(state['terminal_record'].encode()) if state['terminal_record'] else None)

    def status(self):
        with self.step() as (_, state, _):
            return self._public(state)


def demo():
    vectors = json.loads((ROOT / 'evidence/native-ticket-lab-demo.json').read_text())
    issue = vectors['examples'][0]['plan']
    worker = Worker()
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        root, authority = base / 'component', base / 'independent/authority.sqlite'
        c = Controller(root, authority, issue, lambda: 100, create=True, worker=worker)
        c.recover()
        issued = c.prepare('issue')
        a, b = FakeNode(), FakeNode()
        c.submit_fake('issue', a); b.accept(issued); c.observe_fake('issue', a, b)
        c.choose(worker.terminal(issue, 'consume'))
        terminal = c.prepare('terminal')
        before = c.status()['terminal_outbox_hash']
        a.lose_reply = True
        try:
            c.submit_fake('terminal', a)
        except ModelError:
            pass
        c.close()
        c = Controller(root, authority, issue, lambda: 100, worker=worker)
        try:
            c.recover()
            identical = before == c.status()['terminal_outbox_hash']
            reconcile_only = c.submit_fake('terminal', a) == 'RECONCILE_ONLY'
            b.accept(terminal); c.observe_fake('terminal', a, b)
            blocked = False
            try:
                c.choose(worker.terminal(issue, 'refund'))
            except ModelError:
                blocked = True
            return dict(mode=MODE, identical_saved_transaction=identical,
                        retry_reconciles_without_effect=reconcile_only, opposite_branch_blocked=blocked,
                        status=c.status(), real_rpc_calls=0, broadcasts=0, content_keys=0)
        finally:
            c.close()


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2, sort_keys=True))
