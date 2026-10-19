#!/usr/bin/env python3
"""Synthetic controller integration with reversible native observations. No live effects."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile

import native_ticket_controller as c
import native_ticket_observer as o

MODE = 'SYNTHETIC_OBSERVER_CONTROLLER_NO_LIVE_PROOF'


class Pair:
    """Pinned two-tracker boundary. Dictionaries and FakeNode are never observations."""
    def __init__(self, first, second):
        if any(type(t) is not o.TicketTracker for t in (first, second)):
            raise c.ModelError('Two exact ticket trackers required')
        self.trackers = (first, second)
        if first.path == second.path or first.host == second.host or first.pin_id != second.pin_id:
            raise c.ModelError('Distinct observer stores/hosts and matching pins required')
        self._descriptor = deepcopy(self.descriptor())
        self.id = c.sha(c.core.canonical(dict(mode=MODE, observers=self._descriptor)))
        self.plans = deepcopy({a: s['plan'] for a, s in first.summaries.items()})

    def descriptor(self):
        return [dict(path=str(t.path), endpoint=t.endpoint, host=t.host, bootstrap=t.bootstrap,
                     reader=t.reader.fingerprint, pin=t.pin_id, pins=t.pins, depth=t.depth, age=t.max_age,
                     summaries=t.summaries, config=t._get('config')) for t in self.trackers]

    def check(self):
        if c.core.canonical(self.descriptor()) != c.core.canonical(self._descriptor):
            raise c.IntegrityError('Pinned observer configuration changed')
        if c.core.canonical(self.plans) != c.core.canonical({a: s['plan'] for a, s in self.trackers[0].summaries.items()}):
            raise c.IntegrityError('Pinned observer plans changed')

    def invalidate(self):
        for tracker in self.trackers: tracker.unavailable()

    def plan(self, plan):
        self.check()
        if type(plan) is not dict or type(plan.get('action')) is not str or c.core.canonical(plan) != c.core.canonical(self.plans.get(plan['action'])):
            raise c.ModelError('Plan is not the exact pinned observation operation')

    def current(self, now, summary, phase, *, max_age=5, finish=None):
        self.check()
        action = 'issue' if phase == 'issue' else summary['action']
        for tracker in self.trackers:
            if o.canonical(o.expected(summary)) != o.canonical(tracker.pins[action]):
                raise c.IntegrityError('Saved native semantics differ from observer pins')
        self.plan(summary['plan'])
        # Read current trackers each time; never trust a copied prior status dict.
        try: report = o.combined(*self.trackers, now)
        except o.ObservationError as exc: raise c.ModelError('Native observation unavailable') from exc
        if finish is not None: now = finish()
        for observed in report['observations']:
            at = observed['observed_at']
            if at is None or not 0 <= now - at <= max_age: return False
            if phase == 'issue':
                sample = observed['utxo_sample']
                if sample is None or not 0 <= now - sample['at'] <= max_age: return False
        wanted = {'issue':'ISSUED_UNSPENT', 'consume':'CONSUMPTION', 'refund':'REFUND'}[action]
        return report['state'] == 'TWO_NODE_' + wanted + '_OBSERVED'


class Controller(c.Controller):
    """Known-key fixture controller whose new work requires current tracker facts."""
    def __init__(self, root, authority_path, issue, clock, *, observations, **kwargs):
        if type(observations) is not Pair: raise c.ModelError('Pinned observer pair required')
        observations.check()
        component, authority = Path(root).resolve(), Path(authority_path).resolve()
        for tracker in observations.trackers:
            if component == tracker.path or component in tracker.path.parents or authority == tracker.path or authority.parent in tracker.path.parents:
                raise c.ModelError('Observer stores must be separate from controller and authority backups')
        self.observations = observations
        self.observation_pin = observations.id
        self.observers_seen = None
        super().__init__(root, authority_path, issue, clock, **kwargs)

    def _make_policy(self):
        self.observations.plan(self.issue)
        return c.Policy(c.core.canonical(self.issue).decode(), self.worker.fingerprint,
                        observation_pin=self.observation_pin)

    def _load(self, lease, reconcile=False):
        self.observations.check()
        if self.observations.id != self.observation_pin or self.policy.observation_pin != self.observation_pin:
            raise c.IntegrityError('Controller observation identity changed')
        state, previous = super()._load(lease, reconcile)
        if state['terminal_plan'] is not None: self.observations.plan(state['terminal_plan'])
        return state, previous

    def recover(self):
        self.observations.invalidate()
        self.observers_seen = None
        super().recover()

    def _current(self, lease, info, phase):
        def finish():
            lease.now = self._authority._time()
            return lease.now
        # Verify saved records before sampling time; recheck age at read completion.
        return self.observations.current(finish(), info, phase,
                                         max_age=self.policy.freshness, finish=finish)

    def _fresh_issue(self, lease, state):
        sessions = tuple(t.session for t in self.observations.trackers)
        if self.observers_seen != sessions:
            raise c.ModelError('Reconcile fresh observer handles before new work')
        if state['issue_attempt'] != 'OBSERVED' or not self._current(lease, self._summary(state, 'issue'), 'issue'):
            raise c.ModelError('Current matching unspent native ticket observations required')

    def choose(self, plan):
        self.observations.plan(plan)
        return super().choose(plan)

    def observe_fake(self, *args):
        raise c.ModelError('Fake acceptance maps cannot satisfy this observer-bound controller')

    def observe_native(self, phase):
        if phase not in ('issue', 'terminal'): raise c.ModelError('Unknown native observation phase')
        self.observers_seen = None
        with self.step() as (lease, state, previous):
            info = self._summary(state, phase)
            if state[phase + '_attempt'] == 'NONE': raise c.ModelError('No durable synthetic submission intent')
            exact = self._current(lease, info, phase)
            if exact:
                self.observers_seen = tuple(t.session for t in self.observations.trackers)
                if state[phase + '_attempt'] != 'OBSERVED':
                    state[phase + '_attempt'] = 'OBSERVED'
                    self._save(lease, state, previous, phase + '-observed')
            return exact

    def _public(self, state):
        return dict(super()._public(state), observation_binding=self.observation_pin)


def fixture_pair(root, issue, worker, *, min_successors=2, max_age=10):
    """Offline construction: unsigned pins only; never sign both terminal branches."""
    pins = {a: worker.pin(issue if a == 'issue' else worker.terminal(issue, a))
            for a in ('issue', 'consume', 'refund')}
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    reader = o.Reader()
    trackers = []
    try:
        for n in range(2):
            trackers.append(o.TicketTracker(root / f'node-{n}.sqlite', pins,
                f'wss://synthetic-{n}.invalid/kaspa/testnet-10/wrpc/borsh', o.fake_id(0),
                reader=reader, min_successors=min_successors, max_age=max_age))
        return Pair(*trackers)
    except BaseException:
        for tracker in trackers: tracker.close()
        raise


def demo():
    worker = c.Worker(); issue = o.fixture_pins()['issue']['plan']
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); now = [100]
        pair = fixture_pair(root / 'observations', issue, worker)
        control = Controller(root / 'component', root / 'independent/authority.sqlite', issue,
                             lambda: now[0], observations=pair, worker=worker, create=True)
        try:
            control.recover(); issued = control.prepare('issue')
            node = c.FakeNode(); control.submit_fake('issue', node)
            for tracker in pair.trackers:
                tracker.apply(o.fixture_scan(0,[1,2,3],transactions={1:[o.fixture_rpc(issued)]}),100)
                tracker.apply_utxos(o.fixture_utxos(tracker.summaries),100)
            assert control.observe_native('issue')
            control.choose(pair.plans['consume']); control.prepare('terminal')
            saved = control.status()
            for tracker in pair.trackers: tracker.apply(o.fixture_scan(3,removed=[3,2,1],target=0),101)
            now[0] = 101
            blocked = False
            try: control.submit_fake('terminal', node)
            except c.ModelError: blocked = True
            assert blocked and control.status() == saved
            # The observer stores remain separate and are never checkpointed as service history.
            return dict(mode=MODE, reorg_blocks_new_effect=blocked, permanent_state_preserved=control.status()==saved,
                        branch=saved['branch'], charge=saved['charge'], real_rpc_calls=0, broadcasts=0, content_keys=0)
        finally:
            control.close()
            for tracker in pair.trackers: tracker.close()


if __name__ == '__main__':
    print(json.dumps(demo(),indent=2,sort_keys=True))
