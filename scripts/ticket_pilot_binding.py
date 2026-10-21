#!/usr/bin/env python3
"""P0 observations gate new private preparation. No submission or authorization."""
from copy import deepcopy
from pathlib import Path

import ticket_pilot_private as private
import ticket_pilot_observer as observer

MODE = 'P0_OBSERVATION_BOUND_PREPARATION_NO_SUBMISSION_OR_AUTHORIZATION'


class Pair:
    """Current trusted trackers only; public status dictionaries are never a gate."""
    def __init__(self, first, second, *, freshness=5):
        if any(type(t) is not observer.Tracker for t in (first,second)):
            raise private.Error('Two exact P0 trackers required')
        if (first.path == second.path or first.host == second.host or first.pin_id != second.pin_id):
            raise private.Error('Distinct observer paths/hosts with matching P0 policy required')
        if type(freshness) is not int or not 1 <= freshness <= 30:
            raise private.Error('Invalid P0 binding freshness')
        self.trackers = (first,second); self.freshness = freshness
        self.review = deepcopy(first.review)
        self._sealed = deepcopy(self.descriptor())
        self.id = self._identity()
        self.check()

    def descriptor(self):
        return dict(freshness=self.freshness, review=self.review,
                    trackers=[t._descriptor() for t in self.trackers])

    def _identity(self):
        return private.sha(b'icp/p0-observation-binding/v0\0'+private.canonical(self._sealed))

    def check(self):
        if (len(self.trackers) != 2 or any(type(t) is not observer.Tracker for t in self.trackers)
            or private.canonical(self.descriptor()) != private.canonical(self._sealed)
            or self.id != self._identity()):
            raise private.IntegrityError('Pinned P0 observation pair changed')
        try:
            for tracker in self.trackers: tracker._check()
        except observer.Error as exc:
            raise private.IntegrityError('Pinned P0 tracker changed or unavailable') from exc

    def sessions(self):
        self.check()
        sessions = tuple(t.session for t in self.trackers)
        if sessions != tuple(t._get('session') for t in self.trackers):
            raise private.Error('P0 observer handle superseded; reopen and reconcile')
        return sessions

    def invalidate(self):
        for tracker in self.trackers: tracker.unavailable()

    def current(self, now, *, phase=None, entry=None, finish):
        self.check(); sessions = self.sessions()
        try: report = observer.combined(*self.trackers,now)
        except observer.Error as exc:
            raise private.Error('Current P0 observation unavailable') from exc
        # Status/verification may take time. Never decide with the lease-entry clock.
        if self.sessions() != sessions: raise private.Error('P0 handles changed during observation')
        now = finish()
        allowed = ('SOURCE_UNSPENT','ISSUED_UNSPENT','CONSUMPTION','REFUND')
        wanted = 'SOURCE_UNSPENT' if phase == 'issue' else 'ISSUED_UNSPENT' if phase in ('terminal','choice') else None
        if report['state'] not in tuple('TWO_NODE_'+s+'_OBSERVED' for s in allowed):
            raise private.Error('Two current matching P0 observations required')
        if wanted is not None and report['state'] != 'TWO_NODE_'+wanted+'_OBSERVED':
            raise private.Error('P0 outpoint is not currently observed unspent for this operation')
        for observed in report['observations']:
            at = observed['observed_at']
            if at is None or not 0 <= now-at <= self.freshness:
                raise private.Error('P0 accepted-chain observation expired')
            sample_name = 'source_sample' if observed['state'] == 'SOURCE_UNSPENT_OBSERVED' else 'utxo_sample'
            if observed['state'] in ('SOURCE_UNSPENT_OBSERVED','ISSUED_UNSPENT_OBSERVED'):
                sample = observed[sample_name]
                if sample is None or not 0 <= now-sample['at'] <= self.freshness:
                    raise private.Error('Positive P0 UTXO observation expired')
                if entry is not None and private.canonical(entry) != private.canonical(sample['entry']):
                    raise private.Error('Signing entry differs from current two-node metadata')
        return report


class Controller(private.Controller):
    """Separate policy identity; the offline controller cannot reopen this journal."""
    def __init__(self, root, authority_path, claims_path, review, clock, *, observations, **kwargs):
        if type(observations) is not Pair: raise private.Error('Exact pinned P0 pair required')
        observations.check()
        if private.canonical(review) != private.canonical(observations.review):
            raise private.Error('Controller and observers require the same complete public review')
        component = Path(root).resolve()
        stores = {Path(authority_path).resolve(),Path(claims_path).resolve(),component/'pilot.sqlite'}
        # Observers belong in their own directory, outside private store backup directories.
        backups = {component,Path(authority_path).resolve().parent,Path(claims_path).resolve().parent}
        for tracker in observations.trackers:
            if tracker.path in stores or any(p == tracker.path or p in tracker.path.parents for p in backups):
                raise private.Error('Observer stores must be outside private backup directories')
        self.observations = observations; self.observation_pin = observations.id
        self._seen_sessions = None
        super().__init__(root,authority_path,claims_path,review,clock,**kwargs)

    def _make_policy(self, claims_path):
        return private.Policy(private.canonical(self.review).decode(),self.reviewer.fingerprint,
                              self.worker.fingerprint,str(claims_path.resolve()),self.observation_pin)

    def _load(self, lease, reconcile=False):
        self.observations.check()
        if (self.observations.id != self.observation_pin
            or self.policy.observation_pin != self.observation_pin
            or private.canonical(self.review) != private.canonical(self.observations.review)):
            raise private.IntegrityError('Private P0 observation policy changed')
        return super()._load(lease,reconcile)

    def recover(self):
        self._seen_sessions = None; self.observations.invalidate()
        super().recover()

    def _current(self, lease, *, phase=None, entry=None):
        def finish():
            lease.now = self._authority._time()
            return lease.now
        return self.observations.current(finish(),phase=phase,entry=entry,finish=finish)

    def reconcile_observations(self):
        self._seen_sessions = None
        with self._step() as (lease, _, _):
            self._current(lease)
            self._seen_sessions = self.observations.sessions()
        return self.status()

    def _require_current(self, lease, *, phase, entry=None):
        if self._seen_sessions != self.observations.sessions():
            raise private.Error('Reconcile fresh P0 observer handles before new work')
        return self._current(lease,phase=phase,entry=entry)

    def _before_choice(self, lease, state):
        self._require_current(lease,phase='choice')

    def _before_signing(self, lease, state, phase, entry):
        if type(entry) is not dict: raise private.Error('Complete current P0 signing entry required')
        self._require_current(lease,phase=phase,entry=entry)

    def _summary(self, state):
        result = super()._summary(state)
        result.pop('source_observed')
        result.update(mode=MODE,observation_policy=self.observation_pin,
                      status_scope='HISTORICAL_OUTBOX_NOT_CURRENT_CHAIN_PROOF')
        return result
