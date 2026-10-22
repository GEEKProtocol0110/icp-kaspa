#!/usr/bin/env python3
"""Durable P0 submission experiment. Transport effects are strictly simulated."""
from copy import deepcopy
from dataclasses import dataclass
import json
from pathlib import Path
import re

import ticket_pilot_binding as binding
import ticket_pilot_private as private

MODE = 'P0_SUBMISSION_JOURNAL_SIMULATED_TRANSPORT_NO_LIVE_PROOF'
REPLIES = ('REPORTED_ACCEPTED', 'REPORTED_REJECTED', 'UNKNOWN')


class SimulatedTransport:
    """No network implementation or interchangeable live adapter in this milestone."""
    def __init__(self, name='test-transport'):
        if type(name) is not str or not re.fullmatch(r'[a-z0-9-]{1,40}', name):
            raise private.Error('Bounded simulated transport name required')
        self.name = name; self.calls = []
        self._sealed = private.canonical(self.descriptor())

    def descriptor(self):
        return dict(mode=MODE, name=self.name)

    def check(self):
        if private.canonical(self.descriptor()) != self._sealed:
            raise private.IntegrityError('Pinned simulated transport changed')

    def send(self, transaction_id, signed_rpc):
        self.check()
        self.calls.append(dict(transaction_id=transaction_id, signed_rpc=deepcopy(signed_rpc)))
        return dict(transaction_id=transaction_id, accepted=True)


@dataclass(frozen=True)
class Policy(private.Policy):
    transport_pin: str = ''

    @property
    def id(self):
        return private.sha(private.canonical(dict(mode=MODE, **self.__dict__)))


def initial():
    return dict(mode=MODE, **{p:dict(intent=None, reply=None) for p in ('issue','terminal')})


class Controller(binding.Controller):
    """One durable attempt per saved outbox; every uncertain outcome is read-only."""
    def __init__(self, root, authority_path, claims_path, review, clock, *, transport, create=False, **kwargs):
        if type(transport) is not SimulatedTransport:
            raise private.Error('Exact simulated transport required; live submission unavailable')
        transport.check()
        self.transport = transport
        self.transport_pin = private.sha(private.canonical(transport.descriptor()))
        self._submission = None
        path = Path(root)/'submission.sqlite'
        if path.resolve() in (Path(authority_path).resolve(),Path(claims_path).resolve()):
            raise private.Error('Separate submission component store required')
        if create and path.exists(): raise private.Error('Refuse existing submission journal')
        try:
            super().__init__(root,authority_path,claims_path,review,clock,create=create,**kwargs)
            private.private_file(path,create)
            self._submission = private.core.Journal(path,'p0-submission',self.policy,
                                                     self._authority.id,initial(),create)
            if create:
                with self._authority.serial(self.generation,recovery=True) as lease:
                    seq,h = self._submission.db.execute('SELECT seq,hash FROM events').fetchone()
                    self._authority.checkpoint(lease,self._submission.role,seq,h)
        except BaseException:
            self.close(); raise

    def close(self):
        if self._submission is not None: self._submission.db.close()
        # Parent construction can fail before it has opened any store.
        if hasattr(self,'_authority'): super().close()

    def _make_policy(self, claims_path):
        return Policy(private.canonical(self.review).decode(),self.reviewer.fingerprint,
                      self.worker.fingerprint,str(claims_path.resolve()),self.observation_pin,
                      self.transport_pin)

    def _summary(self, state):
        result = super()._summary(state)
        result['mode'] = MODE
        return result

    def _check_transport(self):
        if (type(self.transport) is not SimulatedTransport
            or private.sha(private.canonical(self.transport.descriptor())) != self.transport_pin
            or self.policy.transport_pin != self.transport_pin):
            raise private.IntegrityError('Submission transport policy changed')
        self.transport.check()

    @staticmethod
    def _intent(record):
        return dict(record_sha256=private.sha(private.canonical(record)),
                    transaction_id=record['transaction_id'],action=record['action'])

    def _load(self, lease, reconcile=False):
        self._check_transport()
        state,previous = super()._load(lease,reconcile)
        self._load_submission(lease,state,reconcile)
        return state,previous

    def _load_submission(self, lease, private_state, reconcile=False):
        state,previous = self._submission.load(lease,reconcile)
        old = None
        for raw, in self._submission.db.execute('SELECT body FROM events ORDER BY seq'):
            body = json.loads(raw); row = body['state']
            if set(row) != set(initial()) or row['mode'] != MODE:
                raise private.IntegrityError('Wrong submission state shape')
            for phase in ('issue','terminal'):
                part = row[phase]
                if type(part) is not dict or set(part) != {'intent','reply'}:
                    raise private.IntegrityError('Wrong submission phase shape')
                intent,reply = part['intent'],part['reply']
                if reply is not None and (type(reply) is not str or reply not in REPLIES or intent is None):
                    raise private.IntegrityError('Reply without one submission intent')
                if intent is not None:
                    record = private_state[phase+'_record']
                    if record is None or private.canonical(intent) != private.canonical(self._intent(record)):
                        raise private.IntegrityError('Submission intent differs from exact native outbox')
                    if phase == 'terminal' and row['issue']['intent'] is None:
                        raise private.IntegrityError('Terminal attempt without issuance attempt')
            if old is None:
                if row != initial() or body['kind'] != 'genesis':
                    raise private.IntegrityError('Wrong submission genesis')
            else:
                valid = False
                for phase in ('issue','terminal'):
                    for field,kind in (('intent','intent'),('reply','reply')):
                        expected = deepcopy(old); expected[phase][field] = row[phase][field]
                        if (body['kind'] == phase+'-submission-'+kind and row == expected
                            and old[phase][field] is None and row[phase][field] is not None):
                            valid = True
                if not valid: raise private.IntegrityError('Submission history reset or skipped an intent')
            old = row
        return state,previous

    @staticmethod
    def _phase(phase):
        if phase not in ('issue','terminal'): raise private.Error('Invalid submission phase')

    def submit_simulated(self, phase):
        self._phase(phase)
        # The intent commits before transport access. Even a crash before send is uncertain.
        with self._step() as (lease, state, _):
            attempts,previous = self._load_submission(lease,state)
            if attempts[phase]['intent'] is not None:
                raise private.RecoveryRequired('Submission already attempted; reconcile without retry')
            record = state[phase+'_record']
            if record is None: raise private.Error('Save an exact signed outbox before submission')
            if phase == 'terminal' and attempts['issue']['intent'] is None:
                raise private.Error('Issuance submission intent required before terminal submission')
            self._require_current(lease,phase=phase,entry=record['entry'])
            attempts[phase]['intent'] = self._intent(record)
            self._submission.save(lease,attempts,phase+'-submission-intent',previous,self.hook)
        self.hook('submission:reserved')
        # Reopening/recovery fences this lease before any effect. Hold it through send.
        with self._step() as (lease, state, _):
            attempts,previous = self._load_submission(lease,state)
            record = state[phase+'_record']
            rpc = deepcopy(record['signed_rpc']); txid = record['transaction_id']
            self._check_transport()
            self._require_current(lease,phase=phase,entry=record['entry'])
            try:
                reply = self.transport.send(txid,rpc)
                result = 'UNKNOWN'
                if (type(reply) is dict and set(reply) == {'transaction_id','accepted'}
                    and reply['transaction_id'] == txid and type(reply['accepted']) is bool):
                    result = 'REPORTED_ACCEPTED' if reply['accepted'] else 'REPORTED_REJECTED'
            except Exception:
                result = 'UNKNOWN'
            self.hook('submission:returned')
            attempts[phase]['reply'] = result
            self._submission.save(lease,attempts,phase+'-submission-reply',previous,self.hook)
        self.hook('submission:acknowledged')
        return self.status()

    def reconcile_submission(self, phase):
        """Read current trackers only; never sign/send or make observations permanent."""
        self._phase(phase)
        with self._step() as (lease, state, _):
            attempts,_ = self._load_submission(lease,state)
            if attempts[phase]['intent'] is None:
                raise private.Error('No local submission intent to reconcile')
            report = self._require_current(lease,phase='reconcile')
            action = state[phase+'_record']['action']
            terminal = {'consume':'TWO_NODE_CONSUMPTION_OBSERVED','refund':'TWO_NODE_REFUND_OBSERVED'}
            if phase == 'issue':
                exact = report['state'] in ('TWO_NODE_ISSUED_UNSPENT_OBSERVED',*terminal.values())
            else:
                exact = report['state'] == terminal[action]
            return dict(mode=MODE,phase=phase,transaction_id=attempts[phase]['intent']['transaction_id'],
                        current_exact_observed=exact,observation_state=report['state'],
                        checked_at=lease.now,scope='REVOCABLE_TRUSTED_NODE_OBSERVATION',
                        retry_allowed=False)

    def status(self):
        with self._step() as (lease, state, _):
            attempts,_ = self._load_submission(lease,state)
            result = self._summary(state)
            result.pop('broadcasts')
            result.update(mode=MODE,transport_policy=self.transport_pin,live_broadcasts=0,
                          submissions={p:dict(intent=attempts[p]['intent'],reply=attempts[p]['reply'],
                                               retry_allowed=False) for p in ('issue','terminal')})
            return result
