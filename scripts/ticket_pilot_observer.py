#!/usr/bin/env python3
"""P0-specific read-only trusted-node observations. No signer or submission API."""
from copy import deepcopy
import hashlib
import sqlite3
from urllib.parse import quote
from pathlib import Path

import native_ticket_observer as base
from ticket_pilot_review import Reviewer

MODE = 'TRUSTED_NODE_P0_OBSERVATION_ONLY'
Error = base.ObservationError
canonical = base.canonical


class Tracker(base.TicketTracker):
    observation_mode = MODE

    def __init__(self, path, review, endpoint, bootstrap, *, reader=None, reviewer=None,
                 min_successors=10, max_age=30):
        path = Path(path)
        if path.exists():
            # Do not add observer tables to a service journal/authority/claim DB.
            db = sqlite3.connect('file:'+quote(str(path.resolve()),safe='/')+'?mode=ro',uri=True)
            try:
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if tables not in (set(), {'ticket_meta','ticket_blocks'}):
                    raise Error('P0 observation requires a separate observer database')
            finally: db.close()
        self.reviewer = reviewer or Reviewer()
        self.source_sample = None
        super().__init__(path, review, endpoint, bootstrap, reader=reader,
                         min_successors=min_successors, max_age=max_age)
        self.review = self.summaries
        self.plan = self.review['plan']
        self.funding_key = self.plan['funding_key']
        source = self.plan['source']
        self.source = (source['transaction_id'], source['index'])
        self.source_output = dict(value=source['amount'], script_version=0,
                                  script='20'+self.funding_key+'ac', covenant=None)
        self._sealed = canonical(self._descriptor())

    def _prepare_pins(self, review):
        verified = self.reviewer.verify(review)
        if review['plan']['purpose'] != 'operator-unsigned-review':
            raise Error('P0 observation requires an operator public review; never fund fixtures')
        self.review_id = verified['review_id']
        pins = {}
        for action in ('issue','consume','refund'):
            txs = [t for t in verified['transactions'] if t['action'] == action]
            if len(txs) != 1: raise Error('Exact P0 action preview required')
            tx = deepcopy(txs[0]['unsigned_rpc'])
            tx['verboseData'] = dict(transactionId=txs[0]['transaction_id'])
            pins[action] = self.reader.project_p0(tx)
        if len({p['transaction_id'] for p in pins.values()}) != 3:
            raise Error('Distinct P0 transactions required')
        return pins, review['plan']['ticket_key']

    def _pin_identity(self):
        return dict(mode=MODE, pins=self.pins, depth=self.depth, age=self.max_age,
                    review=self.summaries, reviewer=self.reviewer.fingerprint)

    def _descriptor(self):
        return dict(identity=self._pin_identity(), path=str(self.path), endpoint=self.endpoint,
                    host=self.host, bootstrap=self.bootstrap, reader=self.reader.fingerprint,
                    reader_endpoint=self.reader.endpoint, pin=self.pin_id, review_id=self.review_id,
                    ticket_key=self.ticket_key, ticket=self.ticket, issue_id=self.issue_id,
                    funding=self.funding, mode=self.observation_mode, funding_key=self.funding_key,
                    source=self.source, source_output=self.source_output, plan=self.plan,
                    review=self.review, config=self._get('config'))

    def _check(self):
        try:
            if (canonical(self._descriptor()) != self._sealed
                or hashlib.sha256(self.reader.binary.read_bytes()).hexdigest() != self.reader.fingerprint
                or hashlib.sha256(self.reviewer.binary.read_bytes()).hexdigest() != self.reviewer.fingerprint):
                raise Error('Pinned P0 observation configuration or binary changed')
        except OSError as exc:
            raise Error('Pinned P0 observation binary unavailable') from exc

    def _project(self, transaction):
        return self.reader.project_p0(transaction)

    def unavailable(self):
        self.source_sample = None
        super().unavailable()

    def apply(self, response, observed_at):
        self._check()
        return super().apply(response, observed_at)

    @staticmethod
    def _entry(response, public_key, outpoint, output):
        """Positive exact UTXO metadata, including the asserted creation DAA score."""
        try:
            base.guard(response['node'])
            if response['publicKey'] != public_key or type(response['utxos']) is not list or len(response['utxos']) > 100000:
                raise Error('Wrong P0 query or oversized UTXO sample')
            base.txid(response['from']); base.txid(response['target'])
            found = None; seen = set()
            for row in response['utxos']:
                point = base.point(row['outpoint'])
                if point in seen: raise Error('Duplicate P0 UTXO')
                seen.add(point)
                if point == outpoint:
                    entry = row['utxoEntry']
                    if (set(entry) != {'amount','scriptPublicKey','blockDaaScore','isCoinbase','covenantId'}
                        or base.integer(entry['amount']) != output['value']
                        or entry['scriptPublicKey'] != '0000'+output['script']
                        or entry['isCoinbase'] is not False or entry['covenantId'] is not None):
                        raise Error('Exact ordinary P0 UTXO required')
                    base.integer(entry['blockDaaScore'])
                    if entry['blockDaaScore'] > response['node']['virtualDaaScore']:
                        raise Error('UTXO creation DAA is ahead of sampled node')
                    found = deepcopy(entry)
            return found
        except (KeyError, TypeError, base.WatchError) as exc:
            raise Error('Malformed P0 UTXO sample') from exc

    def apply_utxos(self, response, observed_at):
        self._check(); self.utxo_sample = None
        entry = self._entry(response, self.ticket_key, self.ticket, self.pins['issue']['outputs'][0])
        super().apply_utxos(response, observed_at)
        self.utxo_sample['entry'] = entry

    def apply_source_utxos(self, response, observed_at):
        self._check(); self.source_sample = None
        at = self._clock(observed_at)
        entry = self._entry(response, self.funding_key, self.source, self.source_output)
        self.source_sample = dict(at=at, before=response['from'], after=response['target'],
                                  found=entry is not None, entry=entry)

    def _sample_positions(self, sample, now):
        if sample is None or not 0 <= now-sample['at'] <= self.max_age: return None
        positions = [self._position(sample[k]) for k in ('before','after')]
        return positions if None not in positions and positions[0] <= positions[1] else None

    def status(self, now):
        self._check(); report = super().status(now)
        positions = self._sample_positions(self.source_sample, now)
        if report['state'] == 'ISSUE_NOT_FOUND':
            if positions is None: report['state'] = 'SOURCE_SAMPLE_REQUIRED'
            elif not self.source_sample['found']: report['state'] = 'SOURCE_NOT_UNSPENT'
            else: report['state'] = 'SOURCE_UNSPENT_OBSERVED'
        elif (report['issue'] is not None and positions is not None
              and self.source_sample['found'] and report['issue']['position'] <= positions[0]
              and report['state'] not in ('SCAN_REQUIRED','STALE','CHAIN_BACKLOG')):
            report['state'] = 'INCONSISTENT_SOURCE_UTXO_VIEW'
        report.update(review_id=self.review_id, source_outpoint=dict(transaction_id=self.source[0],index=self.source[1]),
                      source_sample=deepcopy(self.source_sample))
        return report

    def poll(self, native, clock):
        self.unavailable(); self._check()
        if type(native) is not base.Reader or native.endpoint != self.endpoint or native.fingerprint != self.reader.fingerprint:
            raise Error('Wrong P0 read-only endpoint/adapter')
        try:
            source_at = base.integer(clock()); source = native.utxos(self.funding_key)
            ticket_at = base.integer(clock()); ticket = native.utxos(self.ticket_key)
            scan_at = base.integer(clock()); scan = native.scan(self.tip)
            self.apply_source_utxos(source, source_at); source_sample = self.source_sample
            self.apply_utxos(ticket, ticket_at); ticket_sample = self.utxo_sample
            self.apply(scan, scan_at)
            self.source_sample, self.utxo_sample = source_sample, ticket_sample
            return self.status(clock())
        except BaseException:
            self.unavailable(); raise


def combined(first, second, now):
    if any(type(t) is not Tracker for t in (first,second)):
        raise Error('Two exact P0 trackers required; fixture trackers cannot be substituted')
    if first.path == second.path or first.host == second.host or first.pin_id != second.pin_id:
        raise Error('Two distinct P0 node hosts/databases and one exact review/policy required')
    a,b = first.status(now), second.status(now)
    state = 'TWO_NODE_GATE_BLOCKED'
    if a['state'] == b['state']:
        label = a['state']
        if label in ('SOURCE_UNSPENT_OBSERVED','ISSUED_UNSPENT_OBSERVED'):
            field = 'source_sample' if label == 'SOURCE_UNSPENT_OBSERVED' else 'utxo_sample'
            if a[field]['entry'] == b[field]['entry']: state = 'TWO_NODE_'+label
        elif label in ('CONSUMPTION_OBSERVED','REFUND_OBSERVED'):
            if a['spend']['transaction_id'] == b['spend']['transaction_id']: state = 'TWO_NODE_'+label
    return dict(mode=MODE,state=state,review_id=first.review_id,observations=[a,b])


def poll_pair(first, second, clock):
    """Sequential bounded reads; any failed node invalidates both cached views."""
    if any(type(t) is not Tracker for t in (first,second)): raise Error('Exact P0 trackers required')
    try:
        # Validate pair identity before any network call.
        if first.path == second.path or first.host == second.host or first.pin_id != second.pin_id:
            raise Error('Distinct matching P0 node pair required')
        for tracker in (first,second): tracker.poll(tracker.reader,clock)
        return combined(first,second,clock())
    except BaseException:
        for tracker in (first,second): tracker.unavailable()
        raise


def main(argv=None):
    import argparse
    import json
    import time
    from ticket_pilot_review import load
    parser = argparse.ArgumentParser(description='Read-only TN10 P0 observations; no signing or submission')
    commands = parser.add_subparsers(dest='command',required=True)
    observe = commands.add_parser('observe')
    for name in ('review','first_db','first_endpoint','first_bootstrap',
                 'second_db','second_endpoint','second_bootstrap'): observe.add_argument(name)
    args = parser.parse_args(argv)
    review = load(args.review)
    trackers = []
    try:
        for role in ('first','second'):
            trackers.append(Tracker(getattr(args,role+'_db'),review,getattr(args,role+'_endpoint'),
                                    getattr(args,role+'_bootstrap')))
        report = poll_pair(*trackers,lambda:int(time.time()))
        print(json.dumps(report,indent=2,sort_keys=True))
        return report
    finally:
        for tracker in trackers: tracker.close()


if __name__ == '__main__':
    main()
