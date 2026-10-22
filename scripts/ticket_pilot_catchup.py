#!/usr/bin/env python3
"""Historical P0 catch-up only. Existing fresh snapshot remains the effect gate."""
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

import native_ticket_observer as base
import ticket_pilot_observer as observer

MODE = 'TN10_P0_HISTORY_CATCHUP_V1'
WINDOWS = (16, 64, 256, 1024)


class HistoryReader:
    def __init__(self, endpoint, binary, *, relay=None):
        base.endpoint_host(endpoint)
        self.endpoint = endpoint
        self.binary = Path(binary).resolve()
        self.relay = Path(relay or base.ROOT/'scripts/with_proxy.py').resolve()
        self.binary_hash = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.relay_hash = hashlib.sha256(self.relay.read_bytes()).hexdigest()
        self._sealed = base.canonical(self.descriptor())

    def descriptor(self):
        return dict(mode=MODE, endpoint=self.endpoint, binary=str(self.binary),
                    binary_hash=self.binary_hash, relay=str(self.relay), relay_hash=self.relay_hash)

    def check(self):
        if (base.canonical(self.descriptor()) != self._sealed
            or hashlib.sha256(self.binary.read_bytes()).hexdigest() != self.binary_hash
            or hashlib.sha256(self.relay.read_bytes()).hexdigest() != self.relay_hash):
            raise base.ObservationError('Pinned history helper changed')

    def page(self, cursor, window):
        self.check(); base.txid(cursor)
        if type(window) is not int or window not in WINDOWS:
            raise base.ObservationError('Supported history window required')
        env = {k:v for k,v in os.environ.items() if k in ('PATH','HTTPS_PROXY','HTTP_PROXY','ALL_PROXY','NO_PROXY')}
        env['ICP_UPSTREAM_URL'] = self.endpoint
        process = subprocess.Popen([sys.executable,str(self.relay),str(self.binary)],
            cwd=base.ROOT,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,start_new_session=True)
        try:
            output,_ = process.communicate(base.canonical(dict(cursor=cursor,window=window)),timeout=30)
            if process.returncode or len(output)>32_000_000:
                raise base.ObservationError('Bounded history read failed')
        except BaseException:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.communicate(); raise
        return validate(base.decode(output),cursor,window)


def validate(value, cursor, window):
    try:
        if (type(value) is not dict or set(value) != {
                'mode','window','start_blue_score','sink_blue_score','min_confirmation_count','scan'}
            or value['mode'] != MODE or type(value['window']) is not int or value['window'] != window):
            raise base.ObservationError('Wrong history profile/window')
        for k in ('start_blue_score','sink_blue_score','min_confirmation_count'):
            if type(value[k]) is not int or not 0 <= value[k] < 2**64:
                raise base.ObservationError('Invalid history score')
        if value['min_confirmation_count'] != max(0,value['sink_blue_score']-value['start_blue_score']-window):
            raise base.ObservationError('Changed history hint')
        scan=value['scan']
        if set(scan) != {'node','from','target','changes'} or scan['from'] != cursor:
            raise base.ObservationError('Wrong history cursor')
        base.txid(scan['target']); base.guard(scan['node'])
        if set(scan['changes']) != {'removedChainBlockHashes','addedChainBlockHashes','chainBlockAcceptedTransactions'}:
            raise base.ObservationError('Wrong history changes')
        return value
    except (KeyError,TypeError,base.WatchError) as exc:
        raise base.ObservationError('Malformed history page') from exc


def advance(tracker, reader, clock, window=256):
    """Apply full accepted history through existing validation; never supply UTXOs."""
    if type(tracker) is not observer.Tracker or type(reader) is not HistoryReader:
        raise base.ObservationError('Exact P0 tracker and separate history reader required')
    tracker.unavailable()
    try:
        tracker._check(); reader.check()
        if reader.endpoint != tracker.endpoint:
            raise base.ObservationError('History endpoint differs from pinned tracker')
        descriptor=base.canonical(tracker._descriptor()); start=tracker.tip
        started=base.integer(clock())
        tracker._clock(started)
        value=reader.page(start,window)
        # Validate again at the import boundary, including callers testing an adapter.
        validate(value,start,window)
        if tracker.tip != start or base.canonical(tracker._descriptor()) != descriptor:
            raise base.ObservationError('History tracker changed during read')
        tracker.apply(value['scan'],started)
        return dict(mode=MODE,from_cursor=start,cursor=tracker.tip,
                    sampled_target=value['scan']['target'],window=window,
                    caught_up=tracker.tip == value['scan']['target'],
                    eligibility=False,scope='HISTORY_ONLY_REQUIRES_FRESH_PINNED_SNAPSHOT')
    finally:
        # apply() marks a scan ready. Historical imports must never authorize effects.
        tracker.unavailable()


def main(argv=None):
    import argparse
    from ticket_pilot_review import Reviewer, load
    parser=argparse.ArgumentParser(description='P0 history catch-up; no keys, private journals or submissions')
    parser.add_argument('review'); parser.add_argument('database'); parser.add_argument('endpoint'); parser.add_argument('bootstrap')
    parser.add_argument('--binary',required=True); parser.add_argument('--reader',required=True); parser.add_argument('--reviewer',required=True)
    parser.add_argument('--window',type=int,choices=WINDOWS,default=256)
    parser.add_argument('--pages',type=int,default=1)
    parser.add_argument('--min-successors',type=int,default=10); parser.add_argument('--max-age',type=int,default=30)
    a=parser.parse_args(argv)
    if not Path(a.database).is_file() or not 1 <= a.pages <= 128:
        parser.error('Existing observer database and 1..128 pages required')
    tracker=observer.Tracker(a.database,load(a.review),a.endpoint,a.bootstrap,
        reader=base.Reader(a.endpoint,a.reader),reviewer=Reviewer(a.reviewer),
        min_successors=a.min_successors,max_age=a.max_age)
    try:
        reader=HistoryReader(a.endpoint,a.binary)
        for _ in range(a.pages):
            report=advance(tracker,reader,lambda:int(time.time()),a.window)
            print(json.dumps(report,sort_keys=True),flush=True)
            if report['caught_up']: break
    finally: tracker.close()


if __name__ == '__main__': main()
