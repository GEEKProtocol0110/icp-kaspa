#!/usr/bin/env python3
"""Pinned TN10 network submission capability; live acceptance requires a separate pilot."""
from copy import deepcopy
from dataclasses import dataclass
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from urllib.parse import urlsplit

import ticket_pilot_private as private
import ticket_pilot_submission as submission

MODE = 'TN10_P0_LIVE_SUBMISSION_CONTROLLER_NO_AUTHORIZATION'
REQUEST_MODE = 'TN10_P0_SUBMISSION_REQUEST_V0'


def endpoint(value):
    if type(value) is not str: raise private.Error('Pinned TLS TN10 endpoint required')
    p=urlsplit(value)
    if (p.scheme!='wss' or not p.hostname or p.username or p.password or p.query or p.fragment
        or p.path!='/kaspa/testnet-10/wrpc/borsh' or len(p.hostname)>253
        or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in p.hostname.split('.'))):
        raise private.Error('Canonical TLS TN10 endpoint required')
    host=p.hostname
    try:
        authority=host+(':'+str(p.port) if p.port is not None and p.port>0 else '')
    except ValueError as exc: raise private.Error('Invalid endpoint port') from exc
    if value!='wss://'+authority+p.path: raise private.Error('Canonical endpoint spelling required')
    return value


class Transport:
    def __init__(self, url, *, binary=None, relay=None):
        self.endpoint=endpoint(url)
        self.binary=Path(binary or private.ROOT/'target/debug/examples/ticket_pilot_submit').resolve()
        self.relay=Path(relay or private.ROOT/'scripts/with_proxy.py').resolve()
        self.binary_hash=private.sha(self.binary.read_bytes()); self.relay_hash=private.sha(self.relay.read_bytes())
        self._sealed=private.canonical(self.descriptor())

    def descriptor(self):
        return dict(mode=MODE,endpoint=self.endpoint,binary=str(self.binary),binary_hash=self.binary_hash,
                    relay=str(self.relay),relay_hash=self.relay_hash,timeout=40,max_input=65536,max_output=4096)

    def check(self):
        try:
            endpoint(self.endpoint)
            if (private.canonical(self.descriptor())!=self._sealed
                or private.sha(self.binary.read_bytes())!=self.binary_hash
                or private.sha(self.relay.read_bytes())!=self.relay_hash):
                raise private.IntegrityError('Pinned TN10 sender or relay changed')
        except (OSError,ValueError) as exc:
            raise private.IntegrityError('Pinned TN10 transport unavailable or changed') from exc

    def send(self, payload):
        self.check()
        if (type(payload) is not dict or set(payload)!={'mode','endpoint','not_before','not_after','record'}
            or payload['mode']!=REQUEST_MODE or payload['endpoint']!=self.endpoint
            or any(type(payload[k]) is not int or not 0<=payload[k]<2**53 for k in ('not_before','not_after'))
            or not 0<payload['not_after']-payload['not_before']<=30):
            raise private.Error('Exact bounded TN10 dispatch request required')
        raw=private.canonical(payload)
        if len(raw)>65536: raise private.Error('Oversized native submission request')
        env={k:v for k,v in os.environ.items() if k in ('PATH','HTTPS_PROXY','HTTP_PROXY','ALL_PROXY','NO_PROXY')}
        env['ICP_UPSTREAM_URL']=self.endpoint
        command=[sys.executable,str(self.relay),str(self.binary),'submit']
        process=subprocess.Popen(command,cwd=private.ROOT,env=env,stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
        # Incremental bounded pipes: do not buffer unbounded native/remote diagnostics.
        output=bytearray(); offset=0; deadline=time.monotonic()+40
        try:
            os.set_blocking(process.stdin.fileno(),False); os.set_blocking(process.stdout.fileno(),False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdin,selectors.EVENT_WRITE)
                selector.register(process.stdout,selectors.EVENT_READ)
                while selector.get_map():
                    remaining=deadline-time.monotonic()
                    if remaining<=0: raise TimeoutError('Native submission outcome unknown')
                    for key,_ in selector.select(remaining):
                        if key.fileobj is process.stdin:
                            try: offset+=os.write(process.stdin.fileno(),raw[offset:offset+4096])
                            except BrokenPipeError: offset=len(raw)
                            if offset==len(raw): selector.unregister(process.stdin); process.stdin.close()
                        else:
                            part=os.read(process.stdout.fileno(),4096)
                            if not part: selector.unregister(process.stdout); process.stdout.close()
                            else:
                                output.extend(part)
                                if len(output)>4096: raise private.Error('Native reply exceeds bounded limit')
            process.wait(timeout=max(0.001,deadline-time.monotonic()))
            if process.returncode: raise private.RecoveryRequired('Native submission outcome unknown')
            return private.decode(bytes(output))
        except BaseException:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=5)
            raise
        finally:
            for stream in (process.stdin,process.stdout):
                if not stream.closed: stream.close()


@dataclass(frozen=True)
class Policy(submission.Policy):
    @property
    def id(self):
        return private.sha(private.canonical(dict(mode=MODE,**self.__dict__)))


class Controller(submission.Controller):
    mode=MODE
    transport_type=Transport
    policy_type=Policy
    submission_role='p0-live-submission'

    def __init__(self,*args,transport,observations,**kwargs):
        if (type(observations) is not submission.binding.Pair or type(transport) is not Transport
            or transport.endpoint!=observations.trackers[0].endpoint):
            raise private.Error('TN10 submission endpoint must match the first pinned observer')
        super().__init__(*args,transport=transport,observations=observations,**kwargs)

    def _check_transport(self):
        super()._check_transport()
        if self.transport.endpoint!=self.observations.trackers[0].endpoint:
            raise private.IntegrityError('TN10 sender/observer endpoint mismatch')

    def submit_simulated(self,phase):
        raise private.Error('Live policy requires the explicit submit API')

    def submit(self,phase):
        return self._submit(phase)

    def _payload(self,record):
        return deepcopy(record)

    def _send(self,record,lease,report):
        timestamps=[]
        for observed in report['observations']:
            sample='source_sample' if record['action']=='issue' else 'utxo_sample'
            timestamps.extend((observed['observed_at'],observed[sample]['at']))
        expires=min(timestamps)+self.observations.freshness
        return self.transport.send(dict(mode=REQUEST_MODE,endpoint=self.transport.endpoint,
            not_before=lease.now,not_after=expires,record=record))

    def _transport_status(self):
        return dict(network_submission_capable=True,transport_scope='TN10_ONLY_NOT_ACCEPTANCE_PROOF')
