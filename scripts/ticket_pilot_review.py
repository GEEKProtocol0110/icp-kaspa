#!/usr/bin/env python3
"""Unsigned public P0 review receipts. Never a permission, signer or live journal."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from native_ticket_observer import canonical, decode, fixture_pins

ROOT=Path(__file__).resolve().parents[1]
MODE='UNSIGNED_P0_REVIEW_NOT_FUNDING_AUTHORIZATION'


class ReviewError(ValueError):
    pass


def checksum(body):
    return hashlib.sha256(b'icp/ticket-pilot-review/receipt/p0\0'+canonical(body)).hexdigest()


def load(path,limit=131072):
    with Path(path).open('rb') as f:raw=f.read(limit+1)
    if len(raw)>limit:raise ReviewError('Oversized public review input')
    return decode(raw)


class Reviewer:
    def __init__(self,binary=None):
        self.binary=Path(binary or ROOT/'target/debug/examples/ticket_pilot_review').resolve()
        try:self.fingerprint=hashlib.sha256(self.binary.read_bytes()).hexdigest()
        except OSError as exc:raise ReviewError('Build ticket_pilot_review first') from exc

    def native(self,plan):
        raw=canonical(plan)
        if len(raw)>16384:raise ReviewError('Oversized public plan')
        try:
            if hashlib.sha256(self.binary.read_bytes()).hexdigest()!=self.fingerprint:
                raise ReviewError('Pinned review binary changed')
            r=subprocess.run([str(self.binary)],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             env={'PATH':'/usr/bin:/bin'},timeout=20)
        except (OSError,subprocess.TimeoutExpired) as exc:raise ReviewError('Native review unavailable') from exc
        if r.returncode or len(r.stdout)>131072:raise ReviewError('Native public plan rejected')
        result=decode(r.stdout)
        if result.get('mode')!=MODE:raise ReviewError('Wrong native review mode')
        return result

    def make(self,plan):
        body=dict(plan=decode(canonical(plan)),review=self.native(plan))
        return dict(body,receipt_hash=checksum(body))

    def verify(self,record):
        if type(record) is not dict or set(record)!={'plan','review','receipt_hash'}:
            raise ReviewError('Closed public review record required')
        body={k:record[k] for k in ('plan','review')}
        if record['receipt_hash']!=checksum(body):raise ReviewError('Public receipt checksum changed')
        if canonical(self.native(record['plan']))!=canonical(record['review']):
            raise ReviewError('Public receipt differs from native recomputation')
        return record['review']

    def save(self,path,plan):
        record=self.make(plan)
        # This is a public draft receipt, not a transaction outbox or submission claim.
        with Path(path).open('xb') as f:
            f.write(json.dumps(record,indent=2,sort_keys=True).encode()+b'\n');f.flush();os.fsync(f.fileno())
        parent_fd=os.open(Path(path).parent,os.O_RDONLY)
        try:os.fsync(parent_fd)
        finally:os.close(parent_fd)
        return record


def fixture_plan():
    p=fixture_pins()['issue']['plan']
    return dict(namespace='icp-ticket-pilot-review-p0',network='testnet-10',purpose='public-fixture-never-fund',
                run_nonce='44'*32,evidence_digest='77'*32,
                **{k:p[k] for k in ('funding_key','ticket_key','return_key')},
                source=dict(transaction_id='11'*32,index=0,amount=24_000_000))


def demo():
    r=Reviewer();record=r.make(fixture_plan());r.verify(record)
    return dict(mode='PUBLIC_P0_FIXTURE_NEVER_FUND_NO_LIVE_PROOF',record=record,
                operational_keys_created=0,real_rpc_calls=0,broadcasts=0)


if __name__=='__main__':
    args=sys.argv[1:]
    if not args:result=demo()
    elif len(args)==3 and args[0]=='review':result=Reviewer().save(args[2],load(args[1],16384))
    elif len(args)==2 and args[0]=='verify':result=Reviewer().verify(load(args[1]))
    else:raise SystemExit('Usage: ticket_pilot_review.py [review PUBLIC_PLAN NEW_RECEIPT | verify RECEIPT]')
    print(json.dumps(result,indent=2,sort_keys=True))
