#!/usr/bin/env python3
"""Fresh v1 funded acceptance run; never resumes or overwrites an existing journal.

Run after public setup, private-key backup and a confirmed funding transfer.
Each signing subprocess receives only its role's file path. This is same-host
test orchestration, not a demonstration of independent-host security.
"""
import json
import os
from pathlib import Path
import time
from watchtower import Native, arm, act, point

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT/'runtime/protected-pilot'
SESSION = RUN/'session'
KEYS = ROOT/'.secrets/protected-pilot'
BIN = ROOT/'target/debug/icp-protected'

def adapter(role=None):
    command = ['env', '-u', 'ICP_SIGNER_KEY_FILE']
    if role:
        command.append(f'ICP_SIGNER_KEY_FILE={KEYS/role/"key.json"}')
    return Native(command + [str(BIN)])

def durable(path, value):
    temp = path.with_suffix(path.suffix+'.tmp')
    with temp.open('w') as file:
        json.dump(value, file, indent=2); file.write('\n'); file.flush(); os.fsync(file.fileno())
    temp.replace(path)

def main():
    os.environ['ICP_PROTECTED_STATE_DIR'] = str(SESSION)
    RUN.mkdir(parents=True, exist_ok=True)
    journal_path = RUN/'journal.json'
    # Exclusive initial creation prevents an accidental second funded run.
    with journal_path.open('x') as file:
        json.dump({'status':'STARTING'},file); file.flush(); os.fsync(file.fileno())
    journal = {'version':'protected-v1','status':'STARTED','steps':[]}
    def save(): durable(journal_path,journal)
    def note(text): print(text,flush=True)
    save(); read=adapter(); owner=adapter('owner'); recovery=adapter('recovery'); cold=adapter('cold');store=None
    config=read.call('descriptor')

    def call(label, native, *args, expected_rejection=False):
        before=set(SESSION.glob('*.json'));output=None;error=None
        try:
            output=native.call(*args,json_output=False)
        except Exception as failure:
            error=str(failure)
        receipts=[]
        for path in sorted(set(SESSION.glob('*.json'))-before):
            value=json.loads(path.read_text())
            if value.get('status') in ('MEMPOOL_ACCEPTED','REJECTED_OR_UNKNOWN','PREPARED'):
                receipts.append(value)
        record={'step':label,'output':output,'error':error,'receipts':receipts};journal['steps'].append(record);save()
        if len(receipts)!=1:raise RuntimeError('Expected one durable native receipt; inspect before retrying')
        receipt=receipts[0]
        if expected_rejection:
            if not error or receipt['status']!='REJECTED_OR_UNKNOWN' or 'sequence' not in receipt.get('error','').lower():
                raise RuntimeError('Expected explicit node sequence-lock rejection')
        elif error or receipt['status']!='MEMPOOL_ACCEPTED':
            raise RuntimeError(error or 'Native broadcast was not unambiguously accepted')
        note(label+': '+receipt['id']+' ('+receipt['status']+')')
        return receipt

    def wait_output(ident,spk,value,timeout=90):
        until=time.monotonic()+timeout
        while time.monotonic()<until:
            snapshot=read.snapshot()
            hit=next((u for u in snapshot['utxos'] if point(u['outpoint'])==ident+':0'),None)
            if hit:
                if hit['utxoEntry']['scriptPublicKey']!=spk or hit['utxoEntry']['amount']!=value:
                    raise RuntimeError('Exact accepted output script/value mismatch')
                return snapshot,hit
            time.sleep(1)
        raise RuntimeError('Exact accepted output not observed; reconcile before continuing')

    def prepared(native, entry, source):
        receipt=native.call('prepare-'+entry,source)
        journal.setdefault('prepared',[]).append(receipt);save()
        return receipt

    try:
        funding=json.loads((RUN/'funding-receipt.json').read_text())
        if funding['status']!='MEMPOOL_ACCEPTED':raise RuntimeError('Funding receipt must be reconciled before the pilot')
        journal['funding']=funding;save()
        snapshot=read.snapshot();journal['initial_snapshot']=snapshot;save()
        if not any(point(u['outpoint'])==funding['id']+':0' and u['utxoEntry']['amount']==70_000_000 for u in snapshot['utxos']):
            raise RuntimeError('Pinned funding output is not yet accepted/unspent')
        deposits=[]
        for label in ['approved_deposit','unexpected_deposit']:
            receipt=call(label,owner,'deposit','30000000')
            wait_output(receipt['id'],config['idle_spk'],30_000_000);deposits.append(receipt['id']+':0')
        journal['roots']=deposits;save()
        store=arm(recovery,RUN/'watch.sqlite',RUN/'watch-config.json',deposits)
        first=prepared(owner,'initiate',deposits[0]);pending=first['id']+':0'
        store.authorize(deposits[0],pending,read.snapshot()['node']['virtualDaaScore']+6000)
        call('approved_intent',read,'broadcast',first['path'])
        wait_output(first['id'],config['pending_spk'],28_000_000)
        normal=prepared(owner,'execute',pending)
        call('early_normal_execute',read,'broadcast',normal['path'],expected_rejection=True)
        unexpected=call('unexpected_intent',owner,'initiate',deposits[1])
        journal['authorized_pending']=pending;journal['unexpected_pending']=unexpected['id']+':0';save()
        early_cold=None;quarantine=None;executed=False;released=False
        until=time.monotonic()+480
        while time.monotonic()<until:
            scan=recovery.call('scan',store.get('tip'));store.apply(scan);act(store,recovery,execute=True)
            journal['watcher_state']=store.state();journal['actions']=[dict(r) for r in store.db.execute('SELECT * FROM actions')];save()
            terminal=store.state()['terminal']
            if any(t['kind']=='UNAUTHORIZED_EXECUTION' for t in terminal.values()):raise RuntimeError('Unapproved withdrawal executed')
            if deposits[1] in terminal and not early_cold:
                t=terminal[deposits[1]]
                if t['kind']!='RECOVERED' or t.get('custody')!='QUARANTINED':raise RuntimeError('Recovery was not covenant quarantine')
                quarantine=t['transaction_id']
                snapshot,hit=wait_output(quarantine,config['recovery_spk'],26_000_000)
                journal['quarantine_snapshot']=snapshot;journal['quarantine_utxo']=hit;save()
                early_cold=prepared(cold,'release',quarantine+':0')
                call('early_cold_release',read,'broadcast',early_cold['path'],expected_rejection=True)
                note('Automatic recovery confirmed in covenant quarantine; cold release rejected before maturity.')
            snapshot=read.snapshot()
            live={point(u['outpoint']):u['utxoEntry'] for u in snapshot['utxos']}
            if not executed and pending in live and snapshot['node']['virtualDaaScore']-live[pending]['blockDaaScore']>=config['delay_daa']+10:
                accepted=call('approved_execute_after_delay',read,'broadcast',normal['path'])
                if accepted['id']!=normal['id']:raise RuntimeError('Normal payout changed from its early-rejected transaction')
                wait_output(normal['id'],config['recipient_spk'],26_000_000);executed=True
            if early_cold and not released and quarantine+':0' in live and snapshot['node']['virtualDaaScore']-live[quarantine+':0']['blockDaaScore']>=config['cold_delay_daa']+10:
                accepted=call('cold_release_after_delay',read,'broadcast',early_cold['path'])
                if accepted['id']!=early_cold['id']:raise RuntimeError('Cold payout changed from its early-rejected transaction')
                wait_output(early_cold['id'],config['cold_spk'],24_000_000);released=True
            cold_observation=terminal.get(deposits[1],{})
            if executed and released and terminal.get(deposits[0],{}).get('kind')=='EXECUTED' and cold_observation.get('custody')=='COLD_RELEASED' and cold_observation.get('release_transaction_id')==early_cold['id']:
                if len(journal['actions'])!=1 or journal['actions'][0]['status']!='CONFIRMED':raise RuntimeError('Automatic recovery not chain-confirmed')
                final=read.snapshot()
                if any(u['utxoEntry']['scriptPublicKey'] in [config['idle_spk'],config['pending_spk'],config['recovery_spk']] for u in final['utxos']):raise RuntimeError('A pilot vault output remains live')
                journal['status']='LIVE_PROTECTED_PASSED';journal['final_snapshot']=final;journal['descriptor']=config
                journal['audit']=[{'kind':r['kind'],'data':json.loads(r['data'])} for r in store.db.execute('SELECT * FROM audit ORDER BY id')]
                save();note('LIVE_PROTECTED_PASSED: approved payout and covenant recovery/cold release confirmed.');return
            time.sleep(1)
        raise RuntimeError('Pilot timed out; inspect the existing journal and exact UTXOs')
    except Exception as failure:
        journal['status']='STOPPED_REQUIRES_INSPECTION';journal['error']=str(failure);save();raise
    finally:
        if store:
            store.db.execute('PRAGMA wal_checkpoint(FULL)');store.db.close()

if __name__=='__main__':main()
