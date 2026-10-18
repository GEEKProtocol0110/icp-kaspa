#!/usr/bin/env python3
"""Fresh two-vault live demo: approve one intent, auto-recover the other."""
import json
from pathlib import Path
import time
from watchtower import Native, Store, arm, act, point

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'runtime/watchtower-pilot'

def main():
    RUN.mkdir(exist_ok=False)
    journal={'status':'STARTED','steps':[]}
    def save(): (RUN/'journal.json').write_text(json.dumps(journal,indent=2)+'\n')
    save();native=Native();store=None
    def broadcast_call(label,*args):
        before=set((ROOT/'runtime').glob('*.json'))
        output=native.call(*args,json_output=False)
        receipts=[]
        for path in set((ROOT/'runtime').glob('*.json'))-before:
            value=json.loads(path.read_text())
            if value.get('status')=='MEMPOOL_ACCEPTED':receipts.append(value)
        if len(receipts)!=1:raise RuntimeError('Expected one unambiguous broadcast receipt')
        receipt=receipts[0];journal['steps'].append({'step':label,'receipt':receipt,'output':output});save()
        return receipt['id']
    def wait_output(ident,index=0):
        until=time.monotonic()+90
        while time.monotonic()<until:
            s=native.snapshot()
            hit=next((u for u in s['utxos'] if point(u['outpoint'])==f'{ident}:{index}'),None)
            if hit:return s,hit
            time.sleep(1)
        raise RuntimeError('Accepted output not observed; inspect receipts before retrying')
    try:
        deposit=broadcast_call('deposit','deposit','30000000')
        wait_output(deposit,0);wait_output(deposit,1)
        roots=[f'{deposit}:0',f'{deposit}:1']
        store=arm(native,RUN/'watch.sqlite',RUN/'config.json',roots)
        prepared=native.call('prepare-initiate',roots[0]);authorized=prepared['id']+':0'
        snapshot=native.snapshot();store.authorize(roots[0],authorized,snapshot['node']['virtualDaaScore']+3000)
        first=broadcast_call('approved_intent','broadcast',prepared['path'])
        second=broadcast_call('unexpected_intent','initiate',roots[1])
        journal['roots']=roots;journal['authorized_pending']=authorized;journal['unexpected_pending']=second+':0';save()
        executed=False;until=time.monotonic()+240
        while time.monotonic()<until:
            scan=native.call('scan',store.get('tip'));store.apply(scan)
            act(store,native,execute=True)
            journal['watcher_state']=store.state();journal['actions']=[dict(r) for r in store.db.execute('SELECT * FROM actions')];save()
            terminal=store.state()['terminal']
            if roots[1] in terminal and terminal[roots[1]]['kind']=='RECOVERED':
                if not executed:
                    s=native.snapshot()
                    pending=next((u for u in s['utxos'] if point(u['outpoint'])==authorized),None)
                    if pending and s['node']['virtualDaaScore']-pending['utxoEntry']['blockDaaScore']>=610:
                        broadcast_call('approved_execute','execute',authorized);executed=True
                if roots[0] in terminal:
                    if terminal[roots[0]]['kind']!='EXECUTED':raise RuntimeError('Approved withdrawal was not preserved')
                    if len(journal['actions'])!=1 or journal['actions'][0]['status']!='CONFIRMED':raise RuntimeError('Recovery action is not chain-confirmed')
                    journal['status']='LIVE_WATCHTOWER_PASSED';journal['final_snapshot']=native.snapshot();save()
                    print('LIVE_WATCHTOWER_PASSED: unexpected intent auto-recovered; approved intent executed after delay.',flush=True)
                    return
            if any(t['kind']=='UNAUTHORIZED_EXECUTION' for t in terminal.values()):raise RuntimeError('Unexpected withdrawal executed')
            time.sleep(1)
        raise RuntimeError('Watchtower live test timed out; inspect state before continuing')
    except Exception as error:
        journal['status']='STOPPED_REQUIRES_INSPECTION';journal['error']=str(error)
        if store:journal['watcher_state']=store.state();journal['actions']=[dict(r) for r in store.db.execute('SELECT * FROM actions')]
        save();raise
    finally:
        if store:store.db.close()

if __name__=='__main__':main()
