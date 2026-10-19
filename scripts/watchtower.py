#!/usr/bin/env python3
"""Deterministic TN10 watchtower. SQLite chain undo + durable signed outbox.

The controller never reads keys. Its signer adapter invokes prepare-recover;
protected deployments can delegate signing to an SSH forced-command service.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
ID = re.compile(r'^[0-9a-f]{64}$')

class WatchError(RuntimeError):
    pass

def txid(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise WatchError('Invalid transaction/block ID')
    return value

def integer(value):
    if type(value) is not int or value < 0 or value >= 2**64:
        raise WatchError('Invalid unsigned integer')
    return value

def point(value):
    return f"{txid(value['transactionId'])}:{integer(value['index'])}"

def guard(node):
    if node.get('networkId') != 'testnet-10' or node.get('isSynced') is not True or node.get('hasUtxoIndex') is not True:
        raise WatchError('Refusing unhealthy or wrong-network node')
    if integer(node.get('virtualDaaScore')) < 467579632:
        raise WatchError('Covenants inactive')

class Store:
    def __init__(self, path, config):
        if config['network'] != 'testnet-10':
            raise WatchError('TN10 only')
        for name in ('idle_spk','pending_spk','recipient_spk','recovery_spk'):
            if not isinstance(config[name], str) or not re.fullmatch('[0-9a-f]+',config[name]):
                raise WatchError('Invalid pinned script')
        if not 0 < integer(config['delay_daa']) < 2**32 or integer(config['max_fee']) == 0:
            raise WatchError('Invalid pinned limits')
        self.config = config
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS blocks(hash TEXT PRIMARY KEY,previous TEXT NOT NULL,undo TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS approvals(pending TEXT PRIMARY KEY,root TEXT NOT NULL,expires INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS actions(pending TEXT PRIMARY KEY,payload TEXT,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last REAL NOT NULL DEFAULT 0,error TEXT);
          CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,data TEXT NOT NULL);
        ''')
        digest=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()
        previous=self.get('config')
        if previous and previous != digest:
            raise WatchError('Configuration changed; refusing to reuse watcher state')
        with self.db:
            self.put('config',digest)
    def get(self,k):
        row=self.db.execute('SELECT v FROM meta WHERE k=?',(k,)).fetchone()
        return row['v'] if row else None
    def put(self,k,v):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',(k,v))
    def state(self):
        return json.loads(self.get('state') or '{"outputs":{},"terminal":{}}')
    def audit(self,kind,data):
        self.db.execute('INSERT INTO audit(kind,data) VALUES(?,?)',(kind,json.dumps(data,sort_keys=True)))
    def arm(self,anchor,deposits):
        if self.get('tip'):
            raise WatchError('Watcher already armed')
        outputs={}
        for u in deposits:
            key=point(u['outpoint']);entry=u['utxoEntry']
            if entry['scriptPublicKey'] != self.config['idle_spk'] or entry.get('covenantId') is not None:
                raise WatchError('Bootstrap requires exact idle covenant UTXOs')
            value=integer(entry['amount'])
            if value <= self.config['max_fee'] or key in outputs:
                raise WatchError('Invalid bootstrap deposit')
            outputs[key]={'stage':'idle','amount':value,'root':key,'accepted_daa':integer(entry['blockDaaScore']),'authorized':False}
        if not outputs:
            raise WatchError('No registered deposits')
        with self.db:
            self.put('tip',txid(anchor));self.put('state',json.dumps({'outputs':outputs,'terminal':{}}))
            self.audit('ARMED',{'anchor':anchor,'deposits':list(outputs)})
    def authorize(self,root,pending,expires):
        txid(pending.split(':')[0]);integer(expires)
        if not pending.endswith(':0') or root not in self.state()['outputs'] or self.state()['outputs'][root]['stage']!='idle':
            raise WatchError('Approval must bind a registered unspent idle deposit and pending output zero')
        if pending in self.state()['outputs']:
            raise WatchError('Cannot authorize an already detected pending intent')
        with self.db:
            self.db.execute('INSERT INTO approvals VALUES(?,?,?)',(pending,root,expires))
            self.audit('AUTHORIZED',{'root':root,'pending':pending,'expires':expires})
    def _transaction(self,state,transaction,daa):
        ident=txid(transaction['verboseData']['transactionId'])
        inputs=[point(i['previousOutpoint']) for i in transaction['inputs']]
        hits=[k for k in inputs if k in state['outputs']]
        if not hits:
            return
        if len(inputs)!=1 or len(hits)!=1 or len(transaction['outputs'])!=1:
            raise WatchError('Accepted transaction violates registered vault layout')
        source=state['outputs'][hits[0]];out=transaction['outputs'][0]
        value=integer(out['value']);spk=out['scriptPublicKey']
        if value==0 or value>source['amount'] or source['amount']-value>self.config['max_fee']:
            raise WatchError('Accepted vault value invariant violated')
        if out.get('covenant') is not None:
            raise WatchError('Unexpected output covenant binding')
        if source['stage']=='idle' and spk==self.config['pending_spk']:
            pending=ident+':0'
            approval=self.db.execute('SELECT * FROM approvals WHERE pending=?',(pending,)).fetchone()
            authorized=bool(approval and approval['root']==source['root'] and daa<=approval['expires'])
            state['outputs'][pending]={'stage':'pending','root':source['root'],'amount':value,'accepted_daa':daa,'authorized':authorized}
            self.audit('INTENT',{'pending':pending,'authorized':authorized,'root':source['root'],'daa':daa})
        elif spk==self.config['recovery_spk']:
            state['terminal'][source['root']]={'kind':'RECOVERED','transaction_id':ident,'daa':daa}
            if self.config.get('version')=='protected-v1':
                state['terminal'][source['root']].update({'custody':'QUARANTINED','outpoint':ident+':0','amount':value})
                self.audit('RECOVERY_QUARANTINED',{'root':source['root'],'outpoint':ident+':0','amount':value})
        elif source['stage']=='pending' and spk==self.config['recipient_spk']:
            state['terminal'][source['root']]={'kind':'EXECUTED' if source['authorized'] else 'UNAUTHORIZED_EXECUTION','transaction_id':ident,'daa':daa}
            if not source['authorized']:
                self.audit('CRITICAL_UNAUTHORIZED_EXECUTION',{'root':source['root'],'txid':ident})
        else:
            raise WatchError('Accepted output does not match a pinned vault path')
        del state['outputs'][hits[0]]
    def apply(self,response):
        guard(response['node'])
        if response['from'] != self.get('tip'):
            raise WatchError('Stale RPC scan cursor')
        changes=response['changes'];added=changes['addedChainBlockHashes'];removed=changes['removedChainBlockHashes']
        blocks=changes['chainBlockAcceptedTransactions']
        if [b['chainBlockHeader']['hash'] for b in blocks] != added or len(set(added))!=len(added):
            raise WatchError('Incomplete or unordered accepted-chain response')
        state=self.state();tip=self.get('tip')
        with self.db:
            for h in removed:
                if h!=tip:
                    raise WatchError('Reorg removal is not the tracked chain tip')
                row=self.db.execute('SELECT * FROM blocks WHERE hash=?',(h,)).fetchone()
                if not row:
                    raise WatchError('Reorg crosses bootstrap anchor; stop and reconcile')
                state=json.loads(row['undo']);tip=row['previous']
                self.db.execute('DELETE FROM blocks WHERE hash=?',(h,));self.audit('REORG_UNDO',{'block':h})
            for b in blocks:
                header=b['chainBlockHeader'];h=txid(header['hash']);daa=integer(header['daaScore'])
                undo=json.dumps(state)
                for transaction in b['acceptedTransactions']:
                    self._transaction(state,transaction,daa)
                self.db.execute('INSERT INTO blocks VALUES(?,?,?)',(h,tip,undo));tip=h
            self.put('tip',tip);self.put('state',json.dumps(state))
            self._reconcile_actions(state)
    def _reconcile_actions(self,state):
        for row in self.db.execute('SELECT * FROM actions').fetchall():
            pending=row['pending'];live=state['outputs'].get(pending)
            if live and live['stage']=='pending' and not live['authorized']:
                if row['status'] in ('ORPHANED','CONFIRMED'):
                    self.db.execute('UPDATE actions SET status=?,attempts=0 WHERE pending=?',('PREPARED' if row['payload'] else 'NEEDED',pending))
            else:
                payload=json.loads(row['payload']) if row['payload'] else {}
                confirmed=any(t['transaction_id']==payload.get('id') and t['kind']=='RECOVERED' for t in state['terminal'].values())
                self.db.execute('UPDATE actions SET status=? WHERE pending=?',('CONFIRMED' if confirmed else 'ORPHANED',pending))
    def recoveries(self):
        return {k:v for k,v in self.state()['outputs'].items() if v['stage']=='pending' and not v['authorized']}

class Native:
    def __init__(self,command=None):
        binary=ROOT/'bin/icp'
        if not binary.exists():binary=ROOT/'target/debug/icp'
        self.command=command or [str(binary)]
    def call(self,*args,json_output=True):
        env={k:v for k,v in os.environ.items() if k!='ICP_SIGNER_KEY_FILE'} if args[0] in ('status','descriptor','anchor','scan','broadcast') else None
        p=subprocess.run(self.command+list(args),cwd=ROOT,text=True,capture_output=True,timeout=35,env=env)
        if p.returncode:
            raise WatchError(p.stderr.strip() or p.stdout.strip() or 'Native CLI failed')
        return json.loads(p.stdout) if json_output else p.stdout
    def snapshot(self):
        value=self.call('status');guard(value['node']);return value
    def prepare(self,pending):
        return self.call('prepare-recover',pending)
    def broadcast(self,payload):
        path=Path(os.environ.get('ICP_OUTBOX_DIR',ROOT/'runtime/outbox'))/f"{txid(payload['id'])}.json"
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(payload))
        return self.call('broadcast',str(path),json_output=False)

def validate_recovery(payload,pending,amount,config):
    tx=payload['transaction']
    if len(tx['inputs'])!=1 or len(tx['outputs'])!=1:
        raise WatchError('Recovery signer returned unexpected transaction layout')
    out=tx['outputs'][0]
    if point(tx['inputs'][0]['previousOutpoint'])!=pending or out['scriptPublicKey']!=config['recovery_spk'] or out.get('covenant') is not None or not 0<integer(out['value'])<=integer(amount) or amount-out['value']>config['max_fee']:
        raise WatchError('Recovery signer returned unexpected transaction')
    txid(payload['id'])

def act(store,adapter,execute=False,now=None):
    """Always reconcile exact live UTXOs before signing or re-broadcasting."""
    now=time.time() if now is None else now
    snapshot=adapter.snapshot();guard(snapshot['node'])
    live={point(u['outpoint']):u['utxoEntry'] for u in snapshot['utxos']}
    for pending,expected in store.recoveries().items():
        entry=live.get(pending)
        if not entry or entry['scriptPublicKey']!=store.config['pending_spk'] or entry['amount']!=expected['amount'] or entry.get('covenantId') is not None:
            continue
        row=store.db.execute('SELECT * FROM actions WHERE pending=?',(pending,)).fetchone()
        if row and (row['status'] in ('CONFIRMED','ORPHANED') or row['attempts']>=3 or now-row['last']<10):
            continue
        if not execute:
            with store.db:store.audit('WOULD_RECOVER',{'pending':pending})
            continue
        if not row:
            with store.db:store.db.execute('INSERT INTO actions(pending,status) VALUES(?,?)',(pending,'NEEDED'))
        row=store.db.execute('SELECT * FROM actions WHERE pending=?',(pending,)).fetchone()
        try:
            payload=json.loads(row['payload']) if row['payload'] else adapter.prepare(pending)
            validate_recovery(payload,pending,expected['amount'],store.config)
            # Durable signed outbox BEFORE the network side effect.
            with store.db:
                store.db.execute('UPDATE actions SET payload=?,status=?,attempts=attempts+1,last=? WHERE pending=?',(json.dumps(payload),'PREPARED',now,pending))
            adapter.broadcast(payload)
            with store.db:
                store.db.execute('UPDATE actions SET status=?,error=NULL WHERE pending=?',('SUBMITTED',pending))
                store.audit('RECOVERY_SUBMITTED',{'pending':pending,'txid':payload['id']})
        except Exception as error:
            with store.db:
                store.db.execute('UPDATE actions SET error=?,last=?,attempts=CASE WHEN payload IS NULL THEN attempts+1 ELSE attempts END WHERE pending=?',(str(error),now,pending))
                store.audit('RECOVERY_RETRY_REQUIRED',{'pending':pending,'error':str(error)})
            # Continue watching the chain; an ambiguous transport outcome is
            # reconciled before retrying the identical signed transaction.

def arm(adapter,db,config,deposits):
    first=adapter.snapshot();descriptor=adapter.call('descriptor');anchor=adapter.call('anchor');second=adapter.snapshot()
    guard(anchor['node'])
    def selected(snapshot):
        found={point(u['outpoint']):u for u in snapshot['utxos']}
        if any(k not in found for k in deposits):raise WatchError('Registered deposit changed during arming')
        return [found[k] for k in deposits]
    before=selected(first);after=selected(second)
    if before!=after:raise WatchError('Registered deposits changed during arming')
    config.write_text(json.dumps(descriptor,indent=2)+'\n')
    store=Store(db,descriptor);store.arm(anchor['anchor'],after);return store

def heartbeat(store,node,execute,remote=False,now=None):
    now=time.time() if now is None else now
    daa=integer(node['virtualDaaScore'])
    previous=json.loads(store.get('heartbeat') or '{}')
    advanced=now if previous.get('daa')!=daa else previous.get('advanced_at',now)
    with store.db:
        store.put('health_limits',json.dumps({'delay_daa':store.config['delay_daa']}))
        store.put('heartbeat',json.dumps({'at':now,'advanced_at':advanced,'daa':daa,'execute':execute,'remote_signer':remote}))
        store.put('health_error','')

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['arm','run','authorize','status'])
    p.add_argument('--remote-signer',type=Path,help='Pinned SSH recovery-only signer config')
    p.add_argument('--cli',type=Path,help='Explicit native CLI, e.g. target/debug/icp-protected')
    p.add_argument('--db',type=Path,default=ROOT/'runtime/watchtower.sqlite');p.add_argument('--config',type=Path,default=ROOT/'runtime/watchtower-config.json')
    p.add_argument('--deposit',action='append',default=[]);p.add_argument('--pending');p.add_argument('--expires-daa',type=int)
    p.add_argument('--execute',action='store_true');p.add_argument('--once',action='store_true');p.add_argument('--poll',type=float,default=1)
    a=p.parse_args();a.db.parent.mkdir(parents=True,exist_ok=True)
    with Path(str(a.db)+'.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        native=Native([str(a.cli.resolve())] if a.cli else None)
        if a.command=='arm':
            store=arm(native,a.db,a.config,a.deposit)
        else:
            store=Store(a.db,json.loads(a.config.read_text()))
        if a.command=='authorize':
            if len(a.deposit)!=1 or not a.pending or a.expires_daa is None:p.error('authorize needs one --deposit, --pending TXID:0 and --expires-daa')
            store.authorize(a.deposit[0],a.pending,a.expires_daa)
        elif a.command=='run':
            if a.remote_signer:
                from recovery_signer import RemoteNative
                native=RemoteNative(native.command,a.remote_signer,store.config)
            last_event=int(store.get('logged_event') or 0)
            while True:
                try:
                    response=native.call('scan',store.get('tip'));scanned_at=time.time()
                    store.apply(response);act(store,native,a.execute)
                    heartbeat(store,response['node'],a.execute,remote=bool(a.remote_signer),now=scanned_at)
                except Exception as error:
                    with store.db:
                        store.audit('WATCH_ERROR',{'error':str(error)})
                        store.put('health_error',str(error))
                    raise
                for event in store.db.execute('SELECT * FROM audit WHERE id>? ORDER BY id',(last_event,)).fetchall():
                    print(json.dumps({'event_id':event['id'],'kind':event['kind'],'data':json.loads(event['data'])}),flush=True)
                    last_event=event['id']
                with store.db:store.put('logged_event',str(last_event))
                if a.once:break
                time.sleep(max(a.poll,0.1))
        print(json.dumps({'tip':store.get('tip'),'state':store.state(),'actions':[dict(r) for r in store.db.execute('SELECT * FROM actions')]},indent=2))

if __name__=='__main__':
    main()
