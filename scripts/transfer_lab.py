#!/usr/bin/env python3
"""Local-only encrypted transfer/receipt experiment; no RPC or custody signing.

Conventional Ed25519 identities, fresh per-message AES-256-GCM keys, and a
trusted policy/clock/replay database. Key delivery is out of band. Receipt
signatures attest a recipient claim, not remote execution or factual truth.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 'icp-transfer-lab-v0'
MAX_BYTES = 1024 * 1024
MAX_WIRE = 2 * MAX_BYTES + 8192
FIELDS = {'version','network','policy_id','transfer_id','sender','recipient','issued_at','expires_at','nonce','ciphertext_hash'}


class TransferError(ValueError):
    pass


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def digest(domain,value):
    return hashlib.sha256(domain.encode('ascii')+b'\0'+canonical(value)).hexdigest()


def public(key):
    return key.public_key().public_bytes_raw().hex()


def number(value):
    if type(value) is not int or not 0 <= value < 2**53:
        raise TransferError('Invalid integer')
    return value


def unhex(value,size):
    if not isinstance(value,str) or len(value)!=size*2 or not re.fullmatch('[0-9a-f]+',value):
        raise TransferError('Invalid hex encoding')
    return bytes.fromhex(value)


@dataclass(frozen=True)
class Policy:
    approver: str
    sender: str
    recipient: str
    max_bytes: int = MAX_BYTES
    max_lifetime: int = 300

    def __post_init__(self):
        for value in (self.approver,self.sender,self.recipient):unhex(value,32)
        if len({self.approver,self.sender,self.recipient})!=3:
            raise TransferError('Roles must be distinct')
        if not 0<number(self.max_bytes)<=MAX_BYTES or not 0<number(self.max_lifetime)<=3600:
            raise TransferError('Invalid policy limit')

    def body(self):
        return {'version':VERSION,'network':'testnet-10','mode':'offchain-local',
                'approver':self.approver,'sender':self.sender,'recipient':self.recipient,
                'max_bytes':self.max_bytes,'max_lifetime':self.max_lifetime}

    @property
    def id(self):
        return digest('icp/lab/policy/v0',self.body())


def _material(envelope,policy):
    if type(envelope) is not dict or not {'manifest','ciphertext'}<=envelope.keys() or envelope.keys()-{'manifest','ciphertext','approval','sender_signature'}:
        raise TransferError('Invalid envelope fields')
    m=envelope['manifest']
    if type(m) is not dict or set(m)!=FIELDS:
        raise TransferError('Invalid manifest fields')
    if (m['version'],m['network'],m['policy_id'],m['sender'],m['recipient'])!=(VERSION,'testnet-10',policy.id,policy.sender,policy.recipient):
        raise TransferError('Policy, network or participant mismatch')
    unhex(m['transfer_id'],32);unhex(m['nonce'],12);unhex(m['ciphertext_hash'],32)
    issued=number(m['issued_at']);expires=number(m['expires_at'])
    if not 0<expires-issued<=policy.max_lifetime:
        raise TransferError('Invalid permission lifetime')
    ct=envelope['ciphertext']
    if not isinstance(ct,str) or len(ct)%2 or not 16<len(ct)//2<=policy.max_bytes+16:
        raise TransferError('Ciphertext size outside policy')
    ciphertext=unhex(ct,len(ct)//2)
    if hashlib.sha256(ciphertext).hexdigest()!=m['ciphertext_hash']:
        raise TransferError('Ciphertext commitment mismatch')
    return m,ciphertext


def _signature(key_hex,signature,domain,manifest_id):
    try:
        Ed25519PublicKey.from_public_bytes(unhex(key_hex,32)).verify(
            unhex(signature,64),domain.encode('ascii')+b'\0'+unhex(manifest_id,32))
    except InvalidSignature as error:
        raise TransferError('Signature verification failed') from error


def manifest_id(envelope):
    return digest('icp/lab/manifest/v0',envelope['manifest'])


def seal(policy,plaintext,issued_at,expires_at):
    if type(plaintext) is not bytes or not 0<len(plaintext)<=policy.max_bytes:
        raise TransferError('Plaintext size outside policy')
    m={'version':VERSION,'network':'testnet-10','policy_id':policy.id,
       'transfer_id':os.urandom(32).hex(),'sender':policy.sender,'recipient':policy.recipient,
       'issued_at':number(issued_at),'expires_at':number(expires_at),'nonce':os.urandom(12).hex()}
    # A new key on every seal avoids nonce reuse with an existing key. This
    # return value is secret and must be delivered separately to the recipient.
    key=AESGCM.generate_key(bit_length=256)
    ciphertext=AESGCM(key).encrypt(bytes.fromhex(m['nonce']),plaintext,canonical(m))
    m['ciphertext_hash']=hashlib.sha256(ciphertext).hexdigest()
    envelope={'manifest':m,'ciphertext':ciphertext.hex()}
    _material(envelope,policy)
    return envelope,key


def approve(envelope,policy,approver):
    _material(envelope,policy)
    if public(approver)!=policy.approver:
        raise TransferError('Wrong approver')
    signature=approver.sign(b'icp/lab/approve/v0\0'+bytes.fromhex(manifest_id(envelope)))
    return dict(envelope,approval=signature.hex())


def _active(manifest,now):
    if not manifest['issued_at']<=number(now)<manifest['expires_at']:
        raise TransferError('Permission not active')


def sign_send(envelope,policy,sender,now):
    m,_=_material(envelope,policy)
    _active(m,now)
    _signature(policy.approver,envelope.get('approval'),'icp/lab/approve/v0',manifest_id(envelope))
    if public(sender)!=policy.sender:
        raise TransferError('Wrong sender')
    signature=sender.sign(b'icp/lab/send/v0\0'+bytes.fromhex(manifest_id(envelope)))
    return dict(envelope,sender_signature=signature.hex())


def verify_envelope(envelope,policy,now):
    m,ciphertext=_material(envelope,policy)
    if set(envelope)!={'manifest','ciphertext','approval','sender_signature'}:
        raise TransferError('Both approvals required')
    _active(m,now)
    ident=manifest_id(envelope)
    _signature(policy.approver,envelope['approval'],'icp/lab/approve/v0',ident)
    _signature(policy.sender,envelope['sender_signature'],'icp/lab/send/v0',ident)
    return m,ciphertext


def decode(raw):
    if type(raw) is not bytes or not 0<len(raw)<=MAX_WIRE:
        raise TransferError('Wire size outside limit')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise TransferError('Duplicate JSON field')
            result[k]=v
        return result
    try:
        return json.loads(raw,object_pairs_hook=unique)
    except (ValueError,UnicodeError,RecursionError) as error:
        raise TransferError('Invalid JSON encoding') from error


def receipt_body(envelope,policy,accepted_at):
    m=envelope['manifest']
    return {'version':VERSION,'network':'testnet-10','policy_id':policy.id,
            'transfer_id':m['transfer_id'],'manifest_id':manifest_id(envelope),
            'ciphertext_hash':m['ciphertext_hash'],'recipient':policy.recipient,
            'accepted_at':number(accepted_at),'status':'VERIFIED_LOCAL'}


def verify_receipt(receipt,envelope,policy):
    if type(receipt) is not dict or set(receipt)!={'body','signature'} or type(receipt['body']) is not dict:
        raise TransferError('Invalid receipt fields')
    body=receipt['body']
    now=number(body.get('accepted_at'))
    verify_envelope(envelope,policy,now)
    if body!=receipt_body(envelope,policy,now):
        raise TransferError('Receipt does not match exchange')
    ident=digest('icp/lab/receipt-body/v0',body)
    _signature(policy.recipient,receipt['signature'],'icp/lab/receipt/v0',ident)
    return True


class Receiver:
    def __init__(self,path,policy,recipient):
        if public(recipient)!=policy.recipient:
            raise TransferError('Wrong recipient key')
        self.policy=policy;self.recipient=recipient
        self.db=sqlite3.connect(path,timeout=5)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS policy(id TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS receipts(transfer_id TEXT PRIMARY KEY,body TEXT NOT NULL);''')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            rows=self.db.execute('SELECT id FROM policy').fetchall()
            if rows and rows!=[(policy.id,)]:raise TransferError('Replay database policy mismatch')
            if not rows:self.db.execute('INSERT INTO policy VALUES(?)',(policy.id,))
            self.db.commit()
        except Exception:
            self.db.rollback();self.db.close();raise

    def receive(self,raw,key,now):
        envelope=decode(raw)
        m,ciphertext=verify_envelope(envelope,self.policy,now)
        if type(key) is not bytes or len(key)!=32:
            raise TransferError('Expected AES-256 key')
        context={k:v for k,v in m.items() if k!='ciphertext_hash'}
        try:
            plaintext=AESGCM(key).decrypt(bytes.fromhex(m['nonce']),ciphertext,canonical(context))
        except InvalidTag as error:
            raise TransferError('Payload authentication failed') from error
        body=receipt_body(envelope,self.policy,now)
        ident=digest('icp/lab/receipt-body/v0',body)
        receipt={'body':body,'signature':self.recipient.sign(b'icp/lab/receipt/v0\0'+bytes.fromhex(ident)).hex()}
        try:
            with self.db:
                self.db.execute('INSERT INTO receipts VALUES(?,?)',(m['transfer_id'],canonical(receipt).decode('ascii')))
        except sqlite3.IntegrityError as error:
            raise TransferError('Transfer already accepted') from error
        # Commit before returning. A crash after commit may prevent delivery;
        # get_receipt() recovers the acknowledgment, not the plaintext.
        return plaintext,receipt

    def get_receipt(self,transfer_id):
        unhex(transfer_id,32)
        row=self.db.execute('SELECT body FROM receipts WHERE transfer_id=?',(transfer_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def close(self):
        self.db.close()


def demo():
    approver,sender,recipient=(Ed25519PrivateKey.generate() for _ in range(3))
    policy=Policy(public(approver),public(sender),public(recipient))
    now=int(time.time())
    envelope,key=seal(policy,b'ICP synthetic local payload',now,now+300)
    envelope=sign_send(approve(envelope,policy,approver),policy,sender,now)
    with tempfile.TemporaryDirectory() as directory:
        receiver=Receiver(Path(directory)/'receipts.sqlite',policy,recipient)
        plaintext,receipt=receiver.receive(canonical(envelope),key,now)
        verified=verify_receipt(receipt,envelope,policy)
        try:
            receiver.receive(canonical(envelope),key,now)
        except TransferError:
            replay_rejected=True
        else:
            replay_rejected=False
        receiver.close()
    matches=plaintext==b'ICP synthetic local payload'
    if not verified or not matches or not replay_rejected:
        raise TransferError('Local demo verification failed')
    return {'mode':'LOCAL_ONLY_NO_CHAIN_ANCHOR','receipt_verified':verified,
            'payload_matches':matches,
            'replay_rejected':replay_rejected,'policy':policy.body(),
            'envelope':envelope,'receipt':receipt}


if __name__=='__main__':
    print(json.dumps(demo(),indent=2))
