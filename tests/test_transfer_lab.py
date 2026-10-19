"""Local transfer checks; synthetic data/keys, no RPC, funds or key delivery."""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from transfer_lab import (AESGCM, Ed25519PrivateKey, MAX_WIRE, Policy, Receiver,
                          TransferError, approve, canonical, decode, digest,
                          public, receipt_body, seal, sign_send, verify_envelope,
                          verify_receipt)


class TransferLabTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'lab.sqlite'
        self.approver,self.sender,self.recipient=(Ed25519PrivateKey.generate() for _ in range(3))
        self.policy=Policy(public(self.approver),public(self.sender),public(self.recipient),max_bytes=512,max_lifetime=60)
        self.payload=b'synthetic private record - not real customer data'
        self.envelope,self.key=self.exchange()
        self.receiver=Receiver(self.path,self.policy,self.recipient)

    def tearDown(self):
        self.receiver.close();self.tmp.cleanup()

    def exchange(self):
        value,key=seal(self.policy,self.payload,100,160)
        return self.signed(value),key

    def signed(self,value):
        return sign_send(approve(value,self.policy,self.approver),self.policy,self.sender,101)

    def receive(self,value=None,key=None,now=101):
        return self.receiver.receive(canonical(self.envelope if value is None else value),
                                     self.key if key is None else key,now)

    def assert_unused(self):
        self.assertEqual(self.receiver.db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0],0)

    def recontext(self,value,key):
        m=value['manifest'];context={k:v for k,v in m.items() if k!='ciphertext_hash'}
        ct=AESGCM(key).encrypt(bytes.fromhex(m['nonce']),self.payload,canonical(context))
        m['ciphertext_hash']=hashlib.sha256(ct).hexdigest();value['ciphertext']=ct.hex()
        return self.signed(value)

    def test_private_payload_and_matching_public_receipt(self):
        plaintext,receipt=self.receive()
        self.assertEqual(plaintext,self.payload)
        self.assertTrue(verify_receipt(receipt,self.envelope,self.policy))
        stored=self.path.read_bytes()
        self.assertNotIn(self.payload,stored)
        self.assertNotIn(self.key.hex().encode(),stored)
        self.assertNotIn(self.envelope['ciphertext'].encode(),stored)
        self.assertEqual(self.receiver.get_receipt(self.envelope['manifest']['transfer_id']),receipt)

    def test_fresh_key_nonce_and_transfer_id_for_each_seal(self):
        other,key=self.exchange()
        self.assertNotEqual(key,self.key)
        for field in ('nonce','transfer_id','ciphertext_hash'):
            self.assertNotEqual(other['manifest'][field],self.envelope['manifest'][field])

    def test_changed_ciphertext_is_rejected_before_acceptance(self):
        value=copy.deepcopy(self.envelope);value['ciphertext']='00'+value['ciphertext'][2:]
        if value['ciphertext']==self.envelope['ciphertext']:value['ciphertext']='ff'+value['ciphertext'][2:]
        with self.assertRaisesRegex(TransferError,'commitment'):self.receive(value)
        self.assert_unused()

    def test_rehashed_ciphertext_without_new_approval_is_rejected(self):
        value=copy.deepcopy(self.envelope);value['ciphertext']='ff'+value['ciphertext'][2:]
        if value['ciphertext']==self.envelope['ciphertext']:value['ciphertext']='00'+value['ciphertext'][2:]
        value['manifest']['ciphertext_hash']=hashlib.sha256(bytes.fromhex(value['ciphertext'])).hexdigest()
        with self.assertRaises(TransferError):self.receive(value)
        self.assert_unused()

    def test_approved_tampered_tag_still_fails_aead(self):
        value=copy.deepcopy(self.envelope)
        ct=bytearray.fromhex(value['ciphertext']);ct[-1]^=1
        value['ciphertext']=ct.hex();value['manifest']['ciphertext_hash']=hashlib.sha256(ct).hexdigest()
        with self.assertRaisesRegex(TransferError,'authentication'):self.receive(self.signed(value))
        self.assert_unused()

    def test_wrong_key_does_not_consume_permission(self):
        with self.assertRaisesRegex(TransferError,'authentication'):self.receive(key=AESGCM.generate_key(bit_length=256))
        self.assert_unused()
        self.assertEqual(self.receive()[0],self.payload)

    def test_changed_signed_metadata_is_rejected(self):
        for field,value in (('transfer_id','ab'*32),('issued_at',99),('expires_at',159),('nonce','ab'*12)):
            changed=copy.deepcopy(self.envelope);changed['manifest'][field]=value
            with self.subTest(field=field),self.assertRaises(TransferError):self.receive(changed)
        self.assert_unused()

    def test_aead_binds_metadata_even_with_fresh_valid_signatures(self):
        value=copy.deepcopy(self.envelope);value['manifest']['transfer_id']='ab'*32
        changed=self.signed(value)
        verify_envelope(changed,self.policy,101)
        with self.assertRaisesRegex(TransferError,'authentication'):self.receive(changed)
        self.assert_unused()

    def test_wrong_approver_or_sender_cannot_sign(self):
        other=Ed25519PrivateKey.generate()
        with self.assertRaises(TransferError):approve(self.envelope,self.policy,other)
        with self.assertRaises(TransferError):sign_send(self.envelope,self.policy,other,101)
        value=copy.deepcopy(self.envelope);value.pop('approval')
        with self.assertRaises(TransferError):sign_send(value,self.policy,self.sender,101)

    def test_wrong_recipient_key_and_changed_identity_are_rejected(self):
        with self.assertRaises(TransferError):Receiver(self.path,self.policy,Ed25519PrivateKey.generate())
        value=copy.deepcopy(self.envelope);value['manifest']['recipient']=public(self.sender)
        with self.assertRaises(TransferError):self.receive(value)
        self.assert_unused()

    def test_missing_or_swapped_role_signatures_are_rejected(self):
        values=[]
        for field in ('approval','sender_signature'):
            value=copy.deepcopy(self.envelope);value.pop(field);values.append(value)
        swapped=copy.deepcopy(self.envelope)
        swapped['approval'],swapped['sender_signature']=swapped['sender_signature'],swapped['approval']
        values.append(swapped)
        for value in values:
            with self.assertRaises(TransferError):self.receive(value)
        self.assert_unused()

    def test_permission_window_has_exact_local_clock_boundaries(self):
        for now in (99,160,161,True,-1):
            with self.subTest(now=now),self.assertRaises(TransferError):self.receive(now=now)
            with self.subTest(send_at=now),self.assertRaises(TransferError):
                sign_send(self.envelope,self.policy,self.sender,now)
        self.assert_unused()
        self.assertEqual(self.receive(now=100)[0],self.payload)

    def test_invalid_lifetime_and_payload_limits_are_rejected(self):
        for start,end in ((100,100),(100,99),(100,161),(True,150)):
            with self.assertRaises(TransferError):seal(self.policy,self.payload,start,end)
        for payload in (b'',b'x'*513,'text'):
            with self.assertRaises(TransferError):seal(self.policy,payload,100,160)

    def test_policy_pins_limits_roles_and_network(self):
        for field,value in (('policy_id','ab'*32),('network','mainnet'),('version','next'),('sender',public(self.recipient))):
            changed=copy.deepcopy(self.envelope);changed['manifest'][field]=value
            with self.assertRaises(TransferError):self.receive(changed)
        self.assert_unused()

    def test_replay_rejected_after_restart_and_receipt_recoverable(self):
        _,receipt=self.receive()
        self.receiver.close();self.receiver=Receiver(self.path,self.policy,self.recipient)
        with self.assertRaisesRegex(TransferError,'already accepted'):self.receive()
        self.assertEqual(self.receiver.get_receipt(self.envelope['manifest']['transfer_id']),receipt)

    def test_same_transfer_id_with_new_valid_exchange_is_rejected(self):
        self.receive()
        value,key=self.exchange();value['manifest']['transfer_id']=self.envelope['manifest']['transfer_id']
        value=self.recontext(value,key)
        with self.assertRaisesRegex(TransferError,'already accepted'):self.receive(value,key)
        self.assertEqual(self.receiver.db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0],1)

    def test_replay_scope_requires_the_same_intact_database(self):
        self.receive()
        other=Receiver(Path(self.tmp.name)/'independent.sqlite',self.policy,self.recipient)
        try:
            plaintext,_=other.receive(canonical(self.envelope),self.key,101)
            self.assertEqual(plaintext,self.payload)
        finally:other.close()

    def test_concurrent_receivers_only_accept_once(self):
        barrier=threading.Barrier(2)
        def accept(_):
            receiver=Receiver(self.path,self.policy,self.recipient)
            try:
                barrier.wait(timeout=5)
                try:
                    receiver.receive(canonical(self.envelope),self.key,101)
                    return True
                except TransferError as error:
                    self.assertIn('already accepted',str(error))
                    return False
            finally:receiver.close()
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(accept,range(2)))
        self.assertEqual(sorted(results),[False,True])

    def test_database_cannot_silently_change_policy(self):
        _,receipt=self.receive()
        changed=Policy(self.policy.approver,self.policy.sender,self.policy.recipient,max_bytes=511,max_lifetime=60)
        with self.assertRaisesRegex(TransferError,'database policy'):Receiver(self.path,changed,self.recipient)
        self.assertEqual(self.receiver.get_receipt(self.envelope['manifest']['transfer_id']),receipt)

    def test_duplicate_json_keys_and_wire_limits_are_rejected(self):
        for raw in (b'{"a":1,"a":2}',b'{"x":{"a":1,"a":2}}',b'',b'x'*(MAX_WIRE+1),b'{',b'\xff'):
            with self.assertRaises(TransferError):decode(raw)
        self.assert_unused()

    def test_unknown_fields_and_malformed_hex_are_rejected(self):
        values=[]
        for location in ('envelope','manifest'):
            value=copy.deepcopy(self.envelope)
            (value if location=='envelope' else value['manifest'])['extra']='unexpected'
            values.append(value)
        for field,data in (('nonce','zz'*12),('transfer_id','AB'*32),('expires_at',True)):
            value=copy.deepcopy(self.envelope);value['manifest'][field]=data;values.append(value)
        for value in values:
            with self.assertRaises(TransferError):self.receive(value)
        self.assert_unused()

    def test_receipt_cannot_move_to_another_exchange_or_status(self):
        _,receipt=self.receive()
        other,_=self.exchange()
        with self.assertRaises(TransferError):verify_receipt(receipt,other,self.policy)
        changed=copy.deepcopy(receipt);changed['body']['status']='CHAIN_CONFIRMED'
        with self.assertRaises(TransferError):verify_receipt(changed,self.envelope,self.policy)

    def test_wrong_receipt_signature_is_rejected(self):
        _,receipt=self.receive()
        receipt['signature']=self.sender.sign(b'unrelated').hex()
        with self.assertRaises(TransferError):verify_receipt(receipt,self.envelope,self.policy)

    def test_receipt_is_an_attestation_not_proof_of_decryption(self):
        # A recipient key holder can make this claim without calling receive().
        body=receipt_body(self.envelope,self.policy,101)
        ident=digest('icp/lab/receipt-body/v0',body)
        receipt={'body':body,'signature':self.recipient.sign(b'icp/lab/receipt/v0\0'+bytes.fromhex(ident)).hex()}
        self.assertTrue(verify_receipt(receipt,self.envelope,self.policy))
        self.assert_unused()

    def test_key_holder_can_decrypt_outside_the_policy_api(self):
        unsigned,key=seal(self.policy,self.payload,100,160)
        m=unsigned['manifest'];context={k:v for k,v in m.items() if k!='ciphertext_hash'}
        plaintext=AESGCM(key).decrypt(bytes.fromhex(m['nonce']),bytes.fromhex(unsigned['ciphertext']),canonical(context))
        self.assertEqual(plaintext,self.payload)
        self.assertNotIn('approval',unsigned)
        self.assert_unused()

    def test_receipt_remains_checkable_after_permission_expiry(self):
        _,receipt=self.receive(now=159)
        self.assertTrue(verify_receipt(receipt,self.envelope,self.policy))
        # accepted_at is the signer's claimed time, not an external timestamp.
        self.assertEqual(receipt['body']['accepted_at'],159)

    def test_json_whitespace_does_not_change_signed_semantics(self):
        raw=json.dumps(self.envelope,indent=4).encode()
        self.assertEqual(self.receiver.receive(raw,self.key,101)[0],self.payload)

    def test_policy_requires_distinct_roles_and_bounded_integer_limits(self):
        for kwargs in ({'sender':self.policy.approver},{'max_bytes':0},{'max_bytes':True},{'max_lifetime':3601}):
            values=dict(approver=self.policy.approver,sender=self.policy.sender,recipient=self.policy.recipient)
            values.update(kwargs)
            with self.assertRaises(TransferError):Policy(**values)

    def test_published_synthetic_transcript_has_valid_bound_signatures(self):
        path=Path(__file__).resolve().parents[1]/'evidence/transfer-lab-demo.json'
        value=json.loads(path.read_text());p=value['policy']
        policy=Policy(p['approver'],p['sender'],p['recipient'],p['max_bytes'],p['max_lifetime'])
        self.assertEqual(p,policy.body())
        self.assertEqual(value['mode'],'LOCAL_ONLY_NO_CHAIN_ANCHOR')
        self.assertTrue(verify_receipt(value['receipt'],value['envelope'],policy))
        changed=copy.deepcopy(value['receipt']);changed['body']['manifest_id']='00'*32
        with self.assertRaises(TransferError):verify_receipt(changed,value['envelope'],policy)


if __name__=='__main__':unittest.main()
