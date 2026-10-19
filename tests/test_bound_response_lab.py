"""Encryption-key enrollment and signed dummy-response recovery, never content keys."""
import copy
from dataclasses import asdict, replace
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import bound_response_lab as lab
from release_coordinator_model import Context, IntegrityError, ModelError, RecoveryRequired, canonical
signed = lab.signed


class Crash(BaseException):
    pass


class BoundResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.keys = [signed.Ed25519PrivateKey.generate() for _ in range(5)]
        self.delivery = lab.X25519PrivateKey.generate()
        self.delivery_public = self.delivery.public_key().public_bytes_raw().hex()
        roles = dict(zip(('approver','sender','recipient','revoker','service_signer'), map(signed.public,self.keys)))
        label = lab.key_label('model:service','model:budget',roles['recipient'],self.delivery_public,0)
        self.policy = signed.SignedPolicy(**roles,binding_label=label)
        self.config = lab.DeliveryConfig(self.policy,self.delivery_public)
        self.context = Context(binding=label)
        self.permission = signed.permission(self.policy,self.context,self.keys[0],self.keys[1])
        self.now = 100
        self.model = self.open(create=True);self.model.recover()

    def open(self, create=False, root=None):
        base = root or self.root
        return lab.BoundCoordinator(base/'components',base/'authority.sqlite',self.config,lambda:self.now,self.keys[4],create=create)

    def tearDown(self):
        self.model.close();self.tmp.cleanup()

    def restart(self):
        self.model.close();self.model=self.open();self.model.recover()

    def state(self, role):
        with sqlite3.connect(self.root/'components'/(role+'.sqlite')) as db:
            return json.loads(db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()[0])['state']

    def enrollment(self):
        challenge=self.model.binding_challenge()
        proof=lab.prove_binding(self.config,challenge,self.keys[2],self.delivery,self.now)
        approval=lab.approve_binding(self.config,challenge,proof,self.keys[0],self.now)
        return challenge,proof,approval

    def bound(self):
        challenge,proof,approval=self.enrollment()
        return self.model.register_binding(approval)

    def reserved(self):
        self.bound()
        self.admission=signed.answer(self.policy,self.permission,self.model.challenge(self.permission,'reserve'),self.keys[2],self.now)
        self.model.reserve(self.permission,self.admission);self.model.observe(self.context.grant)

    def prepared(self):
        self.reserved();self.model.authorize(self.context.grant);self.model.prepare(self.context.grant)

    def committed(self):
        self.prepared();self.model.commit(self.context.grant)

    def retrieval(self):
        return signed.answer(self.policy,self.permission,self.model.challenge(self.permission,'retrieve'),self.keys[2],self.now,
                             expected_response_hash=self.model.status(self.context.grant)['response_hash'])

    def dispatch(self):
        return self.model.dispatch(self.retrieval())

    def verify(self, raw, now=None):
        return lab.verify_response(self.config,self.permission,self.admission,raw,self.now if now is None else now)

    def revoke(self):
        self.model.revoke(signed.revocation(self.policy,self.permission,self.keys[3],1,self.now,self.now+30,'model:revoke'))

    def fail_at(self, wanted):
        def hook(stage):
            if stage==wanted:raise Crash(stage)
        self.model.hook=hook

    def test_demo_verifies_from_public_configuration_and_records(self):
        result=lab.demo()
        config=lab.DeliveryConfig(signed.SignedPolicy(**result['config']['policy']),result['config']['delivery_key'],result['config']['delivery_epoch'])
        actual=lab.verify_response(config,canonical(result['permission']),canonical(result['admission']),canonical(result['bundle']),100)
        self.assertEqual(actual,result['verified_record'])
        self.assertTrue(result['identical_retry'])
        self.assertEqual((result['content_keys'],result['rpc_calls'],result['broadcasts']),(0,0,0))
        self.assertNotIn('expected',json.dumps(result))
        self.assertNotIn('private_key',json.dumps(result))

    def test_permission_challenge_requires_registered_encryption_key(self):
        with self.assertRaises(ModelError):self.model.challenge(self.permission,'reserve')
        self.assertEqual(self.state('ledger')['grants'],{})
        self.bound();self.model.challenge(self.permission,'reserve')

    def test_both_identity_and_delivery_private_keys_are_required(self):
        challenge=self.model.binding_challenge()
        for identity,delivery in [(self.keys[1],self.delivery),(self.keys[2],lab.X25519PrivateKey.generate())]:
            with self.assertRaises(ModelError):lab.prove_binding(self.config,challenge,identity,delivery,self.now)

    def test_other_private_key_cannot_decrypt_enrollment_token(self):
        challenge=signed.decode(self.model.binding_challenge())
        context=lab.check_challenge(challenge,self.config,self.now)
        with self.assertRaises(lab.InvalidTag):
            lab.SUITE.decrypt(bytes.fromhex(challenge['body']['encrypted_token']),lab.X25519PrivateKey.generate(),info=lab.info(context))

    def test_expected_token_hash_is_not_published_in_challenge(self):
        challenge=self.model.binding_challenge();body=signed.decode(challenge)['body']
        expected=self.state('ledger')['binding_challenges'][body['nonce']]['expected']
        self.assertNotIn(expected,challenge.decode())
        self.assertNotIn('token_hash',body)
        self.assertEqual(len(bytes.fromhex(body['encrypted_token'])),80)

    def test_identity_signature_and_approval_without_token_knowledge_cannot_register(self):
        challenge=self.model.binding_challenge();context=lab.check_challenge(signed.decode(challenge),self.config,self.now)
        body=dict(lab.header(self.config),nonce=context['nonce'],challenge_hash=lab.identify('binding-challenge',signed.decode(challenge)),token_hash='0'*64)
        proof=canonical(dict(body=body,signature=lab.sign(self.keys[2],'binding-proof',body)))
        approval=lab.approve_binding(self.config,challenge,proof,self.keys[0],self.now)
        with self.assertRaises(ModelError):self.model.register_binding(approval)
        self.assertIsNone(self.model.get_binding())
        self.assertFalse(self.state('ledger')['binding_challenges'][context['nonce']]['used'])
        proof=lab.prove_binding(self.config,challenge,self.keys[2],self.delivery,self.now)
        self.model.register_binding(lab.approve_binding(self.config,challenge,proof,self.keys[0],self.now))

    def test_wrong_approver_or_signature_purpose_fails_without_burning_proof(self):
        _,_,approval=self.enrollment();envelope=signed.decode(approval)
        for key,purpose in [(self.keys[1],'binding-approval'),(self.keys[0],'response-record')]:
            changed=copy.deepcopy(envelope);changed['signature']=lab.sign(key,purpose,changed['proof'])
            with self.assertRaises(ModelError):self.model.register_binding(canonical(changed))
        self.model.register_binding(approval)

    def test_service_challenge_tamper_is_rejected_before_decryption(self):
        challenge=signed.decode(self.model.binding_challenge())
        challenge['body']['delivery_epoch']=1
        with self.assertRaises(ModelError):lab.prove_binding(self.config,canonical(challenge),self.keys[2],self.delivery,self.now)

    def test_corrupt_ciphertext_with_valid_service_signature_fails_hpke(self):
        challenge=signed.decode(self.model.binding_challenge())
        value=bytearray.fromhex(challenge['body']['encrypted_token']);value[-1]^=1
        challenge['body']['encrypted_token']=value.hex()
        challenge['signature']=lab.sign(self.keys[4],'binding-challenge',challenge['body'])
        with self.assertRaises(ModelError):lab.prove_binding(self.config,canonical(challenge),self.keys[2],self.delivery,self.now)

    def test_proof_from_another_challenge_cannot_be_approved_or_registered(self):
        first,proof,_=self.enrollment();second=self.model.binding_challenge()
        with self.assertRaises(ModelError):lab.approve_binding(self.config,second,proof,self.keys[0],self.now)
        changed=signed.decode(proof);changed['body']['nonce']=signed.decode(second)['body']['nonce']
        changed['signature']=lab.sign(self.keys[2],'binding-proof',changed['body'])
        forged=dict(proof=changed,signature=lab.sign(self.keys[0],'binding-approval',changed))
        with self.assertRaises(ModelError):self.model.register_binding(canonical(forged))

    def test_expired_enrollment_does_not_create_a_binding(self):
        _,_,approval=self.enrollment();self.now=130
        with self.assertRaises(ModelError):self.model.register_binding(approval)
        self.assertIsNone(self.model.get_binding())
        self.bound()

    def test_restart_invalidates_outstanding_enrollment_but_not_a_bound_key(self):
        _,_,approval=self.enrollment();self.restart()
        with self.assertRaises(ModelError):self.model.register_binding(approval)
        registration=self.bound();self.now=140;self.restart()
        self.assertEqual(self.model.get_binding(),registration)
        self.model.challenge(self.permission,'reserve')

    def test_registration_proof_is_one_use_and_certificate_recovers_exactly(self):
        _,_,approval=self.enrollment();registration=self.model.register_binding(approval)
        with self.assertRaises(ModelError):self.model.register_binding(approval)
        self.restart()
        with self.assertRaises(ModelError):self.model.register_binding(approval)
        self.assertEqual(self.model.get_binding(),registration)
        with self.assertRaises(ModelError):self.model.binding_challenge()

    def test_encryption_key_and_signing_keys_must_be_distinct(self):
        for key in (self.policy.approver,self.policy.sender,self.policy.recipient,self.policy.revoker,self.policy.service_signer):
            policy=replace(self.policy,binding_label=lab.key_label(self.policy.service,self.policy.budget,self.policy.recipient,key,0))
            with self.assertRaises(ModelError):lab.DeliveryConfig(policy,key)

    def test_weak_or_uncommitted_delivery_public_keys_are_rejected(self):
        with self.assertRaises(ModelError):lab.DeliveryConfig(self.policy,lab.X25519PrivateKey.generate().public_key().public_bytes_raw().hex())
        for key in ('00'*32,'01'+'00'*31):
            policy=replace(self.policy,binding_label=lab.key_label(self.policy.service,self.policy.budget,self.policy.recipient,key,0))
            with self.assertRaises(ModelError):lab.DeliveryConfig(policy,key)

    def test_changed_key_configuration_cannot_reopen_existing_stores(self):
        self.bound();key=lab.X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        policy=replace(self.policy,binding_label=lab.key_label(self.policy.service,self.policy.budget,self.policy.recipient,key,0))
        config=lab.DeliveryConfig(policy,key)
        with self.assertRaises(IntegrityError):
            lab.BoundCoordinator(self.root/'components',self.root/'authority.sqlite',config,lambda:self.now,self.keys[4])
        self.assertIsNotNone(self.model.get_binding())

    def test_enrollment_issuance_is_bounded_and_survives_restart(self):
        for _ in range(self.policy.challenge_limit):self.model.binding_challenge()
        self.restart()
        with self.assertRaises(ModelError):self.model.binding_challenge()
        self.assertEqual(len(self.state('ledger')['binding_challenges']),self.policy.challenge_limit)

    def test_binding_certificate_and_approval_links_are_verified(self):
        registration=signed.decode(self.bound())
        for field,value in [('approval_hash','0'*64),('registered_at',131),('generation',999),('nonce','model:wrong')]:
            changed=copy.deepcopy(registration);changed['certificate']['body'][field]=value
            with self.subTest(field=field),self.assertRaises(ModelError):lab.verify_binding(changed,self.config,140)

    def test_registered_certificate_is_not_a_proof_for_another_service_or_epoch(self):
        registration=signed.decode(self.bound())
        for field,value in [('service','model:other-service'),('config_id','0'*64),('policy_id','1'*64),('mode','real-release')]:
            changed=copy.deepcopy(registration);changed['certificate']['body'][field]=value
            with self.subTest(field=field),self.assertRaises(ModelError):lab.verify_binding(changed,self.config,self.now)

    def test_vault_candidate_and_committed_record_are_identical(self):
        self.prepared();candidate=self.state('vault')['candidates'][self.context.grant]
        self.assertIn('response_record',candidate)
        self.assertNotIn('response_record',self.state('ledger')['grants'][self.context.grant])
        self.model.commit(self.context.grant)
        self.assertEqual(candidate['response_record'],self.state('ledger')['grants'][self.context.grant]['response_record'])
        self.verify(self.dispatch())

    def test_response_record_binds_complete_permission_request_key_and_deadline(self):
        self.committed();raw=self.dispatch();bundle=signed.decode(raw)
        self.verify(raw)
        record=bundle['record']['body']
        self.assertEqual(record['delivery_key'],self.delivery_public)
        self.assertEqual(record['permission_hash'],signed.identify('permission',signed.decode(self.permission)))
        self.assertEqual(record['admission_hash'],signed.identify('admission-request',signed.decode(self.admission)))
        self.assertEqual(record['deadline'],self.context.window_end)
        self.assertEqual(record['response_hash'],self.model.status(self.context.grant)['response_hash'])

    def test_changed_response_bytes_or_context_fail_client_verification(self):
        self.committed();original=signed.decode(self.dispatch())
        for category,field,value in [('response','placeholder','0'*32),('response','context','1'*64),
                                     ('response','operation',['model:wrong']),('context','record','model:wrong'),
                                     ('context','size',129),('context','window_end',181)]:
            changed=copy.deepcopy(original);changed[category][field]=value
            with self.subTest(field=field),self.assertRaises(ModelError):self.verify(canonical(changed))

    def test_changed_record_fields_or_signature_purpose_fail(self):
        self.committed();original=signed.decode(self.dispatch())
        for field,value in [('response_hash','0'*64),('binding_hash','1'*64),('context_hash','2'*64),
                            ('delivery_key','3'*64),('prepared_generation',999),('prepared_at',99),
                            ('ledger_checkpoint','4'*64),('deadline',999)]:
            changed=copy.deepcopy(original);changed['record']['body'][field]=value
            with self.subTest(field=field),self.assertRaises(ModelError):self.verify(canonical(changed))
        for key,purpose in [(self.keys[0],'response-record'),(self.keys[4],'binding-certificate')]:
            changed=copy.deepcopy(original);changed['record']['signature']=lab.sign(key,purpose,changed['record']['body'])
            with self.assertRaises(ModelError):self.verify(canonical(changed))

    def test_another_signed_permission_or_admission_does_not_verify_this_response(self):
        self.committed();raw=self.dispatch()
        permission=signed.permission(self.policy,replace(self.context,record='model:other'),self.keys[0],self.keys[1])
        with self.assertRaises(ModelError):lab.verify_response(self.config,permission,self.admission,raw,self.now)
        admission=signed.decode(self.admission);admission['signature']='0'*128
        with self.assertRaises(ModelError):lab.verify_response(self.config,self.permission,canonical(admission),raw,self.now)

    def test_identical_bundle_retries_and_restart_never_resign(self):
        self.committed();first=self.dispatch();record=signed.decode(first)['record']
        self.assertEqual(first,self.dispatch());self.restart();self.model.observe(self.context.grant)
        self.model.prepare(self.context.grant);self.model.commit(self.context.grant)
        second=self.dispatch()
        self.assertEqual(first,second);self.assertEqual(record,signed.decode(second)['record'])
        self.assertLess(record['body']['prepared_generation'],self.model.generation)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'],1)

    def test_pending_record_is_not_exposed_by_status_or_binding_getter(self):
        self.prepared();candidate=self.state('vault')['candidates'][self.context.grant]
        exposed=json.dumps(self.model.status(self.context.grant))+self.model.get_binding().decode()
        self.assertNotIn(candidate['response']['placeholder'],exposed)
        self.assertNotIn(candidate['response_record']['signature'],exposed)
        with self.assertRaises(ModelError):self.model.challenge(self.permission,'retrieve')

    def test_revocation_blocks_valid_request_but_does_not_erase_historical_signature(self):
        self.committed();raw=self.dispatch();request=self.retrieval();record=self.state('vault')
        self.revoke()
        with self.assertRaises(ModelError):self.model.dispatch(request)
        self.assertEqual(self.state('vault'),record)
        self.verify(raw,999)
        self.assertTrue(self.model.status(self.context.grant)['used'])

    def test_policy_or_delivery_epoch_change_blocks_without_rewrap(self):
        self.committed();raw=self.dispatch();before=self.state('vault')
        self.model.advance_epochs(1,1)
        for action in (self.model.prepare,self.model.commit):
            with self.assertRaises(ModelError):action(self.context.grant)
        with self.assertRaises(ModelError):self.model.challenge(self.permission,'retrieve')
        self.assertEqual(self.state('vault'),before)
        self.verify(raw)

    def test_reorg_and_original_deadline_block_signed_record_delivery(self):
        self.committed();request=self.retrieval();self.model.observe(self.context.grant,(True,False))
        with self.assertRaises(ModelError):self.model.dispatch(request)
        self.now=180;self.model.observe(self.context.grant)
        with self.assertRaises(ModelError):self.model.challenge(self.permission,'retrieve')
        self.assertTrue(self.model.status(self.context.grant)['possible_disclosure'])

    def test_lost_registration_ack_recovers_certificate_and_used_nonce_atomically(self):
        _,_,approval=self.enrollment();self.fail_at('ledger:saved')
        with self.assertRaises(Crash):self.model.register_binding(approval)
        saved=self.state('ledger')['registered_binding'];nonce=saved['certificate']['body']['nonce']
        self.model.hook=lambda _:None
        with self.assertRaises(RecoveryRequired):self.model.get_binding()
        self.restart()
        self.assertEqual(self.model.get_binding(),canonical(saved))
        self.assertTrue(self.state('ledger')['binding_challenges'][nonce]['used'])
        with self.assertRaises(ModelError):self.model.register_binding(approval)

    def test_crash_before_registration_commit_does_not_burn_proof(self):
        _,_,approval=self.enrollment();self.fail_at('ledger:before_commit')
        with self.assertRaises(Crash):self.model.register_binding(approval)
        self.model.hook=lambda _:None
        self.assertIsNone(self.model.get_binding())
        self.model.register_binding(approval)

    def test_vault_save_lost_ack_recovers_same_record(self):
        self.reserved();self.model.authorize(self.context.grant);self.fail_at('vault:saved')
        with self.assertRaises(Crash):self.model.prepare(self.context.grant)
        candidate=self.state('vault')['candidates'][self.context.grant]
        self.restart();self.model.observe(self.context.grant);self.model.prepare(self.context.grant);self.model.commit(self.context.grant)
        bundle=signed.decode(self.dispatch())
        self.assertEqual(bundle['record'],candidate['response_record'])
        self.assertEqual(bundle['response'],candidate['response'])

    def test_ledger_commit_lost_ack_preserves_record_and_response(self):
        self.prepared();candidate=self.state('vault')['candidates'][self.context.grant];self.fail_at('ledger:saved')
        with self.assertRaises(Crash):self.model.commit(self.context.grant)
        self.restart();self.model.observe(self.context.grant);raw=self.dispatch()
        self.assertEqual(signed.decode(raw)['record'],candidate['response_record'])
        self.verify(raw)

    def test_dispatch_lost_ack_consumes_request_and_fresh_retry_returns_saved_bundle(self):
        self.committed();request=self.retrieval();record=self.state('ledger')['grants'][self.context.grant]['response_record']
        self.fail_at('delivery:saved')
        with self.assertRaises(Crash):self.model.dispatch(request)
        self.restart();self.model.observe(self.context.grant)
        with self.assertRaises(ModelError):self.model.dispatch(request)
        self.assertEqual(signed.decode(self.dispatch())['record'],record)

    def test_record_corruption_inside_saved_component_halts_before_commit(self):
        self.prepared()
        with self.model._step() as (lease,loaded):
            loaded['vault'][0]['candidates'][self.context.grant]['response_record']['signature']='0'*128
            self.model._save(lease,loaded,'vault','injected-record-corruption')
        with self.assertRaises(IntegrityError):self.model.commit(self.context.grant)
        self.assertIsNone(self.state('ledger')['grants'][self.context.grant]['response'])

    def test_committed_record_mismatch_halts_instead_of_resigning(self):
        self.committed()
        with self.model._step() as (lease,loaded):
            loaded['ledger'][0]['grants'][self.context.grant]['response_record']['signature']='0'*128
            self.model._save(lease,loaded,'ledger','injected-record-loss')
        with self.assertRaises(IntegrityError):self.model.prepare(self.context.grant)

    def test_restored_registration_snapshot_behind_authority_halts(self):
        challenge,proof,approval=self.enrollment()
        shutil.copyfile(self.root/'components'/'ledger.sqlite',self.root/'old-ledger.sqlite')
        self.model.register_binding(approval);self.model.close()
        shutil.copyfile(self.root/'old-ledger.sqlite',self.root/'components'/'ledger.sqlite')
        self.model=self.open()
        with self.assertRaises(IntegrityError):self.model.recover()

    def test_fenced_writer_cannot_register_or_prepare_records(self):
        _,_,approval=self.enrollment();old=self.model;self.model=self.open();self.model.recover()
        try:
            with self.assertRaises(ModelError):old.register_binding(approval)
            with self.assertRaises(ModelError):old.prepare(self.context.grant)
        finally:old.close()

    def test_strict_wire_and_record_shapes_reject_malformed_or_extra_fields(self):
        _,_,approval=self.enrollment()
        for raw in (approval+b'\n',b'{"x":1,"x":2}',b'{"x":NaN}',b' '*32769,b'null'):
            with self.assertRaises(ModelError):self.model.register_binding(raw)
        self.model.register_binding(approval)
        # Reuse bound setup without enrolling a second time.
        self.admission=signed.answer(self.policy,self.permission,self.model.challenge(self.permission,'reserve'),self.keys[2],self.now)
        self.model.reserve(self.permission,self.admission);self.model.observe(self.context.grant)
        self.model.authorize(self.context.grant);self.model.prepare(self.context.grant);self.model.commit(self.context.grant)
        bundle=signed.decode(self.dispatch())
        for record in (None,{},dict(body=None,signature='0'*128)):
            changed=copy.deepcopy(bundle);changed['record']=record
            with self.assertRaises(ModelError):self.verify(canonical(changed))
        changed=copy.deepcopy(bundle);changed['extra']=1
        with self.assertRaises(ModelError):self.verify(canonical(changed))

    def test_old_lab_binding_format_is_not_adopted(self):
        challenge=signed.decode(self.model.binding_challenge())
        challenge['body']['version']='icp-recipient-lab-v0'
        challenge['signature']=lab.sign(self.keys[4],'binding-challenge',challenge['body'])
        with self.assertRaises(ModelError):lab.prove_binding(self.config,canonical(challenge),self.keys[2],self.delivery,self.now)

    def test_captured_signed_request_can_relay_the_unencrypted_dummy_bundle(self):
        self.committed();captured=self.retrieval()
        self.keys[2]=None;self.delivery=None
        # Enrollment does not encrypt the synthetic response or bind a connection.
        raw=self.model.dispatch(captured)
        self.verify(raw)
        self.assertIn('placeholder',signed.decode(raw)['response'])
        with self.assertRaises(ModelError):self.model.dispatch(captured)

    def test_client_rejects_boolean_or_float_substitution_in_bundle_context(self):
        self.committed();bundle=signed.decode(self.dispatch())
        for field,value in [('policy_epoch',False),('delivery_epoch',False),('size',128.0)]:
            changed=copy.deepcopy(bundle);changed['context'][field]=value
            with self.subTest(field=field),self.assertRaises(ModelError):self.verify(canonical(changed))

    def test_client_rejects_wrong_numeric_types_even_with_a_valid_service_signature(self):
        self.committed();bundle=signed.decode(self.dispatch())
        for field,value in [('policy_epoch',False),('delivery_epoch',False),('deadline',180.0)]:
            changed=copy.deepcopy(bundle);changed['record']['body'][field]=value
            changed['record']['signature']=lab.sign(self.keys[4],'response-record',changed['record']['body'])
            with self.subTest(field=field),self.assertRaises(ModelError):self.verify(canonical(changed))

    def test_real_process_exit_recovers_exact_private_response_record(self):
        self.reserved();self.model.authorize(self.context.grant);self.model.close()
        script='''import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import bound_response_lab as lab
x=json.load(sys.stdin)
c=lab.DeliveryConfig(lab.signed.SignedPolicy(**x['config']['policy']),x['config']['delivery_key'],x['config']['delivery_epoch'])
k=lab.signed.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(x['service_key']))
m=lab.BoundCoordinator(Path(sys.argv[2])/'components',Path(sys.argv[2])/'authority.sqlite',c,lambda:100,k)
m.recover();m.observe(x['grant'])
m.hook=lambda stage:os._exit(73) if stage=='vault:saved' else None
m.prepare(x['grant'])
'''
        payload=dict(config=asdict(self.config),service_key=self.keys[4].private_bytes_raw().hex(),grant=self.context.grant)
        result=subprocess.run([sys.executable,'-c',script,str(Path(__file__).resolve().parents[1]/'scripts'),str(self.root)],input=json.dumps(payload),text=True,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,73,result.stderr)
        candidate=self.state('vault')['candidates'][self.context.grant]
        self.model=self.open();self.model.recover();self.model.observe(self.context.grant);self.model.commit(self.context.grant)
        raw=self.dispatch();self.assertEqual(signed.decode(raw)['record'],candidate['response_record']);self.verify(raw)


if __name__=='__main__':unittest.main()
