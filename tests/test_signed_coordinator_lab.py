"""Signed lab access to synthetic responses; no real record keys or chain effects."""
from dataclasses import asdict, replace
import copy
import json
import shutil
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import signed_coordinator_lab as lab
from release_coordinator_model import Context, IntegrityError, ModelError, RecoveryRequired, canonical


class Crash(BaseException):
    pass


class SignedCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.keys = [lab.Ed25519PrivateKey.generate() for _ in range(5)]
        self.policy = lab.SignedPolicy(**dict(zip(('approver','sender','recipient','revoker','service_signer'), map(lab.public, self.keys))))
        self.context = Context()
        self.now = 100
        self.model = self.open(create=True)
        self.model.recover()
        self.permission = lab.permission(self.policy, self.context, self.keys[0], self.keys[1])

    def open(self, create=False, root=None):
        base = root or self.root
        return lab.SignedCoordinator(base / 'components', base / 'authority.sqlite', self.policy,
                                     lambda: self.now, self.keys[4], create=create)

    def tearDown(self):
        self.model.close(); self.tmp.cleanup()

    def restart(self):
        self.model.close(); self.model = self.open(); self.model.recover()

    def request(self, purpose, permission=None):
        permission = permission or self.permission
        grant = lab.decode(permission)['body']['context']['grant']
        expected = self.model.status(grant)['response_hash'] if purpose == 'retrieve' else None
        return lab.answer(self.policy, permission, self.model.challenge(permission, purpose), self.keys[2],
                          self.now, expected_response_hash=expected)

    def reserved(self):
        request = self.request('reserve')
        self.model.reserve(self.permission, request)
        return request

    def committed(self):
        self.reserved(); self.model.observe(self.context.grant)
        self.model.authorize(self.context.grant); self.model.prepare(self.context.grant); self.model.commit(self.context.grant)

    def revocation(self, sequence=1, nonce='model:revocation', permission=None):
        return lab.revocation(self.policy, permission or self.permission, self.keys[3], sequence,
                              self.now, self.now + 30, nonce)

    def state(self, role):
        with sqlite3.connect(self.root / 'components' / (role + '.sqlite')) as db:
            return json.loads(db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()[0])['state']

    def fail_at(self, wanted):
        def hook(stage):
            if stage == wanted: raise Crash(stage)
        self.model.hook = hook

    def test_demo_is_signed_with_identical_synthetic_retries(self):
        result = lab.demo()
        self.assertEqual(result['mode'], lab.MODE)
        self.assertTrue(result['identical_retry'])
        self.assertEqual((result['content_keys'],result['rpc_calls'],result['broadcasts']), (0,0,0))
        self.assertNotIn('private', json.dumps(result))

    def test_both_approval_roles_and_recipient_are_required(self):
        request = self.request('reserve')
        for field, purpose in [('approval','approve'),('sender_signature','send')]:
            envelope = lab.decode(self.permission)
            envelope[field] = lab.sign(self.keys[2], purpose, envelope['body'])
            with self.assertRaises(ModelError): self.model.reserve(canonical(envelope), request)
        wrong = lab.decode(request)
        wrong['signature'] = lab.sign(self.keys[1], 'request/reserve', wrong['challenge'])
        with self.assertRaises(ModelError): self.model.reserve(self.permission, canonical(wrong))
        self.assertEqual(self.state('ledger')['grants'], {})
        self.model.reserve(self.permission, request)

    def test_all_context_fields_are_bound_by_signatures(self):
        fields = {'record':'model:other-record','cipher':'model:other-cipher','request':'model:other-request',
                  'recipient':'model:other-recipient','binding':'model:other-binding','ticket':'model:other-ticket',
                  'consume':'model:other-consume','challenge':'model:other-intent','size':129,'policy_epoch':1,
                  'delivery_epoch':1,'not_before':101,'expires':201,'window_start':99,'window_end':179,'grant':'model:other-grant'}
        for field, value in fields.items():
            with self.subTest(field=field):
                envelope = lab.decode(self.permission); envelope['body']['context'][field] = value
                with self.assertRaises(ModelError): self.model.challenge(canonical(envelope), 'reserve')
        self.assertEqual(self.state('ledger')['grants'], {})

    def test_permission_signature_purposes_cannot_be_swapped(self):
        envelope = lab.decode(self.permission)
        envelope['approval'] = lab.sign(self.keys[0], 'send', envelope['body'])
        with self.assertRaises(ModelError): self.model.challenge(canonical(envelope), 'reserve')
        envelope = lab.decode(self.permission)
        envelope['sender_signature'] = lab.sign(self.keys[1], 'approve', envelope['body'])
        with self.assertRaises(ModelError): self.model.challenge(canonical(envelope), 'reserve')

    def test_foreign_namespace_service_budget_and_policy_rejected(self):
        for field, value in [('version','icp-transfer-lab-v0'),('mode','real'),('network','mainnet'),
                             ('service','model:other-service'),('budget','model:other-budget'),('policy_id','0'*64)]:
            envelope = lab.decode(self.permission); envelope['body'][field] = value
            with self.subTest(field=field), self.assertRaises(ModelError): self.model.challenge(canonical(envelope), 'reserve')

    def test_wrong_registered_recipient_or_binding_rejected_even_with_valid_approvals(self):
        for context in (replace(self.context, recipient='model:someone-else'), replace(self.context, binding='model:unregistered')):
            raw = lab.permission(self.policy, context, self.keys[0], self.keys[1])
            with self.assertRaises(ModelError): self.model.challenge(raw, 'reserve')

    def test_request_for_one_permission_cannot_reserve_another(self):
        request = self.request('reserve')
        other = lab.permission(self.policy, replace(self.context, record='model:other'), self.keys[0], self.keys[1])
        with self.assertRaises(ModelError): self.model.reserve(other, request)
        self.model.reserve(self.permission, request)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'], 1)

    def test_unsigned_model_entry_points_are_not_accepted(self):
        with self.assertRaises(TypeError): self.model.reserve(self.context)
        with self.assertRaises(TypeError): self.model.dispatch(self.context.grant, self.context.request, 'model:nonce', '0'*64)
        with self.assertRaises(ModelError): self.model.revoke(self.context.grant)
        self.assertEqual(self.state('ledger')['grants'], {})

    def test_reservation_request_is_one_use_after_restart(self):
        request = self.reserved()
        with self.assertRaises(ModelError): self.model.reserve(self.permission, request)
        self.restart()
        with self.assertRaises(ModelError): self.model.reserve(self.permission, request)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'], 1)

    def test_old_generation_challenge_rejected_but_fresh_request_works(self):
        old = self.request('reserve'); self.restart()
        with self.assertRaises(ModelError): self.model.reserve(self.permission, old)
        self.reserved()

    def test_unknown_or_modified_challenge_rejected(self):
        challenge = lab.decode(self.model.challenge(self.permission, 'reserve'))
        challenge['body']['nonce'] = 'model:unissued'
        challenge['signature'] = lab.sign(self.keys[4], 'challenge/reserve', challenge['body'])
        request = lab.answer(self.policy, self.permission, canonical(challenge), self.keys[2], 100)
        with self.assertRaises(ModelError): self.model.reserve(self.permission, request)
        self.assertEqual(self.state('ledger')['grants'], {})

    def test_challenge_requires_service_signature(self):
        challenge = lab.decode(self.model.challenge(self.permission, 'reserve'))
        challenge['signature'] = lab.sign(self.keys[0], 'challenge/reserve', challenge['body'])
        with self.assertRaises(ModelError): lab.answer(self.policy, self.permission, canonical(challenge), self.keys[2], self.now)

    def test_recipient_helper_rejects_wrong_identity(self):
        challenge = self.model.challenge(self.permission, 'reserve')
        with self.assertRaises(ModelError): lab.answer(self.policy, self.permission, challenge, self.keys[0], self.now)

    def test_expired_reservation_challenge_does_not_claim_or_charge(self):
        request = self.request('reserve'); self.now = 130
        with self.assertRaises(ModelError): self.model.reserve(self.permission, request)
        self.assertEqual(self.state('ledger')['grants'], {})
        self.reserved()

    def test_old_admission_challenge_expiry_does_not_extend_or_shorten_grant(self):
        self.reserved(); self.now = 140; self.restart(); self.model.observe(self.context.grant)
        self.model.authorize(self.context.grant); self.model.prepare(self.context.grant); self.model.commit(self.context.grant)
        self.assertEqual(json.loads(self.model.dispatch(self.request('retrieve')))['mode'], 'SYNTHETIC_COORDINATOR_NO_KEYS_NO_CHAIN')
        self.now = 180
        with self.assertRaises(ModelError): self.model.challenge(self.permission, 'retrieve')

    def test_retrieval_binds_saved_request_permission_and_response(self):
        self.committed()
        request = self.request('retrieve'); envelope = lab.decode(request)
        for field, value in [('response_hash','0'*64),('admission_hash','1'*64),('permission_hash','2'*64),
                             ('grant','model:other'),('request','model:other-request'),('authority','model:other-authority'),('generation',999)]:
            changed = copy.deepcopy(envelope); changed['challenge']['body'][field] = value
            changed['signature'] = lab.sign(self.keys[2], 'request/retrieve', changed['challenge'])
            with self.subTest(field=field), self.assertRaises(ModelError): self.model.dispatch(canonical(changed))
        first = self.model.dispatch(request)
        self.assertEqual(first, self.model.dispatch(self.request('retrieve')))
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'], 1)

    def test_retrieval_request_replay_is_rejected(self):
        self.committed(); request = self.request('retrieve'); self.model.dispatch(request)
        with self.assertRaises(ModelError): self.model.dispatch(request)
        self.restart(); self.model.observe(self.context.grant)
        with self.assertRaises(ModelError): self.model.dispatch(request)
        self.model.dispatch(self.request('retrieve'))

    def test_reserve_and_retrieve_proofs_are_not_interchangeable(self):
        reserve = self.reserved(); self.model.observe(self.context.grant)
        self.model.authorize(self.context.grant); self.model.prepare(self.context.grant); self.model.commit(self.context.grant)
        with self.assertRaises(ModelError): self.model.dispatch(reserve)
        with self.assertRaises(ModelError): self.model.reserve(self.permission, self.request('retrieve'))

    def test_recipient_request_purpose_is_verified_separately(self):
        self.committed(); request = lab.decode(self.request('retrieve'))
        request['signature'] = lab.sign(self.keys[2], 'request/reserve', request['challenge'])
        with self.assertRaises(ModelError): self.model.dispatch(canonical(request))

    def test_expired_retrieval_request_does_not_consume_nonce(self):
        self.committed(); request = self.request('retrieve'); nonce = lab.decode(request)['challenge']['body']['nonce']
        self.now = 130; self.model.observe(self.context.grant)
        with self.assertRaises(ModelError): self.model.dispatch(request)
        self.assertNotIn(nonce, self.state('delivery')['nonces'])
        self.model.dispatch(self.request('retrieve'))

    def test_recovery_invalidates_outstanding_retrieval_challenge(self):
        self.committed(); request = self.request('retrieve'); self.restart(); self.model.observe(self.context.grant)
        with self.assertRaises(ModelError): self.model.dispatch(request)
        self.model.dispatch(self.request('retrieve'))

    def test_signed_revocation_blocks_an_already_signed_retrieval(self):
        self.committed(); request = self.request('retrieve'); before = self.model.status(self.context.grant)
        self.model.revoke(self.revocation())
        with self.assertRaises(ModelError): self.model.dispatch(request)
        after = self.model.status(self.context.grant)
        self.assertTrue(after['used'] and after['possible_disclosure'] and after['revoked'])
        self.assertEqual(after['response_hash'], before['response_hash'])
        self.assertEqual(after['charges'], before['charges'])

    def test_wrong_revocation_role_or_purpose_does_not_block_valid_request(self):
        self.committed(); envelope = lab.decode(self.revocation())
        for key, purpose in [(self.keys[0],'revocation'),(self.keys[3],'approve')]:
            changed = copy.deepcopy(envelope); changed['signature'] = lab.sign(key,purpose,changed['body'])
            with self.assertRaises(ModelError): self.model.revoke(canonical(changed))
        self.model.dispatch(self.request('retrieve'))

    def test_revocation_must_bind_exact_permission_and_next_sequence(self):
        self.reserved()
        for sequence in (0,2):
            with self.assertRaises(ModelError): self.model.revoke(self.revocation(sequence))
        envelope = lab.decode(self.revocation()); envelope['body']['permission_hash'] = '0'*64
        envelope['signature'] = lab.sign(self.keys[3],'revocation',envelope['body'])
        with self.assertRaises(ModelError): self.model.revoke(canonical(envelope))
        self.assertFalse(self.model.status(self.context.grant)['revoked'])

    def test_expired_revocation_fails_but_exact_saved_retry_is_idempotent(self):
        self.reserved(); raw = self.revocation(); self.now = 130
        with self.assertRaises(ModelError): self.model.revoke(raw)
        raw = self.revocation(); self.model.revoke(raw); self.now = 161; self.model.revoke(raw)
        self.assertEqual(self.state('ledger')['revocations'],1)
        with self.assertRaises(ModelError): self.model.revoke(self.revocation())

    def test_revocation_before_preparation_keeps_saved_charge(self):
        self.reserved(); self.model.observe(self.context.grant); self.model.authorize(self.context.grant)
        self.model.revoke(self.revocation())
        with self.assertRaises(ModelError): self.model.prepare(self.context.grant)
        self.assertEqual(self.state('vault')['candidates'],{})
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'],1)

    def test_epoch_changes_block_old_signed_request_without_resetting_budget(self):
        self.committed(); request = self.request('retrieve'); before=self.model.status(self.context.grant)
        self.model.advance_epochs(1,1)
        with self.assertRaises(ModelError): self.model.dispatch(request)
        self.assertEqual(self.model.status(self.context.grant)['charges'], before['charges'])

    def test_fake_reorg_blocks_valid_signed_retrieval(self):
        self.committed(); request=self.request('retrieve'); self.model.observe(self.context.grant,(False,True))
        with self.assertRaises(ModelError): self.model.dispatch(request)
        self.model.observe(self.context.grant); self.model.dispatch(request)

    def test_fenced_writer_cannot_use_a_previously_signed_request(self):
        self.committed(); request=self.request('retrieve'); old=self.model
        self.model=self.open(); self.model.recover()
        try:
            with self.assertRaises(ModelError): old.dispatch(request)
        finally: old.close()

    def test_lost_reservation_ack_preserves_proof_claim_and_single_charge(self):
        request=self.request('reserve'); self.fail_at('ledger:saved')
        with self.assertRaises(Crash): self.model.reserve(self.permission,request)
        self.model.hook=lambda _:None
        with self.assertRaises(RecoveryRequired): self.model.status(self.context.grant)
        self.restart()
        with self.assertRaises(ModelError): self.model.reserve(self.permission,request)
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'],1)
        nonce=lab.decode(request)['challenge']['body']['nonce']
        self.assertIn(nonce,self.state('ledger')['signed_used'])

    def test_lost_dispatch_ack_consumes_signed_request_before_any_retry(self):
        self.committed(); request=self.request('retrieve'); self.fail_at('delivery:saved')
        with self.assertRaises(Crash): self.model.dispatch(request)
        self.restart(); self.model.observe(self.context.grant)
        with self.assertRaises(ModelError): self.model.dispatch(request)
        response=self.model.dispatch(self.request('retrieve'))
        self.assertEqual(lab.identify('returned',json.loads(response)),lab.identify('returned',self.state('ledger')['grants'][self.context.grant]['response']))

    def test_crash_before_reservation_save_does_not_burn_challenge(self):
        request=self.request('reserve'); self.fail_at('ledger:before_commit')
        with self.assertRaises(Crash): self.model.reserve(self.permission,request)
        self.model.hook=lambda _:None
        self.assertEqual(self.state('ledger')['grants'],{})
        self.model.reserve(self.permission,request)

    def test_pending_challenge_checkpoint_blocks_use_until_recovery(self):
        self.fail_at('ledger:saved')
        with self.assertRaises(Crash): self.model.challenge(self.permission,'reserve')
        self.model.hook=lambda _:None
        with self.assertRaises(RecoveryRequired): self.model.challenge(self.permission,'reserve')
        self.restart(); self.reserved()

    def test_signed_revocation_lost_ack_is_not_discarded(self):
        self.committed(); raw=self.revocation(); self.fail_at('ledger:saved')
        with self.assertRaises(Crash): self.model.revoke(raw)
        self.restart(); self.model.revoke(raw)
        with self.assertRaises(ModelError): self.model.challenge(self.permission,'retrieve')

    def test_corrupt_stored_permission_halts_before_key_placeholder_preparation(self):
        self.reserved(); self.model.observe(self.context.grant)
        with self.model._step() as (lease,loaded):
            loaded['ledger'][0]['grants'][self.context.grant]['signed_admission']['permission']['approval']='0'*128
            self.model._save(lease,loaded,'ledger','injected-corrupt-authorization')
        with self.assertRaises(IntegrityError): self.model.prepare(self.context.grant)
        self.assertEqual(self.state('vault')['candidates'],{})

    def test_status_omits_pending_placeholder_and_signed_identity_evidence(self):
        self.reserved(); self.model.observe(self.context.grant); self.model.authorize(self.context.grant); self.model.prepare(self.context.grant)
        status=json.dumps(self.model.status(self.context.grant))
        self.assertNotIn('placeholder',status)
        self.assertNotIn(self.policy.recipient,status)
        with self.assertRaises(ModelError): self.model.challenge(self.permission,'retrieve')

    def test_all_signing_roles_and_database_policy_are_pinned(self):
        with self.assertRaises(ModelError): replace(self.policy, sender=self.policy.approver)
        with self.assertRaises(ModelError): lab.SignedCoordinator(self.root/'x',self.root/'x-authority',self.policy,lambda:100,self.keys[0],create=True)
        altered=replace(self.policy,recipient=lab.public(lab.Ed25519PrivateKey.generate()))
        with self.assertRaises(IntegrityError): lab.SignedCoordinator(self.root/'components',self.root/'authority.sqlite',altered,lambda:100,self.keys[4])

    def test_challenge_issuance_is_bounded_per_grant_and_purpose(self):
        for _ in range(self.policy.challenge_limit): self.model.challenge(self.permission,'reserve')
        with self.assertRaises(ModelError): self.model.challenge(self.permission,'reserve')
        self.assertEqual(len(self.state('ledger')['signed_challenges']),self.policy.challenge_limit)
        self.assertEqual(self.state('ledger')['grants'],{})

    def test_strict_wire_schema_size_duplicate_nonfinite_and_canonical_rules(self):
        bad=[b'',b' '* (lab.MAX_WIRE+1),b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'\xff',b'{',b'null',b'[]',b'{ }',self.permission+b'\n']
        for raw in bad:
            with self.subTest(raw=raw[:20]),self.assertRaises(ModelError): self.model.challenge(raw,'reserve')
        with self.assertRaises(ModelError): self.model.challenge(lab.decode(self.permission),'reserve')
        envelope=lab.decode(self.permission);envelope['extra']=1
        with self.assertRaises(ModelError): self.model.challenge(canonical(envelope),'reserve')

    def test_exact_numeric_types_and_signature_encoding(self):
        for field,value in [('size',True),('expires',200.0),('policy_epoch',-1)]:
            envelope=lab.decode(self.permission);envelope['body']['context'][field]=value
            with self.subTest(field=field),self.assertRaises(ModelError): self.model.challenge(canonical(envelope),'reserve')
        for sig in ('F'*128,'00','not-hex'):
            envelope=lab.decode(self.permission);envelope['approval']=sig
            with self.assertRaises(ModelError): self.model.challenge(canonical(envelope),'reserve')

    def test_captured_signed_request_can_be_relayed_once_without_the_signing_key(self):
        self.committed(); captured=self.request('retrieve')
        self.keys[2]=None  # Relay caller holds only the already-signed request bytes.
        self.assertEqual(json.loads(self.model.dispatch(captured))['mode'], 'SYNTHETIC_COORDINATOR_NO_KEYS_NO_CHAIN')
        with self.assertRaises(ModelError): self.model.dispatch(captured)

    def test_failed_budget_reservation_does_not_burn_signed_request(self):
        self.reserved()
        other=replace(self.context,grant='model:other',ticket='model:other-ticket',challenge='model:other-intent',size=1000)
        permission=lab.permission(self.policy,other,self.keys[0],self.keys[1])
        request=self.request('reserve',permission);nonce=lab.decode(request)['challenge']['body']['nonce']
        with self.assertRaises(ModelError): self.model.reserve(permission,request)
        state=self.state('ledger')
        self.assertNotIn(nonce,state['signed_used'])
        self.assertNotIn(other.grant,state['grants'])
        self.assertEqual(state['charges']['100']['bytes'],128)

    def test_two_valid_permissions_cannot_replace_one_stable_grant(self):
        first=self.request('reserve')
        other=lab.permission(self.policy,replace(self.context,record='model:other-record'),self.keys[0],self.keys[1])
        second=self.request('reserve',other)
        self.model.reserve(self.permission,first)
        with self.assertRaises(IntegrityError): self.model.reserve(other,second)
        self.assertEqual(self.state('ledger')['charges']['100']['count'],1)
        with self.assertRaises(ModelError): self.model.status(self.context.grant)

    def test_revocation_sequences_and_nonces_are_global_to_the_ledger(self):
        self.reserved()
        other=replace(self.context,grant='model:other',ticket='model:other-ticket',challenge='model:other-intent')
        permission=lab.permission(self.policy,other,self.keys[0],self.keys[1])
        self.model.reserve(permission,self.request('reserve',permission))
        self.model.revoke(self.revocation())
        with self.assertRaises(ModelError): self.model.revoke(self.revocation(1,'model:second',permission))
        with self.assertRaises(ModelError): self.model.revoke(self.revocation(2,'model:revocation',permission))
        self.assertEqual(self.state('ledger')['revocations'],1)
        self.model.revoke(self.revocation(2,'model:second',permission))
        self.assertEqual(self.state('ledger')['revocations'],2)

    def test_client_checks_intended_permission_before_signing_service_challenge(self):
        other=lab.permission(self.policy,replace(self.context,record='model:unexpected-record'),self.keys[0],self.keys[1])
        challenge=self.model.challenge(other,'reserve')
        with self.assertRaises(ModelError): lab.answer(self.policy,self.permission,challenge,self.keys[2],self.now)

    def test_client_requires_expected_committed_response_digest(self):
        self.committed();challenge=self.model.challenge(self.permission,'retrieve')
        with self.assertRaises(ModelError): lab.answer(self.policy,self.permission,challenge,self.keys[2],self.now)
        with self.assertRaises(ModelError): lab.answer(self.policy,self.permission,challenge,self.keys[2],self.now,expected_response_hash='0'*64)
        request=lab.answer(self.policy,self.permission,challenge,self.keys[2],self.now,
                           expected_response_hash=self.model.status(self.context.grant)['response_hash'])
        self.model.dispatch(request)

    def test_joint_authority_restore_can_erase_previously_accepted_revocation(self):
        self.committed()
        shutil.copytree(self.root/'components',self.root/'backup')
        shutil.copyfile(self.root/'authority.sqlite',self.root/'authority-backup.sqlite')
        self.model.revoke(self.revocation())
        self.assertTrue(self.model.status(self.context.grant)['revoked'])
        self.model.close()
        for role in ('ledger','vault','delivery'):
            shutil.copyfile(self.root/'backup'/(role+'.sqlite'),self.root/'components'/(role+'.sqlite'))
        shutil.copyfile(self.root/'authority-backup.sqlite',self.root/'authority.sqlite')
        self.model=self.open();self.model.recover();self.model.observe(self.context.grant)
        # Counterexample: signatures cannot recover a trusted witness's lost history.
        self.assertFalse(self.model.status(self.context.grant)['revoked'])
        self.model.dispatch(self.request('retrieve'))

    def test_real_process_crash_saves_reservation_and_proof_atomically(self):
        self.model.close()
        script='''import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import signed_coordinator_lab as lab
x=json.load(sys.stdin)
p=lab.SignedPolicy(**x['policy'])
m=lab.SignedCoordinator(Path(sys.argv[2])/'components',Path(sys.argv[2])/'authority.sqlite',p,lambda:100,lab.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(x['service_key'])))
m.recover()
request=lab.answer(p,x['permission'].encode(),m.challenge(x['permission'].encode(),'reserve'),lab.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(x['recipient_key'])),100)
m.hook=lambda stage: os._exit(73) if stage=='ledger:saved' else None
m.reserve(x['permission'].encode(),request)
'''
        payload=dict(policy=asdict(self.policy),permission=self.permission.decode(),
                     service_key=self.keys[4].private_bytes_raw().hex(),recipient_key=self.keys[2].private_bytes_raw().hex())
        result=subprocess.run([sys.executable,'-c',script,str(Path(__file__).resolve().parents[1]/'scripts'),str(self.root)],
                              input=json.dumps(payload),text=True,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,73,result.stderr)
        self.model=self.open();self.model.recover()
        state=self.state('ledger');row=state['grants'][self.context.grant]
        nonce=row['signed_admission']['request']['challenge']['body']['nonce']
        self.assertIn(nonce,state['signed_used'])
        self.assertEqual(self.model.status(self.context.grant)['charges']['100']['count'],1)


if __name__ == '__main__':
    unittest.main()
