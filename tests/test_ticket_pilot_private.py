"""Private P0 signing with ephemeral test keys and fabricated entries. No node."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import ticket_pilot_private as p
from ticket_pilot_review import fixture_plan


class PilotPrivateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.keys = {}; self.plan = fixture_plan()
        self.plan.update(purpose='operator-unsigned-review',run_nonce='55'*32)
        self.plan['source']['transaction_id'] = '22'*32
        for role in ('funding','ticket','return'):
            k = ec.generate_private_key(ec.SECP256K1())
            secret = k.private_numbers().private_value.to_bytes(32,'big').hex()
            path = self.root/(role+'.key'); path.write_text(secret); path.chmod(0o600)
            self.keys[role] = path
            self.plan[role+'_key'] = k.public_key().public_numbers().x.to_bytes(32,'big').hex()
        self.reviewer = p.Reviewer(); self.worker = p.Worker()
        self.review = self.reviewer.make(self.plan)
        self.claims = self.root/'claims.sqlite'; p.Controller.create_claims(self.claims)
        self.clock = [100]; self.controllers = []
        self.c = self.open(create=True); self.c.recover()

    def tearDown(self):
        for c in self.controllers: c.close()
        self.tmp.cleanup()

    def open(self, create=False, review=None, name='pilot', worker=None, hook=None):
        c = p.Controller(self.root/name,self.root/(name+'-authority.sqlite'),self.claims,
                         review or self.review,lambda:self.clock[0],create=create,
                         reviewer=self.reviewer,worker=worker or self.worker,hook=hook)
        self.controllers.append(c); return c

    def entry(self, phase='issue'):
        issue = phase == 'issue'; role = 'funding' if issue else 'ticket'
        return dict(amount=self.plan['source']['amount'] if issue else 12_000_000,
                    scriptPublicKey='000020'+self.plan[role+'_key']+'ac',
                    blockDaaScore=123,isCoinbase=False,covenantId=None)

    def prepare_issue(self): return self.c.prepare('issue',self.entry(),self.keys['funding'])

    def saved(self, phase='issue'):
        row = json.loads(self.c._journal.db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()[0])
        return row['state'][phase+'_record']

    def test_issue_and_both_independent_terminal_lifecycles(self):
        for branch, name in [('consume','consume-run'),('refund','refund-run')]:
            plan=deepcopy(self.plan);plan['source']['index']=1 if branch=='consume' else 2
            review=self.reviewer.make(plan);c=self.open(True,review,name);c.recover()
            c.prepare('issue',self.entry(),self.keys['funding']);c.choose(branch)
            result=c.prepare('terminal',self.entry('terminal'),self.keys['ticket'])
            self.assertEqual(result['branch'],branch);self.assertIsNotNone(result['terminal']['outbox_sha256'])
            self.assertFalse(result['source_observed']);self.assertEqual(result['broadcasts'],0)

    def test_public_fixture_rejected_before_state_creation(self):
        with self.assertRaises(p.Error):self.open(True,self.reviewer.make(fixture_plan()),'fixture')
        self.assertFalse((self.root/'fixture').exists())

    def test_branch_is_required_before_terminal_signing(self):
        self.prepare_issue()
        with self.assertRaises(p.Error):self.c.prepare('terminal',self.entry('terminal'),self.keys['ticket'])
        self.assertFalse(self.c.status()['terminal']['signing_started'])

    def test_choose_requires_saved_issue_and_valid_branch(self):
        for branch in ('consume','refund','other'):
            with self.assertRaises(p.Error):self.c.choose(branch)

    def test_branch_is_permanent_after_restart(self):
        self.prepare_issue();self.c.choose('consume');self.c=self.open();self.c.recover()
        self.assertEqual(self.c.choose('consume')['branch'],'consume')
        with self.assertRaises(p.Error):self.c.choose('refund')

    def test_recovery_returns_exact_outbox_without_key_or_resigning(self):
        self.prepare_issue();before=self.saved();self.c=self.open();self.c.recover()
        result=self.c.prepare('issue',{},self.root/'absent.key')
        self.assertEqual(self.saved(),before);self.assertEqual(result['issue']['outbox_sha256'],p.sha(p.canonical(before)))

    def test_wrong_key_consumes_reservation_and_requires_reconciliation(self):
        with self.assertRaises(p.Error):self.c.prepare('issue',self.entry(),self.keys['ticket'])
        self.assertTrue(self.c.status()['issue']['signing_started']);self.assertIsNone(self.saved())
        with self.assertRaises(p.RecoveryRequired):self.prepare_issue()

    def test_wrong_asserted_entry_is_rejected_without_outbox(self):
        entry=self.entry();entry['amount']-=1
        with self.assertRaises(p.Error):self.c.prepare('issue',entry,self.keys['funding'])
        self.assertIsNone(self.saved())

    def test_key_file_mode_symlink_and_noncanonical_encoding_fail(self):
        path=self.keys['funding'];path.chmod(0o644)
        with self.assertRaises(p.Error):p.load_key(path)
        path.chmod(0o600);link=self.root/'alias.key';link.symlink_to(path)
        with self.assertRaises(p.Error):p.load_key(link)
        path.write_text(path.read_text()+'\n')
        with self.assertRaises(p.Error):p.load_key(path)

    def test_source_claim_excludes_other_plan_and_other_journal(self):
        self.prepare_issue()
        for changed in (False,True):
            plan=deepcopy(self.plan)
            if changed:plan['run_nonce']='66'*32
            c=self.open(True,self.reviewer.make(plan),'other-'+str(changed));c.recover()
            with self.assertRaises(p.IntegrityError):c.prepare('issue',self.entry(),self.keys['funding'])

    def test_different_outpoint_has_independent_claim(self):
        self.prepare_issue();plan=deepcopy(self.plan);plan['source']['index']=1
        c=self.open(True,self.reviewer.make(plan),'other');c.recover()
        self.assertIsNotNone(c.prepare('issue',self.entry(),self.keys['funding'])['issue']['outbox_sha256'])

    def test_lost_signer_reply_never_retries(self):
        def hook(stage):
            if stage=='signing:returned':raise RuntimeError('simulated interruption')
        self.c.hook=hook
        with self.assertRaises(RuntimeError):self.prepare_issue()
        self.c=self.open();self.c.recover()
        with self.assertRaises(p.RecoveryRequired):self.prepare_issue()
        self.assertIsNone(self.saved())

    def test_saved_outbox_lost_ack_recovers_same_record(self):
        def hook(stage):
            if stage=='p0-private:saved' and self.saved() is not None:raise RuntimeError('simulated interruption')
        self.c.hook=hook
        with self.assertRaises(RuntimeError):self.prepare_issue()
        record=self.saved();self.assertIsNotNone(record)
        self.c=self.open();self.c.recover();self.c.prepare('issue',{},self.root/'absent.key')
        self.assertEqual(self.saved(),record)

    def test_crash_before_outbox_commit_leaves_unknown_signing_intent(self):
        count=[0]
        def hook(stage):
            if stage=='p0-private:before_commit':
                count[0]+=1
                if count[0]==2:raise RuntimeError('simulated crash')
        self.c.hook=hook
        with self.assertRaises(RuntimeError):self.prepare_issue()
        self.c=self.open();self.c.recover()
        with self.assertRaises(p.RecoveryRequired):self.prepare_issue()

    def test_new_recovery_fences_previous_writer(self):
        newer=self.open();newer.recover()
        with self.assertRaises(p.Error):self.prepare_issue()
        self.assertIsNotNone(newer.prepare('issue',self.entry(),self.keys['funding'])['issue']['outbox_sha256'])

    def test_restore_behind_independent_checkpoint_halts(self):
        snapshot=self.root/'old.sqlite';shutil.copy2(self.root/'pilot/pilot.sqlite',snapshot)
        self.prepare_issue();self.c.close();self.controllers.remove(self.c)
        shutil.copy2(snapshot,self.root/'pilot/pilot.sqlite');self.c=self.open()
        with self.assertRaises(p.IntegrityError):self.c.recover()
        with self.assertRaises(p.Error):self.c.status()

    def test_missing_claim_registry_or_component_is_not_recreated(self):
        self.claims.rename(self.root/'oldclaims.sqlite')
        with self.assertRaises(FileNotFoundError):self.open()
        self.assertFalse(self.claims.exists())

    def test_backward_clock_halts_and_retains_saved_outbox(self):
        self.prepare_issue();before=self.saved();self.clock[0]=99
        with self.assertRaises(p.Error):self.c.status()
        self.assertEqual(self.saved(),before)

    def test_mutated_review_or_worker_binary_fails_before_new_intent(self):
        self.c.review['plan']['run_nonce']='66'*32
        with self.assertRaises(p.IntegrityError):self.prepare_issue()
        self.c.review=deepcopy(self.review)
        copied=self.root/'worker';shutil.copy2(self.worker.path,copied)
        c=self.open(True,name='other',worker=p.Worker(copied));c.recover()
        with copied.open('ab') as f:f.write(b'changed')
        with self.assertRaises(p.Error):c.prepare('issue',self.entry(),self.keys['funding'])
        raw=c._journal.db.execute('SELECT body FROM events ORDER BY seq DESC LIMIT 1').fetchone()[0]
        self.assertFalse(json.loads(raw)['state']['issue_started'])

    def test_native_rejects_signature_mass_compute_output_and_action_tampering(self):
        self.prepare_issue();saved=self.saved()
        mutations=[lambda r:r['signed_rpc'].__setitem__('storageMass',1),
                   lambda r:r['signed_rpc']['inputs'][0].__setitem__('computeBudget',101),
                   lambda r:r['signed_rpc']['inputs'][0].__setitem__('signatureScript',''),
                   lambda r:r['signed_rpc']['outputs'][0].__setitem__('value',1),
                   lambda r:r.__setitem__('action','refund')]
        for mutate in mutations:
            record=deepcopy(saved);mutate(record)
            with self.assertRaises(p.Error):self.worker.verify(record)

    def test_private_channel_duplicate_unknown_and_boolean_amounts_fail(self):
        req=dict(plan=self.plan,action='issue',entry=self.entry(),secret_key=p.load_key(self.keys['funding']))
        raw=p.canonical(req)
        variants=[b' '+raw,raw.replace(b'{',b'{"extra":0,',1),raw.replace(b'{',b'{"action":"issue",',1),raw.replace(b'24000000',b'true')]
        for bad in variants:
            result=subprocess.run([str(self.worker.path),'prepare'],input=bad,capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn(req['secret_key'].encode(),result.stderr+result.stdout)

    def test_status_and_private_journal_never_store_secret_key(self):
        status=self.prepare_issue();data=p.canonical(status)
        rows=''.join(r[0] for r in self.c._journal.db.execute('SELECT body FROM events')).encode()
        for path in self.keys.values():
            secret=path.read_bytes();self.assertNotIn(secret,data);self.assertNotIn(secret,rows)
        self.assertNotIn(b'signed_rpc',data);self.assertNotIn(b'signatureScript',data)
        for path in (self.claims,self.root/'pilot-authority.sqlite',self.root/'pilot/pilot.sqlite'):
            self.assertEqual(path.stat().st_mode & 0o077,0)

    def test_no_effect_commands_or_implicit_registry_reset(self):
        for op in ('submit','broadcast','keygen'):
            with self.assertRaises(p.Error):self.worker.run(op,{})
        with self.assertRaises(FileExistsError):p.Controller.create_claims(self.claims)
        with self.assertRaises(p.Error):self.open(True)
        for authority,claims in [(self.root/'nested/authority.sqlite',self.claims),
                                 (self.root/'external.sqlite',self.root/'nested/claims.sqlite')]:
            with self.assertRaises(p.Error):
                p.Controller(self.root/'nested',authority,claims,self.review,lambda:100,create=True)
        self.assertFalse((self.root/'nested').exists())

    def test_terminal_unknown_outcome_keeps_branch_and_issue(self):
        self.prepare_issue();issue=self.saved();self.c.choose('refund')
        with self.assertRaises(p.Error):self.c.prepare('terminal',self.entry('terminal'),self.keys['funding'])
        self.c=self.open();self.c.recover()
        with self.assertRaises(p.RecoveryRequired):self.c.prepare('terminal',self.entry('terminal'),self.keys['ticket'])
        with self.assertRaises(p.Error):self.c.choose('consume')
        self.assertEqual(self.saved(),issue)

    def test_crash_after_reservation_before_signing_does_not_access_key_on_retry(self):
        def hook(stage):
            if stage=='signing:reserved':raise RuntimeError('simulated interruption')
        self.c.hook=hook
        with self.assertRaises(RuntimeError):self.prepare_issue()
        self.c=self.open();self.c.recover()
        with self.assertRaises(p.RecoveryRequired):self.c.prepare('issue',{},self.root/'absent.key')
        self.assertIsNone(self.saved())

    def test_branch_saved_without_ack_is_recovered_before_terminal_signing(self):
        self.prepare_issue()
        def hook(stage):
            if stage=='p0-private:saved':raise RuntimeError('simulated interruption')
        self.c.hook=hook
        with self.assertRaises(RuntimeError):self.c.choose('refund')
        self.c=self.open();self.c.recover()
        with self.assertRaises(p.Error):self.c.choose('consume')
        self.assertEqual(self.c.prepare('terminal',self.entry('terminal'),self.keys['ticket'])['branch'],'refund')

    def test_unacknowledged_history_cannot_skip_durable_signing_reservation(self):
        # A fabricated future row has a valid hash but an impossible event transition.
        state=p.initial();state['issue_started']=True;state['issue_entry']=self.entry()
        with self.c._authority.serial(self.c.generation) as lease:
            _,previous=self.c._journal.load(lease)
            self.c._claim(create=True)
            body=self.c._journal._body(previous[0]+1,previous[1],'issue-outbox',state)
            self.c._journal.db.execute('INSERT INTO events VALUES(?,?,?)',
                (previous[0]+1,p.core.canonical(body).decode(),p.core.digest(body)))
        with self.assertRaisesRegex(p.IntegrityError,'skipped'):self.c.recover()

    def test_joint_restore_of_all_trusted_stores_defeats_branch_permanence(self):
        # Explicit counterexample: no external monotonic authority is claimed.
        self.prepare_issue()
        paths=[self.root/'pilot/pilot.sqlite',self.root/'pilot-authority.sqlite',self.claims]
        backups=[]
        for i,path in enumerate(paths):
            backup=self.root/('snapshot-'+str(i));shutil.copy2(path,backup);backups.append(backup)
        self.c.choose('consume');self.c.close();self.controllers.remove(self.c)
        for path,backup in zip(paths,backups):shutil.copy2(backup,path)
        self.c=self.open();self.c.recover()
        self.assertEqual(self.c.choose('refund')['branch'],'refund')
