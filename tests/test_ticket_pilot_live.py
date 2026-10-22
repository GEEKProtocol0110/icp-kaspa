"""Live-capable policy and native boundary with offline/simulated evidence only."""
from copy import deepcopy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_ticket_pilot_binding as harness
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_ticket_observer as native
import ticket_pilot_binding as binding
import ticket_pilot_private as private
import ticket_pilot_submission as simulated
import ticket_pilot_live as live


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.h=harness.PilotBindingTests(); self.h.setUp()
        self.transport=live.Transport(self.h.a.endpoint); self.calls=[]
        self.c=self.open(create=True); self.h.c=self.c; self.c.recover()
        self.send_patch=patch.object(self.transport,'send',side_effect=self.inspect)
        self.send_patch.start()

    def open(self,create=False,**kwargs):
        h=self.h
        c=live.Controller(h.secret/'live-component',h.secret/'live-authority/service.sqlite',h.claims,
            h.review,lambda:h.clock[0],observations=kwargs.pop('observations',h.pair),
            transport=kwargs.pop('transport',self.transport),create=create,reviewer=h.reviewer,worker=h.worker,**kwargs)
        h.controllers.append(c); return c

    def tearDown(self): self.send_patch.stop(); self.h.tearDown()

    def prepare(self): self.h.preflight(); self.h.prepare_issue()

    def request(self):
        return dict(mode=live.REQUEST_MODE,endpoint=self.transport.endpoint,not_before=100,not_after=105,
                    record=deepcopy(self.h.state()['issue_record']))

    def run_native(self,payload,operation='verify',env=None):
        raw=payload if type(payload) is bytes else private.canonical(payload)
        return subprocess.run([str(self.transport.binary),operation],input=raw,capture_output=True,
                              timeout=10,env=env or {'PATH':'/usr/bin:/bin'})

    def inspect(self,payload):
        self.calls.append(deepcopy(payload))
        result=self.run_native(payload)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        reply=private.decode(result.stdout)
        self.assertEqual(reply['mode'],'TN10_P0_SUBMISSION_REQUEST_VALID_NOT_SENT')
        return dict(transaction_id=reply['transaction_id'],accepted=True)

    def issued(self):
        self.prepare(); self.c.submit('issue'); self.h.clock[0]=101
        rpc=deepcopy(self.h.state()['issue_record']['signed_rpc'])
        rpc['verboseData']=dict(transactionId=self.h.state()['issue_record']['transaction_id'])
        for t in self.h.pair.trackers:
            t.apply(native.fixture_scan(3,[4,5,6],transactions={4:[rpc]}),101)
            t.apply_utxos(self.h.utxos(t,'terminal',before=6),101)
        self.c.reconcile_observations()

    def fixture_transport(self,body):
        relay=self.h.root/'relay.py'; relay.write_text(body)
        return live.Transport(self.transport.endpoint,relay=relay)

    def test_issue_dispatch_has_exact_record_endpoint_and_original_observation_deadline(self):
        self.prepare()
        self.h.clock[0]=102
        result=self.c.submit('issue'); req=self.calls[0]
        self.assertEqual(req['record'],self.h.state()['issue_record'])
        self.assertEqual((req['not_before'],req['not_after']),(102,105))
        self.assertEqual(req['endpoint'],self.h.a.endpoint)
        self.assertEqual(result['mode'],live.MODE); self.assertTrue(result['network_submission_capable'])
        self.assertNotIn('live_broadcasts',result)
        self.assertNotIn('signed_rpc',private.canonical(result).decode())
        with self.assertRaises(private.RecoveryRequired): self.c.submit('issue')
        self.assertEqual(len(self.calls),1)

    def test_transport_requires_canonical_tls_tn10_endpoint(self):
        for url in ('https://a.invalid/kaspa/testnet-10/wrpc/borsh','wss://a.invalid/kaspa/mainnet/wrpc/borsh',
                    'wss://user@a.invalid/kaspa/testnet-10/wrpc/borsh','wss://a.invalid/kaspa/testnet-10/wrpc/borsh?x=1',
                    'wss://A.invalid/kaspa/testnet-10/wrpc/borsh','wss://a.invalid:0443/kaspa/testnet-10/wrpc/borsh'):
            with self.assertRaises(private.Error): live.Transport(url)

    def test_submission_endpoint_must_match_first_observer_before_creation(self):
        other=live.Transport(self.h.b.endpoint)
        with self.assertRaises(private.Error):
            live.Controller(self.h.secret/'uncreated',self.h.secret/'other/state.sqlite',self.h.claims,
                self.h.review,lambda:100,transport=other,observations=self.h.pair,create=True)
        self.assertFalse((self.h.secret/'uncreated').exists())

    def test_live_controller_rejects_simulated_transport_and_simulated_api(self):
        with self.assertRaises(private.Error): self.open(transport=simulated.SimulatedTransport())
        self.prepare()
        with self.assertRaises(private.Error): self.c.submit_simulated('issue')
        self.assertIsNone(self.c.status()['submissions']['issue']['intent']); self.assertFalse(self.calls)

    def test_simulated_and_preparation_policies_cannot_reopen_live_journal(self):
        args=(self.c.root,self.h.secret/'live-authority/service.sqlite',self.h.claims,self.h.review,lambda:100)
        with self.assertRaises(private.IntegrityError):
            simulated.Controller(*args,observations=self.h.pair,transport=simulated.SimulatedTransport())
        with self.assertRaises(private.IntegrityError): binding.Controller(*args,observations=self.h.pair)

    def test_live_policy_cannot_relabel_a_simulated_journal(self):
        root=self.h.secret/'simulation'; authority=self.h.secret/'sim-authority/state.sqlite'
        c=simulated.Controller(root,authority,self.h.claims,self.h.review,lambda:100,
            observations=self.h.pair,transport=simulated.SimulatedTransport(),create=True)
        c.close()
        with self.assertRaises(private.IntegrityError):
            live.Controller(root,authority,self.h.claims,self.h.review,lambda:100,
                observations=self.h.pair,transport=self.transport)

    def test_saved_submission_needs_no_private_key_or_new_signature(self):
        self.prepare()
        for path in self.h.keys.values():path.unlink()
        with patch.object(private,'load_key') as key,patch.object(self.h.worker,'prepare') as signer:
            self.c.submit('issue'); key.assert_not_called(); signer.assert_not_called()

    def test_unknown_sender_outcome_is_permanent_and_read_only(self):
        self.prepare()
        with patch.object(self.transport,'send',side_effect=TimeoutError('lost response')):
            result=self.c.submit('issue')
        self.assertEqual(result['submissions']['issue']['reply'],'UNKNOWN')
        with self.assertRaises(private.RecoveryRequired):self.c.submit('issue')
        self.assertFalse(self.c.reconcile_submission('issue')['current_exact_observed'])

    def test_slow_payload_construction_cannot_reuse_earlier_eligibility(self):
        self.prepare(); payload=self.c._payload
        def slow(record): self.h.clock[0]=106; return payload(record)
        with patch.object(self.c,'_payload',side_effect=slow):
            with self.assertRaises(private.Error):self.c.submit('issue')
        self.assertFalse(self.calls)
        self.assertIsNotNone(self.c.status()['submissions']['issue']['intent'])

    def test_expired_after_reservation_never_accesses_sender(self):
        self.prepare()
        self.c.hook=lambda s:self.h.clock.__setitem__(0,106) if s=='submission:reserved' else None
        with self.assertRaises(private.Error):self.c.submit('issue')
        self.assertFalse(self.calls)

    def test_consume_uses_same_native_record_verifier_and_permanent_choice(self):
        self.issued(); self.c.choose('consume')
        self.c.prepare('terminal',self.h.entry('terminal'),self.h.keys['ticket']); self.c.submit('terminal')
        self.assertEqual(self.calls[-1]['record']['action'],'consume')
        with self.assertRaises(private.Error):self.c.choose('refund')

    def test_refund_uses_same_native_record_verifier_and_permanent_choice(self):
        self.issued(); self.c.choose('refund')
        self.c.prepare('terminal',self.h.entry('terminal'),self.h.keys['ticket']); self.c.submit('terminal')
        self.assertEqual(self.calls[-1]['record']['action'],'refund')
        with self.assertRaises(private.Error):self.c.choose('consume')

    def test_reconciliation_observes_issue_without_any_new_effect(self):
        self.issued()
        before=deepcopy(self.c.status())
        self.assertTrue(self.c.reconcile_submission('issue')['current_exact_observed'])
        self.assertEqual(self.c.status(),before); self.assertEqual(len(self.calls),1)

    def test_recovery_requires_fresh_observations_and_retains_attempt(self):
        self.prepare(); self.c.submit('issue'); saved=self.c.status()
        self.c=self.open(); self.h.c=self.c; self.c.recover()
        self.assertEqual(saved,self.c.status())
        with self.assertRaises(private.Error):self.c.reconcile_submission('issue')
        with self.assertRaises(private.RecoveryRequired):self.c.submit('issue')
        self.assertEqual(len(self.calls),1)

    def test_endpoint_or_binary_policy_mutation_halts_new_work(self):
        self.transport.endpoint=self.h.b.endpoint
        with self.assertRaises(private.IntegrityError):self.c.status()
        self.assertEqual(self.c._authority.db.execute('SELECT halted FROM meta').fetchone(),(1,))

    def test_changed_relay_bytes_are_detected(self):
        t=self.fixture_transport('pass\n'); t.relay.write_text('raise SystemExit(1)\n')
        with self.assertRaises(private.IntegrityError):t.check()

    def test_native_rejects_modified_full_hash_signature_and_action_before_network(self):
        self.prepare()
        for field in ('hash','signature','action'):
            req=self.request()
            if field=='hash':req['record']['full_hash']='00'*32
            elif field=='signature':req['record']['signed_rpc']['inputs'][0]['signatureScript']=''
            else:req['record']['action']='refund'
            self.assertNotEqual(self.run_native(req).returncode,0)

    def test_native_closed_schema_rejects_private_key_extra_duplicate_and_noncanonical_input(self):
        self.prepare(); req=self.request(); marker='private-marker-must-not-echo'
        changed=deepcopy(req);changed['secret_key']=marker
        raw=private.canonical(req)
        for value in (changed,b' '+raw,raw.replace(b'"mode":',b'"mode":"duplicate","mode":',1)):
            result=self.run_native(value);self.assertNotEqual(result.returncode,0)
            self.assertNotIn(marker.encode(),result.stderr+result.stdout)

    def test_native_expired_or_future_dispatch_refuses_before_connecting(self):
        self.prepare(); req=self.request()
        self.assertNotEqual(self.run_native(req,'submit').returncode,0)
        current=int(time.time()); req.update(not_before=current+100,not_after=current+105)
        self.assertNotEqual(self.run_native(req,'submit').returncode,0)

    def test_native_refuses_unpinned_relay_route_before_connection(self):
        self.prepare(); req=self.request(); current=int(time.time());req.update(not_before=current,not_after=current+30)
        env={'PATH':'/usr/bin:/bin','ICP_RPC_URL':'ws://127.0.0.1:1','ICP_UPSTREAM_URL':self.h.b.endpoint}
        self.assertNotEqual(self.run_native(req,'submit',env=env).returncode,0)

    def test_native_has_no_signing_keygen_or_retry_command(self):
        for op in ('prepare','keygen','retry','broadcast','mainnet'):
            self.assertNotEqual(self.run_native(b'{}',op).returncode,0)

    def test_bounded_pipe_passes_input_without_keys_or_inherited_rpc_override(self):
        self.prepare(); req=self.request()
        t=self.fixture_transport('import json,os,sys\np=json.load(sys.stdin)\nprint(json.dumps(dict(keys=sorted(os.environ),upstream=os.environ["ICP_UPSTREAM_URL"],argv=sys.argv[1:],txid=p["record"]["transaction_id"])))\n')
        with patch.dict(os.environ,{'ICP_SIGNER_KEY_FILE':'secret-path','PRIVATE_KEY':'do-not-forward','ICP_RPC_URL':'ws://wrong'}):
            reply=t.send(req)
        self.assertNotIn('ICP_SIGNER_KEY_FILE',reply['keys']);self.assertNotIn('PRIVATE_KEY',reply['keys'])
        self.assertNotIn('ICP_RPC_URL',reply['keys'])
        self.assertEqual(reply['upstream'],self.transport.endpoint)
        self.assertEqual(reply['argv'],[str(t.binary),'submit'])
        self.assertEqual(reply['txid'],req['record']['transaction_id'])

    def test_incremental_pipe_limit_stops_oversized_stdout(self):
        self.prepare(); t=self.fixture_transport('import sys\nsys.stdout.write("x"*5000)\n')
        with self.assertRaises(private.Error):t.send(self.request())

    def test_pipe_failure_leaves_unknown_result(self):
        self.prepare(); t=self.fixture_transport('raise SystemExit(3)\n')
        with self.assertRaises(private.RecoveryRequired):t.send(self.request())

    def test_pipe_timeout_kills_whole_process_group(self):
        self.prepare(); t=self.fixture_transport('import time\ntime.sleep(60)\n')
        kill=os.killpg
        with patch.object(live.time,'monotonic',side_effect=[0,41]),patch.object(live.os,'killpg',wraps=kill) as killed:
            with self.assertRaises(TimeoutError):t.send(self.request())
        self.assertEqual(killed.call_count,1);self.assertEqual(killed.call_args.args[1],signal.SIGKILL)

    def test_dispatch_window_is_closed_before_process_access(self):
        self.prepare()
        for lower,upper in ((True,105),(100,100),(100,131),(-1,5),(100,2**53)):
            req=self.request(); req.update(not_before=lower,not_after=upper)
            with patch.object(live.subprocess,'Popen') as process:
                with self.assertRaises(private.Error):live.Transport.send(self.transport,req)
                process.assert_not_called()

    def test_live_source_claim_remains_exclusive_with_offline_preparer(self):
        self.prepare()
        c=private.Controller(self.h.secret/'offline',self.h.secret/'offline-authority/state.sqlite',
            self.h.claims,self.h.review,lambda:100,create=True)
        try:
            c.recover()
            with self.assertRaises(private.IntegrityError):c.prepare('issue',self.h.entry(),self.h.keys['funding'])
        finally:c.close()
