import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from recovery_signer import (PROTOCOL, PROBE_PROTOCOL, RemoteNative, SignerNative, digest, serve)
from watchtower import Store, WatchError, act, heartbeat
from watch_health import health
from signer_probe import probe
from test_watchtower import (Adapter, CONFIG, H, NODE, PENDING, ROOT, response,
                            transaction, utxo)

DESCRIPTOR = {**CONFIG, 'version': 'protected-v1', 'cold_spk': 'ee', 'cold_delay_daa': 1800}
PIN = digest(DESCRIPTOR)
REQUEST = {'protocol': PROTOCOL, 'descriptor_sha256': PIN, 'pending': PENDING}


class SignerAdapter(Adapter):
    def call(self, *args):
        if args == ('descriptor',):
            return copy.deepcopy(DESCRIPTOR)
        raise AssertionError(args)

    def prepare(self, pending):
        return {**super().prepare(pending), 'version': 'protected-v1', 'network': 'testnet-10',
                'path': '/private/receipt', 'node': NODE}


class RecoveryServiceTests(unittest.TestCase):
    def test_recovery_only_response_and_no_broadcast(self):
        native = SignerAdapter()
        result = serve(REQUEST, {'descriptor_sha256': PIN}, native)
        self.assertEqual(native.prepared, [PENDING])
        self.assertFalse(native.broadcasts)
        self.assertEqual(set(result), {'version', 'network', 'status', 'id', 'transaction'})

    def test_readiness_probe_checks_node_without_signing(self):
        native = SignerAdapter()
        result = serve({'protocol': PROBE_PROTOCOL, 'descriptor_sha256': PIN}, {'descriptor_sha256': PIN}, native)
        self.assertTrue(result['ready'])
        self.assertFalse(native.prepared)
        native.snapshot = lambda: {'node': {**NODE, 'isSynced': False}}
        with self.assertRaises(WatchError):
            serve({'protocol': PROBE_PROTOCOL, 'descriptor_sha256': PIN}, {'descriptor_sha256': PIN}, native)

    def test_no_request_can_select_operation_destination_key_or_network(self):
        for field in ('command', 'destination', 'key', 'network', 'transaction'):
            with self.subTest(field=field), self.assertRaises(WatchError):
                serve({**REQUEST, field: 'release'}, {'descriptor_sha256': PIN}, SignerAdapter())

    def test_protocol_pin_and_outpoint_validation_precedes_native_access(self):
        for update in ({'protocol': 'other'}, {'descriptor_sha256': H(99)},
                       {'pending': ROOT + ';release'}, {'pending': H(2) + ':1'},
                       {'pending': None}):
            with self.subTest(update=update), self.assertRaises(WatchError):
                serve({**REQUEST, **update}, {'descriptor_sha256': PIN}, None)

    def test_config_drift_fails_before_signing(self):
        native = SignerAdapter()
        native.call = lambda *args: {**DESCRIPTOR, 'cold_spk': 'ff'}
        with self.assertRaises(WatchError):
            serve(REQUEST, {'descriptor_sha256': PIN}, native)
        self.assertFalse(native.prepared)

    def test_independent_node_rejects_wrong_network_unsynced_idle_and_missing(self):
        for update in ('network', 'unsynced', 'idle', 'missing'):
            native = SignerAdapter()
            snapshot = native.snapshot()
            if update == 'network': snapshot['node']['networkId'] = 'mainnet'
            if update == 'unsynced': snapshot['node']['isSynced'] = False
            if update == 'idle': snapshot['utxos'][0]['utxoEntry']['scriptPublicKey'] = 'aa'
            if update == 'missing': snapshot['utxos'] = []
            native.snapshot = lambda: snapshot
            with self.subTest(update=update), self.assertRaises(WatchError):
                serve(REQUEST, {'descriptor_sha256': PIN}, native)
            self.assertFalse(native.prepared)

    def test_native_response_cannot_redirect_or_add_covenant(self):
        native = SignerAdapter()
        native.bad = True
        with self.assertRaises(WatchError):
            serve(REQUEST, {'descriptor_sha256': PIN}, native)
        native.bad = False
        original = native.prepare
        def changed(pending):
            result = original(pending)
            result['transaction']['outputs'][0]['covenant'] = {'id': H(9)}
            return result
        native.prepare = changed
        with self.assertRaises(WatchError):
            serve(REQUEST, {'descriptor_sha256': PIN}, native)

    def test_only_prepare_process_receives_recovery_key(self):
        config = {'cli': '/bin/native', 'working_dir': '/', 'state_dir': '/public',
                  'receipt_dir': '/receipts', 'rpc_url': 'ws://127.0.0.1:17210',
                  'recovery_key': '/private/recovery'}
        native = SignerNative(config)
        with patch('recovery_signer.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run:
            for operation in ('descriptor', 'status', 'prepare-recover'):
                native.call(operation, *([PENDING] if operation == 'prepare-recover' else []))
                env = run.call_args.kwargs['env']
                self.assertEqual('ICP_SIGNER_KEY_FILE' in env, operation == 'prepare-recover')
                self.assertNotIn('HOME', env)
            with self.assertRaises(WatchError): native.call('release', PENDING)

    def client_config(self, directory):
        root = Path(directory)
        for name in ('identity', 'hosts'): (root / name).touch()
        value = {'host': 'signer.example.invalid', 'user': 'icp-recovery', 'port': 22,
                 'identity_file': str(root / 'identity'), 'known_hosts_file': str(root / 'hosts'),
                 'descriptor_sha256': PIN}
        path = root / 'client.json'
        path.write_text(json.dumps(value))
        return path

    def test_client_pins_ssh_and_sends_only_bounded_json_on_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = RemoteNative(['/bin/native'], self.client_config(tmp), DESCRIPTOR)
            receipt = serve(REQUEST, {'descriptor_sha256': PIN}, SignerAdapter())
            with patch.dict(os.environ, {'ICP_SIGNER_KEY_FILE': '/do-not-inherit', 'SSH_AUTH_SOCK': '/agent'}):
                with patch('recovery_signer.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(receipt), '')) as run:
                    self.assertEqual(client.prepare(PENDING), receipt)
                    args = run.call_args.args[0]
                    self.assertIn('StrictHostKeyChecking=yes', args)
                    self.assertIn('IdentityAgent=none', args)
                    self.assertEqual(args[-1], 'signer.example.invalid')
                    self.assertEqual(json.loads(run.call_args.kwargs['input']), REQUEST)
                    self.assertNotIn('ICP_SIGNER_KEY_FILE', run.call_args.kwargs['env'])
                    self.assertNotIn('SSH_AUTH_SOCK', run.call_args.kwargs['env'])

    def test_remote_transport_failure_is_durable_and_restart_keeps_exact_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'watch.sqlite'
            store = Store(path, DESCRIPTOR)
            store.arm(H(10), [utxo()])
            store.apply(response(txs=[transaction()]))
            client = RemoteNative(['/bin/native'], self.client_config(tmp), DESCRIPTOR)
            client.snapshot = Adapter().snapshot
            sends = []
            def broadcast(payload):
                sends.append(payload)
                raise TimeoutError('unknown broadcast outcome')
            client.broadcast = broadcast
            def wire(command, **kwargs):
                result = serve(json.loads(kwargs['input']), {'descriptor_sha256': PIN}, SignerAdapter())
                return subprocess.CompletedProcess(command, 0, json.dumps(result), '')
            with patch('recovery_signer.subprocess.run', side_effect=wire) as transport:
                act(store, client, True, 100)
                store.db.close()
                store = Store(path, DESCRIPTOR)
                act(store, client, True, 111)
                self.assertEqual(transport.call_count, 1)
                self.assertEqual(sends[0], sends[1])
                self.assertEqual(store.db.execute('SELECT attempts FROM actions').fetchone()[0], 2)
            store.db.close()

    def test_actual_forced_command_process_protocol_and_size_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / 'native'
            receipt = SignerAdapter().prepare(PENDING)
            data = {'descriptor': DESCRIPTOR, 'status': SignerAdapter().snapshot(), 'prepare-recover': receipt}
            fake.write_text('#!/usr/bin/python3\nimport json,sys\ndata=' + repr(data) + '\nprint(json.dumps(data[sys.argv[1]]))\n')
            fake.chmod(0o700)
            config = root / 'server.json'
            config.write_text(json.dumps({'cli': str(fake), 'working_dir': tmp, 'state_dir': tmp,
                'receipt_dir': tmp, 'rpc_url': 'ws://127.0.0.1:17210', 'recovery_key': str(root / 'key'),
                'descriptor_sha256': PIN}))
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'scripts/recovery_signer.py'), '--config', str(config)]
            for raw, original, success in ((json.dumps(REQUEST), '', True),
                    ('x' * 1025, '', False), ('{}', '', False),
                    (json.dumps(REQUEST), 'release ' + PENDING, False)):
                result = subprocess.run(command, input=raw, text=True, capture_output=True,
                                        env={**os.environ, 'SSH_ORIGINAL_COMMAND': original}, timeout=5)
                self.assertEqual(result.returncode == 0, success)
                if success: self.assertNotIn('path', json.loads(result.stdout))
                else: self.assertFalse(result.stdout)


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'watch.sqlite'
        self.store = Store(self.path, DESCRIPTOR)
        self.store.arm(H(10), [utxo()])
        with self.store.db:self.store.put('signer_probe_at','100')

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def report(self, now=110):
        return health(self.path, now=now)

    def test_no_heartbeat_and_dry_local_run_are_unhealthy(self):
        self.assertIn('STALE_HEARTBEAT', self.report()['issues'])
        heartbeat(self.store, NODE, False, now=100)
        self.assertEqual(self.report()['issues'], ['DRY_RUN', 'LOCAL_SIGNER'])

    def test_healthy_scan_and_staleness(self):
        heartbeat(self.store, NODE, True, remote=True, now=100)
        self.assertTrue(self.report()['healthy'])
        self.assertIn('STALE_HEARTBEAT', self.report(300)['issues'])

    def test_restarts_and_fresh_heartbeats_cannot_hide_stalled_node(self):
        heartbeat(self.store, NODE, True, remote=True, now=100)
        self.store.db.close()
        self.store = Store(self.path, DESCRIPTOR)
        heartbeat(self.store, NODE, True, remote=True, now=200)
        self.assertIn('NODE_DAA_STALLED', self.report(201)['issues'])
        heartbeat(self.store, {**NODE, 'virtualDaaScore': NODE['virtualDaaScore'] + 1}, True, remote=True, now=202)
        with self.store.db:self.store.put('signer_probe_at','202')
        self.assertTrue(self.report(203)['healthy'])

    def test_signer_probe_failure_is_visible(self):
        heartbeat(self.store, NODE, True, remote=True, now=100)
        with self.store.db:self.store.put('signer_probe_error','unavailable')
        self.assertIn('SIGNER_UNAVAILABLE', self.report()['issues'])

    def test_retry_exhaustion_deadline_and_confirmation(self):
        self.store.apply(response(txs=[transaction()]))
        adapter = Adapter()
        adapter.fail = True
        for at in (100, 111, 122): act(self.store, adapter, True, at)
        heartbeat(self.store, {**NODE, 'virtualDaaScore': NODE['virtualDaaScore'] + 600}, True, remote=True, now=123)
        issues = self.report(124)['issues']
        for issue in ('RECOVERY_UNCONFIRMED', 'RECOVERY_RETRY_REQUIRED', 'RECOVERY_ATTEMPTS_EXHAUSTED', 'RECOVERY_DEADLINE_REACHED'):
            self.assertIn(issue, issues)
        self.store.apply(response(H(11), H(12), [transaction(PENDING, H(3), 'cc', 9800)]))
        self.assertTrue(self.report(124)['healthy'])

    def test_watch_error_and_unapproved_execution_stay_visible(self):
        heartbeat(self.store, NODE, True, remote=True, now=100)
        with self.store.db: self.store.put('health_error', 'RPC failed')
        self.assertIn('WATCH_ERROR', self.report()['issues'])
        self.store.apply(response(txs=[transaction()]))
        self.store.apply(response(H(11), H(12), [transaction(PENDING, H(4), 'dd', 9800)]))
        heartbeat(self.store, NODE, True, remote=True, now=105)
        self.assertIn('UNAUTHORIZED_EXECUTION', self.report()['issues'])

    def test_independent_probe_records_success_and_failure(self):
        client = SignerAdapter()
        client.probe = lambda: None
        self.assertTrue(probe(client, self.path, DESCRIPTOR, now=100))
        client.probe = lambda: (_ for _ in ()).throw(TimeoutError())
        self.assertFalse(probe(client, self.path, DESCRIPTOR, now=101))
        self.assertTrue(self.store.get('signer_probe_error'))
        self.assertEqual(self.store.get('signer_probe_at'), '101')

    def test_probe_rejects_different_database_policy(self):
        with self.assertRaises(RuntimeError):
            probe(None, self.path, {**DESCRIPTOR, 'recovery_spk': 'ff'}, now=100)
        self.assertEqual(self.store.get('signer_probe_at'), '100')

    def test_missing_database_check_does_not_create_database(self):
        path = Path(self.tmp.name) / 'missing.sqlite'
        with self.assertRaises(Exception): health(path)
        self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
