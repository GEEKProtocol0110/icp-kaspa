"""Offline pilot failures and durable one-attempt behavior; no live funds."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import transfer_anchor_pilot as pilot
from transfer_lab import TransferError, demo

NODE = {'networkId': 'testnet-10', 'isSynced': True,
        'hasUtxoIndex': True, 'virtualDaaScore': 600000000}


def ident(n): return f'{n:064x}'


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name) / 'run'
        self.config = {'network': 'testnet-10',
            'funding': {'policy': {'owner': '22' * 32},
                        'source_outpoint': ident(800) + ':0', 'source_amount': 30_000_000},
            'nodes': ['wss://one.example/kaspa/testnet-10/wrpc/borsh',
                      'wss://two.example/kaspa/testnet-10/wrpc/borsh']}
        self.transcript = demo(); self.broadcasts = []
        owner = self
        class FakeNode:
            def __init__(self, endpoint): self.endpoint = endpoint
            def call(native, *args, **kwargs):
                if args[0] == 'anchor': return {'node': copy.deepcopy(NODE), 'anchor': ident(0)}
                if args[0] == 'broadcast':
                    journal = owner.journal()
                    owner.assertEqual(journal['status'], 'SUBMITTING')
                    owner.assertTrue((owner.directory / 'prepared.json').exists())
                    owner.broadcasts.append(args)
                    return 'Mempool accepted; not confirmation'
                if args[0] == 'scan':
                    prepared = json.loads((owner.directory / 'prepared.json').read_text())
                    tx = dict(prepared['transaction'], verboseData={'transactionId': prepared['id']})
                    return {'node': copy.deepcopy(NODE), 'from': args[1], 'target': ident(11),
                        'changes': {'removedChainBlockHashes': [],
                            'addedChainBlockHashes': [ident(n) for n in range(1, 12)],
                            'chainBlockAcceptedTransactions': [
                                {'chainBlockHeader': {'hash': ident(n)},
                                 'acceptedTransactions': [tx] if n == 1 else []}
                                for n in range(1, 12)]}}
                raise AssertionError(args)
        self.nodes = [FakeNode(s) for s in self.config['nodes']]

    def tearDown(self): self.tmp.cleanup()

    def journal(self): return json.loads((self.directory / 'journal.json').read_text())

    def prepare(self, plan_path, receipt_path):
        plan = json.loads(plan_path.read_text())
        tx = {'version': 1, 'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0,
              'payload': plan['payload'], 'inputs': [{'previousOutpoint':
                  {'transactionId': ident(800), 'index': 0}, 'sequence': 0}],
              'outputs': [{'value': plan['source_amount'] - pilot.FEE,
                           'scriptPublicKey': 'synthetic-script', 'covenant': None}]}
        receipt = {'status': 'PREPARED', 'network': 'testnet-10', 'id': ident(900),
            'node': NODE, 'plan': plan, 'fee': pilot.FEE, 'transaction': tx,
            'source': {'outpoint': {'transactionId': ident(800), 'index': 0},
                       'utxoEntry': {'amount': plan['source_amount'],
                         'scriptPublicKey': 'synthetic-script', 'isCoinbase': False, 'covenantId': None}}}
        pilot.durable(receipt_path, receipt, exclusive=True)
        return {'ignored': 'subprocess stdout is not authoritative'}

    def run_pilot(self, **kwargs):
        return pilot.run(self.directory, self.config, self.nodes, prepare=self.prepare,
                         transcript_factory=lambda: self.transcript, **kwargs)

    def test_both_nodes_require_exact_accepted_commitment_and_successors(self):
        result = self.run_pilot()
        self.assertEqual(result['status'], 'TWO_NODE_ANCHOR_OBSERVED')
        self.assertEqual(len(self.broadcasts), 1)
        self.assertEqual([s['selected_chain_successors'] for s in result['observations']], [10, 10])
        self.assertEqual(len(list(self.directory.glob('scan-*.json'))), 2)
        self.assertNotIn('secret', (self.directory / 'exchange.json').read_text())

    def test_existing_run_is_never_overwritten(self):
        self.run_pilot()
        original = (self.directory / 'journal.json').read_bytes()
        with self.assertRaises(FileExistsError): self.run_pilot()
        self.assertEqual((self.directory / 'journal.json').read_bytes(), original)
        self.assertEqual(len(self.broadcasts), 1)

    def test_preflight_failure_never_claims_signs_or_broadcasts(self):
        def fail(*args, **kwargs): raise TimeoutError('offline')
        self.nodes[1].call = fail
        with self.assertRaises(TimeoutError): self.run_pilot()
        self.assertEqual(self.journal()['status'], 'FAILED_PRE_SUBMISSION')
        self.assertFalse((self.directory / 'prepared.json').exists())
        self.assertFalse((self.directory.parent / 'transfer-anchor-claims').exists())
        self.assertEqual(self.broadcasts, [])

    def test_wrong_network_is_rejected_before_preparation(self):
        original = self.nodes[1].call
        def wrong(*args, **kwargs):
            value = original(*args, **kwargs); value['node']['networkId'] = 'mainnet'; return value
        self.nodes[1].call = wrong
        with self.assertRaises(Exception): self.run_pilot()
        self.assertFalse((self.directory / 'prepared.json').exists())
        self.assertEqual(self.broadcasts, [])

    def test_same_source_cannot_be_signed_in_another_run(self):
        self.run_pilot(); self.directory = self.directory.parent / 'another'
        with self.assertRaises(FileExistsError): self.run_pilot()
        self.assertFalse((self.directory / 'prepared.json').exists())
        self.assertEqual(len(self.broadcasts), 1)

    def test_unknown_broadcast_preserves_original_signed_bytes_without_retry(self):
        original = self.nodes[0].call
        def fail(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[0] == 'broadcast': raise TimeoutError('reply lost')
            return result
        self.nodes[0].call = fail
        with self.assertRaises(TimeoutError): self.run_pilot()
        self.assertEqual(self.journal()['status'], 'SUBMISSION_UNKNOWN')
        prepared = (self.directory / 'prepared.json').read_bytes()
        self.nodes[0].call = original
        result = pilot.observe(self.directory, self.nodes)
        self.assertEqual(result['status'], 'TWO_NODE_ANCHOR_OBSERVED')
        self.assertEqual(len(self.broadcasts), 1)
        self.assertEqual((self.directory / 'prepared.json').read_bytes(), prepared)

    def test_mempool_response_alone_does_not_finish_run(self):
        def timeout_observer(directory, nodes, **kwargs):
            return pilot.observe(directory, nodes, timeout=0, **kwargs)
        with self.assertRaises(TimeoutError): self.run_pilot(observer=timeout_observer)
        self.assertEqual(self.journal()['status'], 'OBSERVATION_INCOMPLETE')
        self.assertEqual(len(self.broadcasts), 1)

    def test_observation_rpc_failure_does_not_broadcast_again(self):
        def no_observe(directory, nodes, **kwargs): return self.journal()
        self.run_pilot(observer=no_observe)
        def fail(*args, **kwargs): raise TimeoutError('scan offline')
        self.nodes[1].call = fail
        with self.assertRaises(TimeoutError): pilot.observe(self.directory, self.nodes)
        self.assertEqual(self.journal()['status'], 'OBSERVATION_INCOMPLETE')
        self.assertEqual(len(self.broadcasts), 1)

    def test_tampered_prepared_fee_prevents_submission(self):
        prepare = self.prepare
        def wrong(plan_path, receipt_path):
            prepare(plan_path, receipt_path)
            value = json.loads(receipt_path.read_text()); value['transaction']['outputs'][0]['value'] -= 1
            pilot.durable(receipt_path, value)
        self.prepare = wrong
        with self.assertRaisesRegex(TransferError, 'fee'): self.run_pilot()
        self.assertEqual(self.broadcasts, [])
        self.assertEqual(self.journal()['status'], 'FAILED_PRE_SUBMISSION')

    def test_expired_exchange_prevents_submission(self):
        with self.assertRaisesRegex(TransferError, 'active'):
            self.run_pilot(clock=lambda: time.time() + 400)
        self.assertEqual(self.broadcasts, [])

    def test_recorded_endpoints_are_pinned_on_observation(self):
        self.run_pilot(); self.nodes[1].endpoint = self.config['nodes'][0]
        with self.assertRaisesRegex(TransferError, 'endpoints'): pilot.observe(self.directory, self.nodes)
        self.assertEqual(len(self.broadcasts), 1)

    def test_observed_output_mismatch_never_qualifies(self):
        original = self.nodes[1].call
        def wrong(*args, **kwargs):
            value = original(*args, **kwargs)
            if args[0] == 'scan':
                value['changes']['chainBlockAcceptedTransactions'][0]['acceptedTransactions'][0]['outputs'][0]['value'] -= 1
            return value
        self.nodes[1].call = wrong
        with self.assertRaisesRegex(TransferError, 'fee'): self.run_pilot()
        self.assertEqual(self.journal()['status'], 'OBSERVATION_INCOMPLETE')
        self.assertEqual(len(self.broadcasts), 1)

    def test_changed_exchange_cannot_be_reconciled_as_original(self):
        self.run_pilot()
        pilot.durable(self.directory / 'exchange.json', demo())
        with self.assertRaisesRegex(TransferError, 'commitment'): pilot.observe(self.directory, self.nodes)
        self.assertEqual(len(self.broadcasts), 1)

    def test_configuration_rejects_mainnet_same_host_and_oversized_source(self):
        cases = []
        wrong = copy.deepcopy(self.config); wrong['network'] = 'mainnet'; cases.append(wrong)
        wrong = copy.deepcopy(self.config); wrong['nodes'][1] = wrong['nodes'][0]; cases.append(wrong)
        wrong = copy.deepcopy(self.config); wrong['funding']['source_amount'] = 100000001; cases.append(wrong)
        wrong = copy.deepcopy(self.config); wrong['funding']['source_outpoint'] += '0'; cases.append(wrong)
        wrong = copy.deepcopy(self.config); wrong['nodes'][1] += '?token=secret'; cases.append(wrong)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(TransferError): pilot.validate_config(value)

    def test_read_calls_strip_signer_and_preparation_keeps_it_off_arguments(self):
        from types import SimpleNamespace
        node = pilot.Node(self.config['nodes'][0])
        with patch.dict('os.environ', {'ICP_SIGNER_KEY_FILE': '/private/role.json'}):
            process = SimpleNamespace(returncode=0, communicate=lambda **kwargs: ('{}', ''))
            with patch.object(pilot.subprocess, 'Popen', return_value=process) as call:
                node.call('anchor')
                self.assertNotIn('ICP_SIGNER_KEY_FILE', call.call_args.kwargs['env'])
                node.prepare('plan.json', 'prepared.json')
                self.assertEqual(call.call_args.kwargs['env']['ICP_SIGNER_KEY_FILE'], '/private/role.json')
                self.assertNotIn('/private/role.json', call.call_args.args[0])

    def test_timeout_stops_relay_and_native_process_group(self):
        from unittest.mock import Mock
        process = Mock(pid=12345)
        process.communicate.side_effect = [pilot.subprocess.TimeoutExpired('synthetic', 50), ('', '')]
        with patch.object(pilot.subprocess, 'Popen', return_value=process):
            with patch.object(pilot.os, 'killpg') as kill:
                with self.assertRaises(pilot.subprocess.TimeoutExpired):
                    pilot.Node(self.config['nodes'][0]).call('anchor')
                kill.assert_called_once_with(12345, pilot.signal.SIGKILL)


if __name__ == '__main__': unittest.main()
