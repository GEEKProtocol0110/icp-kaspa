"""Unsigned native P0 previews and public checksum receipts, not live evidence."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import ticket_pilot_review as p
from native_ticket_observer import Reader


class PilotReviewTests(unittest.TestCase):
    def setUp(self):
        self.r=p.Reviewer();self.plan=p.fixture_plan()
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)

    def tearDown(self):self.tmp.cleanup()

    def test_demo_labels_every_result_as_unsigned_fixture(self):
        d=p.demo();self.assertEqual(d['operational_keys_created'],0)
        self.assertEqual((d['real_rpc_calls'],d['broadcasts']),(0,0))
        self.assertIn('NEVER_FUND',d['mode']);self.assertEqual(d['record']['review']['mode'],p.MODE)
        self.assertFalse(d['record']['review']['source_observed']);self.assertFalse(d['record']['review']['vm_verified'])

    def test_native_projection_recomputes_all_three_unsigned_ids(self):
        review=self.r.native(self.plan);reader=Reader();txs=review['transactions']
        for index,t in enumerate(txs):
            rpc=deepcopy(t['unsigned_rpc']);rpc['verboseData']={'transactionId':t['transaction_id']}
            projected=reader.project(rpc)
            self.assertEqual(projected['transaction_id'],t['transaction_id'])
            self.assertEqual(rpc['inputs'][0]['signatureScript'],'')
            self.assertEqual(len(projected['outputs']),2 if index==0 else 1)
            if index:self.assertEqual(projected['inputs'][0]['transaction_id'],txs[0]['transaction_id'])
        self.assertNotEqual(txs[1]['transaction_id'],txs[2]['transaction_id'])

    def test_fee_amounts_change_and_scripts_are_exact(self):
        v=self.r.native(self.plan);self.assertEqual(v['maximum_lifecycle_fee'],4_000_000)
        txs=v['transactions'];self.assertTrue(all(t['fee']==2_000_000 for t in txs))
        self.assertEqual([o['value'] for o in txs[0]['unsigned_rpc']['outputs']],[12_000_000,10_000_000])
        for t in txs[1:]:self.assertEqual([o['value'] for o in t['unsigned_rpc']['outputs']],[10_000_000])
        self.assertTrue(all(a.startswith('kaspatest:') for a in v['roles'].values()))

    def test_known_fixture_cannot_be_relabelled_operator_review(self):
        self.plan['purpose']='operator-unsigned-review'
        with self.assertRaises(p.ReviewError):self.r.make(self.plan)

    def test_unknown_fields_and_private_key_fields_are_rejected_before_save(self):
        for key in ('extra','private_key','seed_phrase','grant','approval'):
            plan=deepcopy(self.plan);plan[key]='not-accepted'
            with self.assertRaises(p.ReviewError):self.r.save(self.root/'receipt.json',plan)
            self.assertFalse((self.root/'receipt.json').exists())

    def test_bool_float_negative_and_oversized_integer_amounts_fail(self):
        for amount in (True,24_000_000.0,-1,2**64,23_999_999,100_000_001):
            plan=deepcopy(self.plan);plan['source']['amount']=amount
            with self.assertRaises(p.ReviewError):self.r.make(plan)

    def test_network_namespace_key_alias_and_bad_curve_key_fail(self):
        for key,value in [('network','mainnet'),('namespace','icp-native-ticket-n0'),
                          ('ticket_key',self.plan['funding_key']),('return_key','00'*32)]:
            plan=deepcopy(self.plan);plan[key]=value
            with self.assertRaises(p.ReviewError):self.r.make(plan)

    def test_payloads_use_distinct_p0_domains(self):
        result=self.r.native(self.plan)
        for t in result['transactions']:
            raw=bytes.fromhex(t['unsigned_rpc']['payload'])
            self.assertTrue(raw.startswith(('ICP-RT-'+t['action'].upper()+'-TN10-P0\0').encode()))
            self.assertNotIn(b'TN10-N0\0',raw);self.assertNotIn(b'TN10-LAB0\0',raw)

    def test_evidence_change_updates_every_native_id(self):
        original=self.r.make(self.plan);self.plan['evidence_digest']='88'*32;changed=self.r.make(self.plan)
        self.assertNotEqual(original['receipt_hash'],changed['receipt_hash'])
        for a,b in zip(original['review']['transactions'],changed['review']['transactions']):
            self.assertNotEqual(a['transaction_id'],b['transaction_id'])

    def test_receipt_roundtrip_and_exclusive_creation(self):
        path=self.root/'review.json';record=self.r.save(path,self.plan)
        self.assertEqual(self.r.verify(p.load(path)),record['review'])
        before=path.read_bytes()
        with self.assertRaises(FileExistsError):self.r.save(path,self.plan)
        self.assertEqual(path.read_bytes(),before)

    def test_recomputed_checksum_does_not_hide_mutated_native_result(self):
        record=self.r.make(self.plan);record['review']['transactions'][0]['unsigned_rpc']['outputs'][0]['value']-=1
        record['receipt_hash']=p.checksum({k:record[k] for k in ('plan','review')})
        with self.assertRaises(p.ReviewError):self.r.verify(record)

    def test_checksum_is_not_an_authorization_signature(self):
        first=self.r.make(self.plan);self.plan['evidence_digest']='99'*32;second=self.r.make(self.plan)
        self.r.verify(first);self.r.verify(second)
        self.assertNotEqual(first['receipt_hash'],second['receipt_hash'])
        self.assertFalse(first['review']['vm_verified']);self.assertFalse(second['review']['vm_verified'])

    def test_missing_unknown_and_changed_receipt_fields_fail(self):
        record=self.r.make(self.plan)
        for key in ('plan','review','receipt_hash'):
            broken=deepcopy(record);del broken[key]
            with self.assertRaises(p.ReviewError):self.r.verify(broken)
        broken=deepcopy(record);broken['extra']=0
        with self.assertRaises(p.ReviewError):self.r.verify(broken)
        record['receipt_hash']='00'*32
        with self.assertRaises(p.ReviewError):self.r.verify(record)

    def test_duplicate_json_and_size_limits_fail(self):
        path=self.root/'plan.json';path.write_text('{"network":"testnet-10","network":"mainnet"}')
        with self.assertRaises(ValueError):p.load(path)
        path.write_bytes(b' '*16385)
        with self.assertRaises(p.ReviewError):p.load(path,16384)
        plan=deepcopy(self.plan);plan['extra']='x'*16385
        with self.assertRaises(p.ReviewError):self.r.make(plan)

    def test_pinned_binary_change_is_refused(self):
        path=self.root/'reviewer';shutil.copy2(self.r.binary,path);r=p.Reviewer(path)
        with path.open('ab') as f:f.write(b'changed')
        with self.assertRaises(p.ReviewError):r.make(self.plan)

    def test_native_binary_exposes_no_effect_command(self):
        for command in ('prepare','sign','submit','broadcast','keygen'):
            result=subprocess.run([str(self.r.binary),command],input=p.canonical(self.plan),capture_output=True)
            self.assertNotEqual(result.returncode,0)

    def test_native_input_encoding_is_canonical(self):
        raw=p.canonical(self.plan)
        for bad in (b' '+raw,raw.replace(b'{',b'{"extra":0,',1),raw.replace(b'24000000',b'24000000.0')):
            r=subprocess.run([str(self.r.binary)],input=bad,capture_output=True)
            self.assertNotEqual(r.returncode,0)

    def test_operator_review_with_ephemeral_test_public_keys_stays_unsigned(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        plan=deepcopy(self.plan);plan['purpose']='operator-unsigned-review'
        plan['run_nonce']='55'*32;plan['source']['transaction_id']='22'*32
        for role in ('funding_key','ticket_key','return_key'):
            plan[role]=ec.generate_private_key(ec.SECP256K1()).public_key().public_numbers().x.to_bytes(32,'big').hex()
        record=self.r.make(plan);self.assertEqual(self.r.verify(record)['purpose'],'operator-unsigned-review')
        self.assertFalse(record['review']['source_observed']);self.assertEqual(record['review']['signatures_created'],0)
