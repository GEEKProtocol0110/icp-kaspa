"""Native read-only snapshot envelope checks; no signer or real network."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_ticket_observer as o


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.r=o.Reader('wss://a.invalid/kaspa/testnet-10/wrpc/borsh')
        self.f,self.t='22'*32,'33'*32
        node=o.fixture_scan(0)['node']
        def sample(key):return dict(node=deepcopy(node),publicKey=key,**{'from':o.fake_id(0)},target=o.fake_id(3),utxos=[])
        self.value=dict(mode='TN10_P0_READ_SNAPSHOT_V1',source=sample(self.f),ticket=sample(self.t),scan=o.fixture_scan(0,[1,2,3]))

    def snapshot(self,value):
        with patch.object(self.r,'_run',return_value=value) as run:
            v=self.r.snapshot_p0(o.fake_id(0),self.f,self.t)
        self.assertEqual(run.call_args.args[0],['observe-p0'])
        self.assertEqual(o.decode(run.call_args.args[1]),dict(cursor=o.fake_id(0),funding_key=self.f,ticket_key=self.t))
        self.assertTrue(run.call_args.kwargs['network'])
        return v

    def test_one_canonical_public_request_returns_shared_brackets(self):
        self.assertEqual(self.snapshot(self.value),self.value)

    def test_wrong_role_cursor_target_bracket_or_node_is_rejected(self):
        for part,field,bad in (('source','publicKey',self.t),('ticket','publicKey',self.f),
                ('scan','from',o.fake_id(9)),('scan','target',o.fake_id(9)),
                ('ticket','from',o.fake_id(9)),('ticket','target',o.fake_id(9)),
                ('ticket','node',{})):
            v=deepcopy(self.value);v[part][field]=bad
            with self.subTest(part=part,field=field),self.assertRaises(o.ObservationError):self.snapshot(v)

    def test_closed_profile_and_health_are_required(self):
        for mutate in (lambda v:v.update(mode='old-profile'),lambda v:v.update(extra=1),lambda v:v.pop('source'),
                       lambda v:v['scan']['node'].update(networkId='mainnet')):
            v=deepcopy(self.value);mutate(v)
            with self.assertRaises(o.ObservationError):self.snapshot(v)

    def test_alias_is_rejected_before_process(self):
        with patch.object(self.r,'_run') as run:
            with self.assertRaises(o.ObservationError):self.r.snapshot_p0(o.fake_id(0),self.f,self.f)
        run.assert_not_called()

    def bootstrap(self):
        return dict(mode='TN10_P0_BOOTSTRAP_CANDIDATE_V1',node=o.fixture_scan(0)['node'],
            bootstrap=o.fake_id(1),sampled_sink=o.fake_id(21),parent_steps=20,
            scope='TRUSTED_NODE_CANDIDATE_NOT_FINALITY')

    def test_bootstrap_is_only_a_pinned_node_candidate(self):
        value=self.bootstrap()
        with patch.object(self.r,'_run',return_value=value) as run:self.assertEqual(self.r.bootstrap_p0(),value)
        run.assert_called_once_with(['bootstrap-p0'],network=True)

    def test_bad_bootstrap_depth_identity_or_health_fails(self):
        for key,bad in (('parent_steps',True),('parent_steps',0),('bootstrap',o.fake_id(21)),
                        ('bootstrap','bad'),('mode','old'),('scope','final')):
            value=self.bootstrap();value[key]=bad
            with patch.object(self.r,'_run',return_value=value),self.assertRaises(o.ObservationError):self.r.bootstrap_p0()
        value=self.bootstrap();value['node']['isSynced']=False
        with patch.object(self.r,'_run',return_value=value),self.assertRaises(o.ObservationError):self.r.bootstrap_p0()

    def test_private_or_ambiguous_native_request_fails_before_network(self):
        req=dict(cursor=o.fake_id(0),funding_key=self.f,ticket_key=self.t)
        raw=o.canonical(req)
        for value in (b' '+raw,raw.replace(b'"cursor":',b'"cursor":"duplicate","cursor":',1),
                      o.canonical(dict(req,secret_key='PRIVATE_SENTINEL')),b'x'*1025):
            result=subprocess.run([str(self.r.binary),'observe-p0'],input=value,capture_output=True,
                                  env={'PATH':'/usr/bin:/bin'},timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn(b'PRIVATE_SENTINEL',result.stdout+result.stderr)


if __name__=='__main__':unittest.main()
