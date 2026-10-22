"""Relay failures close both peers and cancel the opposite direction."""
import asyncio
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from with_proxy import bridge


class Peer:
    def __init__(self,items=(),error=None):
        self.items=iter(items);self.error=error;self.sent=[];self.closed=False;self.cancelled=False
    def __aiter__(self):return self
    async def __anext__(self):
        try:return next(self.items)
        except StopIteration:
            if self.error:raise self.error
            try:await asyncio.Future()
            except asyncio.CancelledError:self.cancelled=True;raise
    async def send(self,value):self.sent.append(value)
    async def close(self,**kwargs):self.closed=True;self.close_info=kwargs


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_upstream_failure_is_retrieved_and_closes_both_peers(self):
        local=Peer();remote=Peer([b'reply'],RuntimeError('private remote details'))
        with self.assertRaises(RuntimeError):await asyncio.wait_for(bridge(local,remote),1)
        self.assertEqual(local.sent,[b'reply']);self.assertTrue(local.cancelled)
        self.assertTrue(local.closed and remote.closed)
        self.assertEqual(local.close_info,dict(code=1011,reason='RPC relay failed'))

    async def test_downstream_failure_stops_upstream_direction(self):
        local=Peer([b'request'],ValueError());remote=Peer()
        with self.assertRaises(ValueError):await asyncio.wait_for(bridge(local,remote),1)
        self.assertEqual(remote.sent,[b'request']);self.assertTrue(remote.cancelled)
        self.assertTrue(local.closed and remote.closed)

    async def test_cancellation_closes_peers_without_retry(self):
        local,remote=Peer(),Peer();task=asyncio.create_task(bridge(local,remote))
        await asyncio.sleep(0);task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertTrue(local.closed and remote.closed)

    async def test_hung_peer_close_is_bounded(self):
        class SlowPeer(Peer):
            async def close(self,**kwargs):await asyncio.Future()
        local=SlowPeer();remote=Peer(error=RuntimeError())
        with self.assertRaises(TimeoutError):await asyncio.wait_for(bridge(local,remote),3)
        self.assertTrue(local.cancelled)


if __name__=='__main__':unittest.main()
