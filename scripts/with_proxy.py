#!/usr/bin/env python3
"""Run the native CLI/pilot through the environment's normal WebSocket proxy.

Optional dependency: websockets==16.0. No private keys are accessed here.
Uses the official SDK resolver's TLS endpoint for testnet-10 only.
"""
import asyncio
import json
import os
from pathlib import Path
import sys
import urllib.request
import websockets

ROOT = Path(__file__).resolve().parents[1]

async def bridge(local, remote):
    """Close both peers on either-direction failure; never strand the native RPC."""
    async def pipe(source, target):
        async for message in source:
            await target.send(message)
    tasks = [asyncio.create_task(pipe(local,remote)), asyncio.create_task(pipe(remote,local))]
    normal = False
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            # Retrieve exceptions so a relay error cannot look like a normal EOF.
            task.result()
        normal = True
    finally:
        for task in tasks:
            if not task.done(): task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        code = 1000 if normal else 1011
        reason = '' if normal else 'RPC relay failed'
        await asyncio.wait_for(asyncio.gather(local.close(code=code,reason=reason),
            remote.close(code=code,reason=reason),return_exceptions=True),timeout=2)

def resolve():
    configured = os.environ.get('ICP_UPSTREAM_URL')
    if configured:
        if not configured.startswith('wss://') or '/kaspa/testnet-10/wrpc/borsh' not in configured:
            raise ValueError('ICP_UPSTREAM_URL must be a TN10 TLS Borsh endpoint')
        return configured
    errors = []
    for host in ('eric.kaspa.stream', 'john.kaspa.red'):
        try:
            url = f'https://{host}/v2/kaspa/testnet-10/tls/wrpc/borsh'
            with urllib.request.urlopen(url, timeout=12) as response:
                node = json.load(response)['url']
            if not node.startswith('wss://') or '/kaspa/testnet-10/wrpc/borsh' not in node:
                raise ValueError('Resolver returned an unexpected endpoint')
            return node
        except Exception as error:
            errors.append(str(error))
    raise RuntimeError('TN10 TLS resolver failed: ' + '; '.join(errors))

async def run(command):
    upstream = await asyncio.to_thread(resolve)
    async def handler(local):
        try:
            async with websockets.connect(upstream, open_timeout=12, max_size=8*1024*1024) as remote:
                await bridge(local, remote)
        except Exception as error:
            print(f'RPC relay failed: {type(error).__name__}', file=sys.stderr, flush=True)
            try: await asyncio.wait_for(local.close(code=1011, reason='RPC relay failed'),timeout=2)
            except Exception: pass
    async with websockets.serve(handler,'127.0.0.1',0) as server:
        port=server.sockets[0].getsockname()[1]
        env=os.environ.copy()
        env['ICP_RPC_URL']=f'ws://127.0.0.1:{port}'
        process=await asyncio.create_subprocess_exec(*command,cwd=ROOT,env=env)
        return await process.wait()

if __name__=='__main__':
    if len(sys.argv)<2:
        raise SystemExit('Usage: python3 scripts/with_proxy.py bin/icp status | python3 scripts/pilot.py')
    raise SystemExit(asyncio.run(run(sys.argv[1:])))
