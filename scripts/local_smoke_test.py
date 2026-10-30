#!/usr/bin/env python3
import asyncio
import json
import subprocess
import sys
import os
import time

async def main():
    url = os.environ.get('SMOKE_WS', 'ws://localhost:9000/ws/packets')
    print('Connecting to', url)
    try:
        import websockets
    except Exception as e:
        print('websockets not installed:', e)
        return 2

    try:
        async with websockets.connect(url, open_timeout=5) as ws:
            # authenticate first: an access token or the API key; empty works only
            # on localhost while no console users exist (development mode)
            token = os.environ.get('SMOKE_TOKEN') or os.environ.get('DASHBOARD_API_KEY') or ''
            await ws.send(json.dumps({'type': 'auth', 'token': token}))
            print('WS connected, triggering integration test')
            proc = subprocess.Popen([sys.executable, 'scripts/integration_test.py'], cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
            try:
                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=12)
                    if json.loads(msg).get('type') != 'auth_ok':
                        break
                print('Received message:', msg)
                proc.wait(timeout=5)
                print('SMOKE TEST: PASS')
                return 0
            except asyncio.TimeoutError:
                print('SMOKE TEST: FAIL - no message within timeout')
                try:
                    proc.kill()
                except Exception:
                    pass
                return 1
    except Exception as e:
        print('Failed to connect to websocket:', e)
        return 3

if __name__ == '__main__':
    code = asyncio.run(main())
    sys.exit(code)
