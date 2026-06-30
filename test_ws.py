import asyncio
import json
from worker.session_http import create_account
from worker.direct import _stream_gen, _to_parts

async def test():
    acct = await create_account()
    print("Created:", acct["email"])
    parts = _to_parts([{"role": "user", "content": "Say hello"}])
    try:
        async for chunk in _stream_gen(acct, "claude-opus-4-8", parts):
            print("CHUNK:", chunk)
    except Exception as e:
        print("ERROR:", repr(e))

if __name__ == "__main__":
    asyncio.run(test())
