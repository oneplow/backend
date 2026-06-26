"""
Phase-1 tooling. Run from the easy-ai/ root.

  python -m worker.spike "prompt"            full flow, headed, prints reply
  python -m worker.spike --sniff "prompt"    same, but logs every xhr/fetch +
                                             dumps localStorage  -> use this to
                                             find DIRECT_API_URL + AUTH_TOKEN_KEY
  python -m worker.spike --harvest 5         sign up + bank 5 accounts
"""
import asyncio
import logging
import sys

from . import config

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


async def _run(prompt: str):
    from .easy_ai import run_prompt
    config.HEADLESS = False
    print(f"\n--- spiking {config.TARGET_URL} ---")
    reply = await run_prompt(model="default", prompt=prompt)
    print("\n=== REPLY ===\n" + reply + "\n=============")


async def _sniff(prompt: str):
    """Walk the cold flow with network logging so you can map the real API."""
    from .easy_ai import async_playwright, _new_context, _switch_model, _signup, _ask
    config.HEADLESS = False

    def on_req(r):
        if r.resource_type in ("xhr", "fetch"):
            print(f">> {r.method} {r.url}")

    def on_resp(r):
        if r.request.resource_type in ("xhr", "fetch"):
            print(f"<< {r.status} {r.url}")

    async with async_playwright() as p:
        browser, ctx = await _new_context(p)
        try:
            page = await ctx.new_page()
            page.on("request", on_req)
            page.on("response", on_resp)
            await page.goto(config.TARGET_URL, wait_until="domcontentloaded")
            await _switch_model(page, "default")
            await _signup(page)
            reply = await _ask(page, prompt)
            ls = await page.evaluate("() => JSON.stringify(Object.keys(localStorage))")
            print("\n--- localStorage keys (token lives in one of these) ---")
            print(ls)
            print("\n=== REPLY ===\n" + reply + "\n=============")
        finally:
            await ctx.close()
            await browser.close()


async def _harvest(n: int):
    from .harvester import harvest_one
    from . import bank
    config.HEADLESS = True
    ok = 0
    for i in range(n):
        if await harvest_one():
            ok += 1
        print(f"  harvested {ok}/{i + 1}  (bank fresh={bank.count_fresh()})")
    print(f"\ndone: banked {ok}/{n} accounts")


def main():
    args = sys.argv[1:]
    if args and args[0] == "--sniff":
        prompt = args[1] if len(args) > 1 else "Say hello in one short sentence."
        asyncio.run(_sniff(prompt))
    elif args and args[0] == "--harvest":
        n = int(args[1]) if len(args) > 1 else 5
        asyncio.run(_harvest(n))
    else:
        prompt = args[0] if args else "Say hello in one short sentence."
        asyncio.run(_run(prompt))


if __name__ == "__main__":
    main()
