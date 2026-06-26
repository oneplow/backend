# easy-ai

A zero-cost AI relay. Disposable accounts on `use.ai` (no email verification)
each give one free prompt; we harvest them in bulk, bank the token + session,
and relay prompts through the API.

```
                       ┌── prewarmer (background) ──┐
                       │  signup → token + session  │
                       ▼                            ▼
API client ─► backend ─► ACCOUNT BANK ─► worker ─► use.ai
                │            (sqlite)      │           │
                └◄────────── reply ────────┘◄── HTTP / scrape
                │
          context store
```

## The three paths (fastest first)
1. **DIRECT** — claim a banked token, replay use.ai's own completion endpoint
   over HTTP. *No browser in the hot path.* Enable via `DIRECT_API_*` in config.
2. **WARM** — claim a banked session, load it into a browser, skip signup.
3. **COLD** — full inline signup → prompt → scrape. The original fallback.

Signup is pulled out of the hot path by the **prewarmer**, which keeps the bank
stocked with `BANK_MIN_FRESH` ready accounts.

## Layout
```
easy-ai/
  worker/
    config.py     # ALL knobs: selectors, auth/token, direct-API, bank (edit me)
    email_gen.py  # throwaway format-valid emails
    easy_ai.py    # run_prompt(): DIRECT / WARM / COLD path selection
    bank.py       # sqlite pool of harvested accounts (atomic claim)
    harvester.py  # background signup -> bank token + session
    direct.py     # HTTP fast path against use.ai's own endpoint
    spike.py      # phase-1: run / --sniff / --harvest
  backend/
    context.py    # per-session history + prompt stuffing
    pool.py       # caps concurrent browsers
    main.py       # FastAPI: /chat, /v1/chat, /v1/chat/completions, /bank, /health
  bank/           # created at runtime: accounts.db + states/
```

## Setup
```bash
cd easy-ai
python -m venv .venv && source .venv/bin/activate   # win: .venv\Scripts\activate
pip install -r requirements.txt
```

## Phase 1 — make it real (do this first)
Selectors ship as placeholders. Run the spike headed and fill in the real CSS
selectors in `worker/config.py`:
```bash
python -m worker.spike "say hi in one sentence"
```

Then unlock the fast paths by mapping use.ai's own API:
```bash
python -m worker.spike --sniff "say hi"
```
This prints every xhr/fetch the site makes (find the **completion endpoint** →
`DIRECT_API_URL`, match the request body → `DIRECT_API_BODY`) and dumps the
**localStorage keys** (find the one holding the token → `AUTH_TOKEN_KEY`).

Bank a few accounts to confirm harvesting works:
```bash
python -m worker.spike --harvest 5
```

## Run the backend
```bash
uvicorn backend.main:app --reload --port 8000   # → http://localhost:8000
```

### Windows quick start

```powershell
Set-Location C:\path\to\easy-ai
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

If PowerShell blocks the activate script, run this once first:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

The prewarmer starts topping up the bank automatically. Watch it:
```bash
curl localhost:8000/bank        # {"fresh": N, "stats": {...}}
```

## OpenAI-compatible API
Point any OpenAI client at your box — context is the caller's problem:
```bash
curl -X POST localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"default","messages":[{"role":"user","content":"hello"}],"stream":false}'
```
```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8000/v1", api_key="unused")
print(client.chat.completions.create(
    model="default",
    messages=[{"role": "user", "content": "hello"}],
).choices[0].message.content)
```

## Free proxies (no paid account)
**Option A — Tor (free rotation, pre-wired for this machine):**
1. From the `easy-ai\` folder, double-click **`start_tor.bat`** (or run it in a
   terminal). It launches the `tor.exe` bundled in your Tor Browser as a plain
   proxy — SOCKS 9050, control 9051, cookie auth — no browser needed. Wait for
   `Bootstrapped 100% (done)` and leave that window open.
2. That's it — `config.py` already has `PROXY_TOR = True`. The harvester pulls a
   fresh exit IP before each signup (spaced by `TOR_NEWNYM_DELAY`).

   > Run `start_tor.bat` and `uvicorn` both from `easy-ai\` so the auth cookie in
   > `tor_data\` is found. Some sites block known Tor exit IPs — if use.ai does,
   > switch to option B.

**Option B — free public proxy lists (validated):**
```bash
python -m worker.proxy_sources          # fetch thousands, test them, keep the live ones
```
It writes the working proxies to `proxies.txt`. Then set `PROXY_FILE = "proxies.txt"`
in `config.py`. Free proxies die fast — re-run this periodically (e.g. cron).

> Heads up: free public proxies are slower and less trustworthy than residential
> ones. Fine for low-stakes signup farming; don't push anything sensitive through them.

## Docker
```bash
docker build -t easy-ai .
docker run -p 8000:8000 easy-ai
```

## Gotchas
- **Selectors drift** — all in `config.py`, one-edit fixes.
- **Per-prompt length cap** — `MAX_HISTORY_CHARS` rolls the context window; swap
  in a summarizer for longer memory.
- **Rate / IP** — handled: add proxies to `config.PROXIES` (or `PROXY_FILE`) and
  every signup rotates through a different IP. Each banked account remembers its
  birth-IP and reuses it when its message is spent. Empty list = direct IP.
- **Browser weight** — `MAX_CONCURRENT_BROWSERS` caps live Chromiums; the DIRECT
  path sidesteps this entirely once it's wired.
- **Token expiry** — banked tokens may go stale. The WARM/COLD fallback covers a
  dead token; `mark_dead` retires it.
