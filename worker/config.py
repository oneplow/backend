"""
Central config for the easy-ai worker.

EVERYTHING site-specific lives here. When use.ai changes its UI, you fix it
in ONE place. The two things you MUST verify against the live site:
  1. The SELECTORS dict  -> open the site, inspect, paste real CSS selectors.
  2. The cloakbrowser launch call in easy_ai.py (_new_context).
"""

import os

TARGET_URL = "https://use.ai"

# ---- Local API auth ----------------------------------------------------------
# Set env var ADMIN_KEY to protect the /admin/keys endpoints.
# Client API keys are generated dynamically and stored in auth.db.
# If ADMIN_KEY is empty, the admin endpoints are disabled.
ADMIN_KEY = os.environ.get("ADMIN_KEY", "").strip()
AUTH_DB_PATH = "bank/auth.db"

# ---- Browser behavior -------------------------------------------------------
HEADLESS = True              # spike.py flips this to False so you can watch
HUMANIZE = True              # cloakbrowser human-like mouse/keyboard/scroll
GUEST_MODE = False
NAV_TIMEOUT_MS = 30_000
ACTION_TIMEOUT_MS = 15_000
RESPONSE_TIMEOUT_MS = 90_000  # how long to wait for the AI reply

# ---- Concurrency ------------------------------------------------------------
# Each browser is a full Chromium. Keep this modest or you'll OOM the box.
MAX_CONCURRENT_BROWSERS = 4

# ---- Email / password generation (must satisfy the site's email regex) ------
EMAIL_LOCAL_MIN = 20
EMAIL_LOCAL_MAX = 20
EMAIL_DOMAIN_MIN = 5
EMAIL_DOMAIN_MAX = 9
EMAIL_TLDS = ["com", "net", "org", "io", "co", "xyz"]
PASSWORD_LENGTH = 16
SIGNUP_MAX_RETRIES = 5        # reroll the email if "already in use"

# ---- Models -----------------------------------------------------------------
# The full use.ai catalog, verified live 2026-06-17. Each entry: the slug used in
# the WS frame (selectedModel = "gateway-<slug>") + a human label for the UI.
# MODELS drives the dropdown; MODEL_ALIASES keeps short OpenAI-ish names working
# on the API. resolve_model() maps either a slug or an alias -> a real slug.
DEFAULT_MODEL = "gpt-5-4"

MODELS = [
    # OpenAI
    {"slug": "gpt-5-5",                   "label": "OpenAI GPT-5.5"},
    {"slug": "gpt-5-4",                   "label": "OpenAI GPT-5.4"},
    {"slug": "gpt-5-3",                   "label": "OpenAI GPT-5.3"},
    {"slug": "gpt-5-1",                   "label": "OpenAI GPT-5.1"},
    {"slug": "gpt-5",                     "label": "OpenAI GPT-5"},
    {"slug": "gpt-5-mini",               "label": "OpenAI GPT-5 Mini"},
    {"slug": "gpt-4o",                    "label": "OpenAI GPT-4o"},
    {"slug": "gpt-4o-mini",              "label": "OpenAI GPT-4o Mini"},
    # Anthropic
    {"slug": "claude-opus-4-8",          "label": "Claude Opus 4.8"},
    {"slug": "claude-opus-4-7",          "label": "Claude Opus 4.7"},
    {"slug": "claude-opus-4-6",          "label": "Claude Opus 4.6"},
    {"slug": "claude-opus-4-5",          "label": "Claude Opus 4.5"},
    {"slug": "claude-opus-4-1",          "label": "Claude Opus 4.1"},
    {"slug": "claude-sonnet-4-6",        "label": "Claude Sonnet 4.6"},
    # Google
    {"slug": "gemini-3-1-pro",           "label": "Gemini 3.1 Pro"},
    {"slug": "gemini-3-pro",             "label": "Gemini 3 Pro"},
    {"slug": "gemini-3-flash",           "label": "Gemini 3 Flash"},
    {"slug": "gemini-2.5-flash",         "label": "Gemini 2.5 Flash"},
    # DeepSeek
    {"slug": "deepseek-v4-pro",          "label": "DeepSeek V4 Pro"},
    {"slug": "deepseek-v4-flash",        "label": "DeepSeek V4 Flash"},
    {"slug": "deepseek-r1",              "label": "DeepSeek R1"},
    # Others
    {"slug": "grok-4",                   "label": "Grok 4"},
    {"slug": "qwen-3-max",               "label": "Qwen 3 Max"},
    {"slug": "qwen-3-5-397b",            "label": "Qwen 3.5"},
    {"slug": "kimi-k2-6",                "label": "Kimi K2.6"},
    {"slug": "deepinfra-kimi-k2",        "label": "Kimi K2"},
    {"slug": "llama-3-3-70b-versatile",  "label": "Llama 3.3"},
]

# Short names that still resolve (back-compat + convenience on the API).
MODEL_ALIASES = {
    "default": "gpt-5-4",
    "fast":    "gpt-5-mini",
    "smart":   "claude-opus-4-8",
}

_MODEL_SLUGS = {m["slug"] for m in MODELS}


def resolve_model(name: str) -> str:
    """Map a UI/API model name (slug OR alias) to a real use.ai slug."""
    if not name:
        return DEFAULT_MODEL
    if name in _MODEL_SLUGS:
        return name
    if name in MODEL_ALIASES:
        return MODEL_ALIASES[name]
    return DEFAULT_MODEL


# Back-compat: some older code/tests still read MODEL_MAP[...] directly.
MODEL_MAP = {**MODEL_ALIASES, **{m["slug"]: m["slug"] for m in MODELS}}

# ---- SELECTORS: VERIFIED LIVE 2026-06-17 ------------------------------------
# use.ai is a Next.js/radix app. Radix auto-ids (radix-_r_xx_) change per render,
# so every selector below uses the site's stable data-testid hooks instead.
# Leave a value as "REPLACE_ME" and the worker will skip/relax that step.
SELECTORS = {
    # model switch (works pre-signup)
    "model_dropdown":    '[data-testid="model-selector"]',
    "model_option":      '[data-testid="model-option-gateway-%s"]',  # %s = MODEL_MAP slug
    # auth (PASSWORDLESS, two-step: open modal -> reveal email field -> submit)
    "signup_button":     '[data-testid="header-sign-in-button"]',     # opens auth modal
    "email_reveal":      '[data-testid="signin-with-email-button"]',  # "continue with email" -> shows the field
    "email_input":       '[data-testid="email-input"]',
    "password_input":    "REPLACE_ME",   # NO password field exists (SSO / email-OTP) -> skipped
    "signup_submit":     '[data-testid="signin-with-email-button"]',  # same button submits the email
    "email_taken_error": "REPLACE_ME",   # N/A: email is OTP login, no "already in use" path -> skipped
    # chat
    "prompt_input":      '[data-testid="chat-input-textarea"]',
    "prompt_submit":     '[data-testid="send-button"]',
    "response_block":    '[data-testid="message-assistant"]',  # text inside: [data-testid="message-content"]
    "response_done":     '[data-testid="message-upvote"]',     # vote btns render only when the stream ends
}

# ---- Auth harvesting --------------------------------------------------------
# VERIFIED 2026-06-17: signup is instant + passwordless + NO email verification
# (fake email accepted; emailVerified stays null). It mints a real better-auth
# session. The token lives in an httpOnly cookie:
#   __Secure-better-auth.session_token   (value e.g. "Km5wpqjm5OnyOMZPgYQh3BJanHRzxwqi")
# (a companion cookie __Secure-better-auth.session_data is a JWT carrying an
#  embedded accessToken + planType). GET api.use.ai/v1/auth/get-session echoes it.
# The free cap is PER-ACCOUNT (1 message each), NOT per-IP -> harvest many.
AUTH_TOKEN_STORAGE = "cookie"     # "local" (localStorage), "cookie", or "none"
AUTH_TOKEN_KEY = "__Secure-better-auth.session_token"   # cookie name holding the token

# ---- Headless WS path (PRIMARY, no browser) ---------------------------------
# VERIFIED working: signup over HTTP -> open the budget-agent WebSocket -> stream
# the reply. No Chromium, no proxies. This is the default hot path now.
DIRECT_WS_ENABLED = True
AUTH_BASE     = "https://api.use.ai/v1/auth"          # email-login / sign-in/credentials / get-session
WS_AGENT_BASE = "wss://agents.use.ai/agents/budget-agent"
MODEL_PREFIX  = "gateway-"                             # selectedModel = gateway-<slug>
WS_OPEN_TIMEOUT = 30                                   # seconds to establish the socket
WS_REPLY_TIMEOUT = 90                                  # (legacy total cap; streaming uses idle)
WS_IDLE_TIMEOUT = 90                                   # give up only if NO token for this long
                                                       # (resets per token -> long code gens are fine)
DIRECT_WS_RETRIES = 2                                  # fresh-account retries on cap/empty
# Keep the old browser path off unless you explicitly enable it. When direct WS
# fails, browser fallback currently depends on local proxy/Tor state and can hide
# the real runner failure behind ERR_PROXY_CONNECTION_FAILED.
BROWSER_FALLBACK_ENABLED = False
# Warm account pool (sub-second latency: signup leaves the hot path)
ACCOUNT_POOL_SIZE = 20                                  # ready accounts kept warm
ACCOUNT_POOL_REFILL_SEC = 3                             # how often to top the pool up
ACCOUNT_TTL_SEC = 600                                   # drop pooled accounts older than this
# No Chromium in the WS path -> serve many at once (browser path stays capped low)
DIRECT_MAX_CONCURRENCY = 24                             # concurrent WS completions
# Show raw tool-call JSON in the stream (useful for debugging).
# Set to False in production so users never see ugly JSON blobs.
TOOL_DEBUG = os.environ.get("TOOL_DEBUG", "1").strip().lower() in ("1", "true", "yes")  # True = show JSON, False = hide

# ---- Direct API (FAST PATH; skips the browser on the hot path) --------------
# VERIFIED 2026-06-17: use.ai streams replies over a WEBSOCKET (Cloudflare Agents
# + Vercel AI SDK frames), NOT a REST endpoint. Full protocol is captured:
#
#   CONNECT: wss://agents.use.ai/agents/budget-agent/<chatId>
#              ?userId=<userId>&userType=regular&userEmail=<email>&planType=free&isTestUser=false
#   SEND (one JSON frame):
#     {"chatId":"<uuid>","userId":"<uuid>","userType":"regular","planType":"free",
#      "selectedModel":"gateway-<slug>","locale":"en",
#      "messages":[{"id":"<rand>","role":"user","parts":[{"type":"text","text":"<PROMPT>"}]}],
#      "trigger":"submit-message","source":"chat_page"}
#   RECV (concatenate chunk.delta where chunk.type=="text-delta"):
#     data-chat-metadata -> stream-start -> {chunk:{start, start-step, text-start,
#       text-delta(delta=...), text-end, finish-step, finish}} -> stream-complete
#     (cap -> {"type":"rate-limit-error","messageMetadata":{...}})
#
# This HTTP-replay path can't carry that; direct.py needs a websockets client
# instead. The session cookie/token above authenticates the socket. Until that
# client is written, keep URL "" to stay browser-only (DIRECT_API_BODY etc below
# are the old REST template, unused for WS).
DIRECT_API_URL = ""               # WebSocket, not REST -> empty until ws client lands
DIRECT_API_METHOD = "POST"
# {model} and {prompt} get substituted (auto JSON-escaped). Match the real body.
DIRECT_API_BODY = '{"model": "{model}", "messages": [{"role": "user", "content": "{prompt}"}]}'
DIRECT_API_AUTH_HEADER = "Authorization"
DIRECT_API_AUTH_FORMAT = "Bearer {token}"
# dotted path into the JSON reply, e.g. "choices.0.message.content"
DIRECT_API_RESPONSE_PATH = "choices.0.message.content"

# ---- Account bank -----------------------------------------------------------
BANK_PATH = "bank/accounts.db"        # sqlite store of harvested accounts/tokens
STORAGE_STATE_DIR = "bank/states"     # saved cookies/localStorage per account
BANK_MIN_FRESH = 10                   # keep at least this many warm + ready
BANK_PREWARM_BATCH = 5                # how many to harvest per top-up cycle
PREWARM_INTERVAL_SEC = 30             # how often the backend tops the bank up
# HARD RULE: each account is worth exactly ONE message. On a banked-account
# failure we retire it and claim a fresh one -- never a 2nd send through one acct.
MAX_BANKED_ATTEMPTS = 2               # how many fresh accounts to try before cold signup

# ---- Proxy rotation ---------------------------------------------------------
# cloakbrowser hides the BROWSER; proxies hide the IP so a flood of signups
# doesn't all come from one address. Empty = disabled (runs on your direct IP).
# Line formats: "1.2.3.4:8000", "http://1.2.3.4:8000",
#               "socks5://user:pass@1.2.3.4:1080", "user:pass@host:port"
PROXIES = []                    # inline list of proxies
PROXY_FILE = r"C:\Users\F\Desktop\ai\easy-ai\proxies"
PROXY_ROTATION = "round_robin"  # "round_robin" or "random"
PROXY_DEFAULT_SCHEME = "socks5"   # used when a proxy line omits the scheme

# ---- FREE proxy options (no paid account) -----------------------------------
# Option A: Tor -- free rotation via the Tor network. Start the daemon with
# start_tor.bat (uses the tor.exe bundled in Tor Browser, no browser needed),
# then this rotates the exit IP before each signup. NEWNYM is rate-limited to
# ~10s, so keep BANK_PREWARM_BATCH small (2-3).  >>> pre-wired for your machine.
PROXY_TOR = False                # you have Tor -> on
TOR_BROWSER_DIR = r"C:\Users\Emir\Desktop\Tor Browser"   # your Tor Browser folder
TOR_SOCKS = "socks5://127.0.0.1:9050"
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD = ""        # "" = cookie auth (what start_tor.bat sets up)
TOR_DATA_DIR = "tor_data"        # where start_tor.bat writes tor's data + auth cookie
TOR_COOKIE_PATH = ""             # "" = auto: <TOR_DATA_DIR>/control_auth_cookie
TOR_NEWNYM_DELAY = 10            # seconds between circuit renewals (Tor's rate limit)

# Option B: free public proxy lists -- run `python -m worker.proxy_sources` to
# fetch + validate them into PROXY_FILE, then set PROXY_FILE above. Free proxies
# die fast, so re-run it periodically.
