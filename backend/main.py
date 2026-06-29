"""
FastAPI orchestrator  (API-only, no frontend).
  GET  /models              -> model list for the dropdown
  GET  /bank                -> bank status (how many warm accounts ready)
  GET  /health              -> full watchdog readout
  POST /chat                -> stateful chat (we hold context), streams reply
  POST /v1/chat             -> stateless, simple OpenAI-ish
  POST /v1/chat/completions -> OpenAI-compatible (drop-in for OpenAI SDK clients)

On startup a background loop keeps the account bank topped up so signup stays
out of the hot path.
"""
import asyncio
from collections import defaultdict, deque
import json
import logging
import time
from urllib import error as urllib_error, parse as urllib_parse, request as urllib_request
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from worker import auth_db, bank, config, health
from worker.harvester import top_up
from worker.easy_ai import run_messages, stream_messages
from backend.tool_support import inject_tools_and_results, ToolCallStreamInterceptor
from . import context
from .pool import run_guarded, run_guarded_gen

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("backend")
app = FastAPI(title="WMan")

# Allow cross-origin calls for the frontend domains we trust in the browser.
_cors_allow_origins = ["*"] if config.CORS_ALLOW_ALL else config.CORS_ALLOW_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_allow_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_auth_attempts: dict[tuple[str, str], deque[float]] = defaultdict(deque)


def _get_client_ip(req: Request) -> str:
    forwarded_for = req.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    real_ip = req.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    return req.client.host if req.client else "unknown"


def _enforce_auth_rate_limit(req: Request, bucket: str) -> None:
    now = time.time()
    window_start = now - config.AUTH_RATE_LIMIT_WINDOW_SEC
    client_ip = _get_client_ip(req)
    key = (bucket, client_ip)
    attempts = _auth_attempts[key]

    while attempts and attempts[0] < window_start:
        attempts.popleft()

    if len(attempts) >= config.AUTH_RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Too many auth attempts. Try again in "
                f"{config.AUTH_RATE_LIMIT_WINDOW_SEC} seconds."
            ),
        )

    attempts.append(now)


def _require_admin_key(req: Request) -> None:
    """Legacy admin auth: accepts ADMIN_KEY bearer or role-based admin session."""
    # First check role-based auth via session token
    auth = req.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    
    if token:
        # Check if this is a session token with admin role
        user_info = auth_db.get_full_user_by_token(token)
        if user_info and user_info.get("role") == "admin":
            return
        
        # Fallback: check ADMIN_KEY
        if config.ADMIN_KEY and token == config.ADMIN_KEY:
            return
    
    # Check x-api-key header as fallback
    key = req.headers.get("x-api-key", "").strip()
    if config.ADMIN_KEY and key == config.ADMIN_KEY:
        return
    
    raise HTTPException(status_code=401, detail="Admin access required")

def _require_api_key(req: Request, model: str) -> str:
    auth = req.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    key = req.headers.get("x-api-key", "").strip()
    
    client_key = token or key
    if not client_key:
        raise HTTPException(status_code=401, detail="Missing API key")
        
    is_valid, reason = auth_db.validate_and_track_usage(client_key, model)
    if not is_valid:
        raise HTTPException(status_code=401, detail=reason)
    return client_key

def _get_user_from_req(req: Request) -> str:
    auth = req.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="Missing session token")
    username = auth_db.get_user_from_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid session token")
    return username


def _get_dashboard_payload(req: Request) -> dict:
    if getattr(config, "DIRECT_WS_ENABLED", False):
        from worker.account_pool import POOL
        snap = health.H.snapshot(POOL.ready())
        snap["warm_accounts"] = POOL.ready()
        snap["pool_target"] = POOL.size
    else:
        snap = health.H.snapshot(bank.count_fresh())

    auth = req.headers.get("authorization", "")
    bearer = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    key = req.headers.get("x-api-key", "").strip()

    dashboard: dict | None = None
    
    # Check role-based admin first, then ADMIN_KEY fallback
    is_admin = False
    if bearer:
        user_info = auth_db.get_full_user_by_token(bearer)
        if user_info and user_info.get("role") == "admin":
            is_admin = True
    if not is_admin and config.ADMIN_KEY and (bearer == config.ADMIN_KEY or key == config.ADMIN_KEY):
        is_admin = True
    
    if is_admin:
        dashboard = {
            "mode": "admin",
            "key_count": len(auth_db.list_keys()),
            "user_count": len(auth_db.get_all_users()),
            "total_system_tokens": auth_db.get_total_system_tokens(),
            "token_info": None,
        }
    elif bearer:
        username = auth_db.get_user_from_token(bearer)
        if username:
            dashboard = {
                "mode": "user",
                "key_count": 1 if auth_db.get_user_key(username) else 0,
                "user_count": None,
                "token_info": auth_db.get_token_usage_by_username(username)
                or {
                    "token_limit": config.DEFAULT_TOKEN_LIMIT,
                    "tokens_used": 0,
                    "token_reset_period": "weekly",
                    "token_last_reset": None,
                },
            }

    snap["dashboard"] = dashboard
    return snap

from pydantic import BaseModel
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None

@app.post("/auth/register")
async def register(req: RegisterRequest, request: Request):
    _enforce_auth_rate_limit(request, "register")
    success, token_or_err, role = auth_db.register_user(req.username, req.password, req.email)
    if not success:
        raise HTTPException(status_code=400, detail=token_or_err)
    return {"token": token_or_err, "username": req.username, "role": role}

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

class GoogleAuthRequest(BaseModel):
    credential: str | None = None
    access_token: str | None = None


def _fetch_google_json(url: str, headers: dict[str, str] | None = None) -> dict:
    req = urllib_request.Request(url, headers=headers or {})
    with urllib_request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _resolve_google_identity(req: GoogleAuthRequest) -> tuple[str, str]:
    if req.credential:
        idinfo = id_token.verify_oauth2_token(
            req.credential,
            google_requests.Request(),
            config.GOOGLE_CLIENT_ID,
        )
        issuer = idinfo.get("iss")
        if issuer not in ("accounts.google.com", "https://accounts.google.com"):
            raise HTTPException(status_code=401, detail="Invalid Google token issuer")

        email = idinfo.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Google account has no email")

        return email, idinfo.get("name", "")

    if req.access_token:
        token_info_url = (
            "https://www.googleapis.com/oauth2/v3/tokeninfo?"
            + urllib_parse.urlencode({"access_token": req.access_token})
        )
        token_info = _fetch_google_json(token_info_url)
        audience = token_info.get("aud") or token_info.get("azp")
        if audience != config.GOOGLE_CLIENT_ID:
            raise HTTPException(status_code=401, detail="Google token audience mismatch")

        profile = _fetch_google_json(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {req.access_token}"},
        )
        email = profile.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Google account has no email")

        return email, profile.get("name", "")

    raise HTTPException(status_code=400, detail="Missing Google credential")

@app.post("/auth/google")
async def google_auth(req: GoogleAuthRequest, request: Request):
    _enforce_auth_rate_limit(request, "google")
    if not config.GOOGLE_CLIENT_ID:
        log.error("GOOGLE_CLIENT_ID is not configured on the backend")
        raise HTTPException(status_code=500, detail="Google login is not configured")

    try:
        email, name = _resolve_google_identity(req)
            
        success, token, username, role = auth_db.login_or_register_google_user(email, name)
        if not success:
            raise HTTPException(status_code=500, detail=token)
            
        return {"token": token, "username": username, "role": role}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"Invalid Google token: {str(e)}")
    except urllib_error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")
        log.error("Google token lookup failed: %s", detail or e.reason)
        raise HTTPException(status_code=401, detail="Invalid Google access token")
    except Exception as e:
        log.error(f"Google auth error: {e}")
        raise HTTPException(status_code=500, detail=f"Google auth error: {str(e)}")

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
async def login(req: LoginRequest, request: Request):
    _enforce_auth_rate_limit(request, "login")
    success, token_or_err, role = auth_db.login_user(req.username, req.password)
    if not success:
        raise HTTPException(status_code=401, detail=token_or_err)
    return {"token": token_or_err, "username": req.username, "role": role}

@app.get("/auth/me")
async def get_auth_me(request: Request):
    """Return current user info from session token."""
    auth = request.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="Missing session token")
    user_info = auth_db.get_full_user_by_token(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid session token")
    return user_info
class UserKeyRequest(BaseModel):
    rpm_limit: int = 60
    expires_in_days: int | None = None
    allowed_models: str | None = None

@app.post("/user/keys")
async def create_user_key(req: UserKeyRequest, request: Request):
    username = _get_user_from_req(request)
    key_info = auth_db.create_or_update_user_key(username, req.rpm_limit, req.expires_in_days, req.allowed_models)
    return {"message": "Key created or updated successfully", "key": key_info}

@app.get("/user/keys")
async def get_user_keys(request: Request):
    username = _get_user_from_req(request)
    key = auth_db.get_user_key(username)
    return {"key": key}

@app.post("/user/keys/reset")
async def reset_user_key(request: Request):
    username = _get_user_from_req(request)
    key = auth_db.get_user_key(username)
    if not key:
        raise HTTPException(status_code=404, detail="No key found")
    auth_db.reset_limit(key["key"])
    return {"message": "Rate limit reset successfully"}

@app.delete("/user/keys")
async def delete_user_key(request: Request):
    username = _get_user_from_req(request)
    key = auth_db.get_user_key(username)
    if not key:
        raise HTTPException(status_code=404, detail="No key found")
    if auth_db.delete_key(key["key"]):
        return {"message": "Key revoked successfully"}
    raise HTTPException(status_code=500, detail="Failed to revoke key")


@app.on_event("startup")
async def _start_prewarmer():
    # The headless WS path signs up its own account per request, so the browser
    # harvester/bank isn't needed. Instead start the warm ACCOUNT POOL so signup
    # stays out of the hot path. Only run the browser prewarmer for the fallback.
    if getattr(config, "DIRECT_WS_ENABLED", False):
        from worker.account_pool import POOL
        POOL.start()
        log.info("DIRECT_WS_ENABLED -> headless path, warm account pool started")
        return

    async def loop():
        while True:
            try:
                n = await top_up()
                if n:
                    log.info("bank +%d (fresh=%d)", n, bank.count_fresh())
            except Exception as e:
                log.warning("prewarm error: %s", e)
            await asyncio.sleep(config.PREWARM_INTERVAL_SEC)
    asyncio.create_task(loop())

# --- admin auth management ---------------------------------------------------
@app.get("/admin/keys")
async def admin_list_keys(req: Request):
    _require_admin_key(req)
    return {"keys": auth_db.list_keys()}

@app.post("/admin/keys")
async def admin_create_key(req: Request):
    _require_admin_key(req)
    body = await req.json()
    
    # Generate a random key if none provided
    key_str = body.get("key") or f"sk-{uuid.uuid4().hex[:32]}"
    name = body.get("name")
    expires_in_days = body.get("expires_in_days")
    rpm_limit = body.get("rpm_limit")
    
    expires_at = None
    if expires_in_days is not None:
        expires_at = time.time() + (float(expires_in_days) * 86400)
        
    if rpm_limit is not None:
        rpm_limit = int(rpm_limit)
        
    try:
        new_key = auth_db.create_key(key=key_str, name=name, expires_at=expires_at, rpm_limit=rpm_limit)
        return {"message": "Key created", "key": new_key}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/admin/keys/{key}")
async def admin_delete_key(key: str, req: Request):
    _require_admin_key(req)
    if auth_db.delete_key(key):
        return {"message": "Key deleted"}
    raise HTTPException(status_code=404, detail="Key not found")

class AdminUpdateKeyRequest(BaseModel):
    name: str | None = None
    rpm_limit: int | None = None
    expires_in_days: int | None = None
    allowed_models: str | None = None

@app.put("/admin/keys/{key}")
async def admin_update_key_route(key: str, req: AdminUpdateKeyRequest, request: Request):
    _require_admin_key(request)
    success = auth_db.admin_update_key(
        key=key,
        name=req.name,
        rpm_limit=req.rpm_limit,
        expires_in_days=req.expires_in_days,
        allowed_models=req.allowed_models
    )
    if not success:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"message": "Key updated successfully"}


@app.post("/admin/keys/{key}/reset")
async def admin_reset_key_limit(key: str, req: Request):
    _require_admin_key(req)
    if auth_db.reset_limit(key):
        return {"message": "Rate limit reset successfully"}
    # Even if rowcount was 0 (no usage yet), we can just return success
    return {"message": "Rate limit reset successfully"}

@app.get("/admin/users")
async def admin_get_users(req: Request):
    _require_admin_key(req)
    users = auth_db.get_all_users()
    for u in users:
        if u.get("key") is None and u.get("token_limit") is None:
            u["token_limit"] = config.DEFAULT_TOKEN_LIMIT
    return {"users": users}

class AdminUpdateUserRequest(BaseModel):
    rpm_limit: int | None = None
    expires_in_days: int | None = None
    allowed_models: str | None = None
    token_limit: int | None = -1  # -1 means "don't change", None means unlimited
    token_reset_period: str | None = None

@app.put("/admin/users/{username}")
async def admin_update_user(username: str, req: AdminUpdateUserRequest, request: Request):
    _require_admin_key(request)
    success = auth_db.admin_update_user_key(
        username=username,
        rpm_limit=req.rpm_limit,
        expires_in_days=req.expires_in_days,
        allowed_models=req.allowed_models
    )
    # Handle token_limit separately (-1 = don't change)
    if req.token_limit != -1:
        auth_db.admin_set_token_limit_by_username(username, req.token_limit, req.token_reset_period)
    elif req.token_reset_period:
        # Only update reset period
        auth_db.admin_set_token_limit_by_username(username, None, req.token_reset_period)
    if not success:
        raise HTTPException(status_code=404, detail="User or key not found")
    return {"message": "User updated successfully"}

@app.delete("/admin/users/{username}")
async def admin_delete_user(username: str, req: Request):
    _require_admin_key(req)
    if auth_db.delete_user(username):
        return {"message": "User and associated data deleted"}
    raise HTTPException(status_code=404, detail="User not found")


# --- Token management endpoints -----------------------------------------------

@app.get("/user/tokens")
async def get_user_tokens(request: Request):
    username = _get_user_from_req(request)
    usage = auth_db.get_token_usage_by_username(username)
    if not usage:
        return {"token_limit": None, "tokens_used": 0, "token_reset_period": "weekly", "token_last_reset": None}
    return usage

@app.get("/admin/users/{username}/tokens")
async def admin_get_user_tokens(username: str, req: Request):
    _require_admin_key(req)
    usage = auth_db.get_token_usage_by_username(username)
    if not usage:
        return {"token_limit": None, "tokens_used": 0, "token_reset_period": "weekly", "token_last_reset": None}
    return usage

class TokenLimitRequest(BaseModel):
    token_limit: int | None = None
    reset_period: str | None = None

@app.put("/admin/users/{username}/tokens")
async def admin_set_user_tokens(username: str, req: TokenLimitRequest, request: Request):
    _require_admin_key(request)
    success = auth_db.admin_set_token_limit_by_username(username, req.token_limit, req.reset_period)
    if not success:
        raise HTTPException(status_code=404, detail="User or key not found")
    return {"message": "Token limit updated"}

@app.post("/admin/users/{username}/tokens/reset")
async def admin_reset_user_tokens(username: str, req: Request):
    _require_admin_key(req)
    success = auth_db.admin_reset_tokens_by_username(username)
    if not success:
        raise HTTPException(status_code=404, detail="User or key not found")
    return {"message": "Token usage reset"}

class AddTokensRequest(BaseModel):
    amount: int

@app.post("/admin/users/{username}/tokens/add")
async def admin_add_user_tokens(username: str, req: AddTokensRequest, request: Request):
    _require_admin_key(request)
    success = auth_db.admin_add_tokens_by_username(username, req.amount)
    if not success:
        raise HTTPException(status_code=404, detail="User or key not found")
    return {"message": f"Added {req.amount} tokens"}

class RoleRequest(BaseModel):
    role: str  # "admin" or "user"

@app.put("/admin/users/{username}/role")
async def admin_set_user_role(username: str, req: RoleRequest, request: Request):
    _require_admin_key(request)
    if req.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    success = auth_db.set_user_role(username, req.role)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": f"User role updated to {req.role}"}


# --- status ------------------------------------------------------------------
@app.get("/v1/models")
async def get_v1_models():
    status_blocks = auth_db.get_model_status_blocks(60)
    return {
        "object": "list",
        "data": [
            {
                "id": m["slug"],
                "object": "model",
                "created": 1686935002,
                "owned_by": "easy-ai",
                "label": m.get("label", m["slug"]),
                "blocks": status_blocks.get(m["slug"], [1] * 60)
            } for m in config.MODELS
        ]
    }


@app.get("/v1/notifications")
async def get_notifications(req: Request):
    try:
        username = _get_user_from_req(req)
        notifications = auth_db.get_user_notifications(username)
        return {"notifications": notifications}
    except HTTPException:
        return {"notifications": []}


@app.get("/bank")
async def bank_status():
    if getattr(config, "DIRECT_WS_ENABLED", False):
        from worker.account_pool import POOL
        snap = health.H.snapshot(POOL.ready())
        return {
            "mode": "headless-ws",
            "warm_accounts": POOL.ready(),
            "pool_target": POOL.size,
            "status": snap["status"],
            "reasons": snap["reasons"],
        }
    snap = health.H.snapshot(bank.count_fresh())
    return {
        "fresh": snap["fresh_accounts"],
        "status": snap["status"],
        "reasons": snap["reasons"],
        "stats": bank.stats(),
    }


@app.get("/health")
async def health_status():
    """Full watchdog readout: status, why, rates, counters, recent errors."""
    if getattr(config, "DIRECT_WS_ENABLED", False):
        from worker.account_pool import POOL
        snap = health.H.snapshot(POOL.ready())
        snap["warm_accounts"] = POOL.ready()
        snap["pool_target"] = POOL.size
        return snap
    return health.H.snapshot(bank.count_fresh())


@app.get("/health/stream")
async def health_stream(req: Request):
    """Real-time SSE stream for dashboard stats."""
    async def gen():
        while True:
            if await req.is_disconnected():
                break
            snap = _get_dashboard_payload(req)
            yield f"data: {json.dumps(snap)}\n\n"
            await asyncio.sleep(2)
            
    return StreamingResponse(gen(), media_type="text/event-stream")


# --- stateful chat -----------------------------------------------------------
def _sse_payload(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def _sse(token: str) -> str:
    return _sse_payload({"type": "token", "token": token})


@app.post("/chat")

@app.get("/user/usage_stats")
async def get_user_usage_stats(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    username = auth_db.get_user_from_token(token)
    if not username:
        return JSONResponse({"detail": "Invalid session"}, status_code=401)
    
    days = int(request.query_params.get("days", 90))
    stats = auth_db.get_usage_stats(username, days)
    return {"stats": stats}

@app.get("/admin/usage_stats")
async def admin_get_usage_stats_route(req: Request):
    _require_admin_key(req)
    days = int(req.query_params.get("days", 90))
    stats = auth_db.admin_get_usage_stats(days)
    return {"stats": stats}


@app.get("/user/logs")
async def get_user_logs(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    username = auth_db.get_user_from_token(token)
    if not username:
        return JSONResponse({"detail": "Invalid session"}, status_code=401)
    
    limit = int(request.query_params.get("limit", 50))
    offset = int(request.query_params.get("offset", 0))
    return auth_db.get_request_logs(username, limit, offset)

@app.get("/admin/logs")
async def admin_get_logs(req: Request):
    _require_admin_key(req)
    limit = int(req.query_params.get("limit", 50))
    offset = int(req.query_params.get("offset", 0))
    return auth_db.admin_get_request_logs(limit, offset)

async def chat(req: Request):
    start_time = time.time()

    body = await req.json()
    model = body.get("model", "default")
    client_key = _require_api_key(req, model)
    message = body.get("message", "")
    session_id = body.get("sessionId") or str(uuid.uuid4())

    messages = context.build_messages(session_id, message)   # role-tagged history + new turn
    context.append(session_id, "user", message)

    async def gen():
        parts: list[str] = []
        try:
            async for delta in run_guarded_gen(lambda: stream_messages(model, messages)):
                parts.append(delta)
                yield _sse(delta)
        except Exception as exc:
            log.warning("chat stream failed: %s: %s", type(exc).__name__, exc)
            if not parts:
                yield _sse(f"Backend error contacting the model runner ({type(exc).__name__}).")
        reply = "".join(parts).strip()
        context.append(session_id, "assistant", reply)
        # Count tokens: input + output
        input_tokens = auth_db.estimate_tokens(message)
        output_tokens = auth_db.estimate_tokens(reply)
        auth_db.consume_tokens(client_key, input_tokens + output_tokens)
        latency = int((time.time() - start_time) * 1000)
        auth_db.log_usage(client_key, model, input_tokens + output_tokens, True, latency)
        auth_db.insert_request_log(client_key, str(uuid.uuid4()), model, 'POST', '/chat', True, input_tokens, output_tokens, latency)
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


# --- stateless: simple -------------------------------------------------------
@app.post("/v1/chat")
async def v1_chat(req: Request):
    start_time = time.time()
    body = await req.json()
    model = body.get("model", "default")
    client_key = _require_api_key(req, model)
    msgs = body.get("messages", [])
    reply = await run_guarded(lambda: run_messages(model, msgs))
    # Count tokens
    input_text = " ".join(m.get("content", "") for m in msgs if m.get("content"))
    input_tokens = auth_db.estimate_tokens(input_text)
    output_tokens = auth_db.estimate_tokens(reply)
    auth_db.consume_tokens(client_key, input_tokens + output_tokens)
    latency = int((time.time() - start_time) * 1000)
    auth_db.log_usage(client_key, model, input_tokens + output_tokens, True, latency)
    auth_db.insert_request_log(client_key, str(uuid.uuid4()), model, 'POST', '/chat', True, input_tokens, output_tokens, latency)
    return JSONResponse({
        "model": model,
        "choices": [{"message": {"role": "assistant", "content": reply}}],
    })


# --- stateless: OpenAI-compatible -------------------------------------------
def _openai_block(reply: str, model: str) -> dict:
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex[:24],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": reply},
            "finish_reason": "stop",
        }],
    }


@app.post("/v1/chat/completions")
async def openai_completions(req: Request):
    start_time = time.time()
    body = await req.json()
    model = body.get("model", "default")
    client_key = _require_api_key(req, model)
    stream = bool(body.get("stream", False))
    msgs = body.get("messages", [])
    tools = body.get("tools", [])

    if tools:
        msgs = inject_tools_and_results(msgs, tools)

    # Estimate input tokens
    text_parts = []
    for m in msgs:
        content = m.get("content")
        if not content:
            continue
        if isinstance(content, str):
            text_parts.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and "text" in part:
                    text_parts.append(part["text"])
    input_text = " ".join(text_parts)
    input_tokens = auth_db.estimate_tokens(input_text)

    if stream:
        cid = "chatcmpl-" + uuid.uuid4().hex[:24]
        created = int(time.time())

        async def gen():
            base = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model}
            output_parts: list[str] = []

            if tools:
                # Buffer only if it's a tool call, otherwise stream in real-time
                valid_tool_names = {t["function"]["name"] for t in tools if t.get("type") == "function"}
                interceptor = ToolCallStreamInterceptor(valid_tools=valid_tool_names)
                async for delta in run_guarded_gen(lambda: stream_messages(model, msgs)):
                    output_parts.append(delta)
                    interceptor.feed(delta)
                    for chunk in interceptor.get_passthrough():
                        yield f"data: {json.dumps({**base, **chunk})}\n\n"
                for chunk in interceptor.finish():
                    yield f"data: {json.dumps({**base, **chunk})}\n\n"
            else:
                # Normal streaming — no buffering needed
                async for delta in run_guarded_gen(lambda: stream_messages(model, msgs)):
                    output_parts.append(delta)
                    chunk = {**base, "choices": [{"index": 0, "delta": {"content": delta},
                                                  "finish_reason": None}]}
                    yield f"data: {json.dumps(chunk)}\n\n"

            done = {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
            yield f"data: {json.dumps(done)}\n\n"
            yield "data: [DONE]\n\n"

            # Count tokens after stream completes
            output_text = "".join(output_parts)
            output_tokens = auth_db.estimate_tokens(output_text)
            auth_db.consume_tokens(client_key, input_tokens + output_tokens)
            latency = int((time.time() - start_time) * 1000)
            auth_db.log_usage(client_key, model, input_tokens + output_tokens, True, latency)
            auth_db.insert_request_log(client_key, str(uuid.uuid4()), model, 'POST', '/chat', True, input_tokens, output_tokens, latency)

        return StreamingResponse(gen(), media_type="text/event-stream")

    reply = await run_guarded(lambda: run_messages(model, msgs))

    # Count tokens for non-streaming
    output_tokens = auth_db.estimate_tokens(reply)
    auth_db.consume_tokens(client_key, input_tokens + output_tokens)
    latency = int((time.time() - start_time) * 1000)
    auth_db.log_usage(client_key, model, input_tokens + output_tokens, True, latency)
    auth_db.insert_request_log(client_key, str(uuid.uuid4()), model, 'POST', '/chat', True, input_tokens, output_tokens, latency)

    if tools:
        from backend.tool_support import _extract_tool_calls
        valid_tool_names = {t["function"]["name"] for t in tools if t.get("type") == "function"}
        tool_calls = _extract_tool_calls(reply, valid_tool_names)
        if tool_calls:
            block = _openai_block("", model)
            block["choices"][0]["message"]["tool_calls"] = tool_calls
            block["choices"][0]["message"].pop("content", None)
            block["choices"][0]["finish_reason"] = "tool_calls"
            return JSONResponse(block)

    return JSONResponse(_openai_block(reply, model))

