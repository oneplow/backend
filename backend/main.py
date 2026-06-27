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
import json
import logging
import time
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

# Allow cross-origin calls so any external client can hit the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _require_admin_key(req: Request) -> None:
    if not config.ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin API is disabled (ADMIN_KEY not set)")
    auth = req.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    key = req.headers.get("x-api-key", "").strip()
    if token != config.ADMIN_KEY and key != config.ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")

def _require_api_key(req: Request, model: str) -> None:
    auth = req.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    key = req.headers.get("x-api-key", "").strip()
    
    client_key = token or key
    if not client_key:
        raise HTTPException(status_code=401, detail="Missing API key")
        
    is_valid, reason = auth_db.validate_and_track_usage(client_key, model)
    if not is_valid:
        raise HTTPException(status_code=401, detail=reason)

def _get_user_from_req(req: Request) -> str:
    auth = req.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="Missing session token")
    username = auth_db.get_user_from_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid session token")
    return username

from pydantic import BaseModel
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None

@app.post("/auth/register")
async def register(req: RegisterRequest):
    success, token_or_err = auth_db.register_user(req.username, req.password, req.email)
    if not success:
        raise HTTPException(status_code=400, detail=token_or_err)
    return {"token": token_or_err, "username": req.username}

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

class GoogleAuthRequest(BaseModel):
    credential: str

@app.post("/auth/google")
async def google_auth(req: GoogleAuthRequest):
    try:
        idinfo = id_token.verify_oauth2_token(req.credential, google_requests.Request())
        email = idinfo.get("email")
        name = idinfo.get("name", "")
        
        if not email:
            raise HTTPException(status_code=400, detail="Google account has no email")
            
        success, token, username = auth_db.login_or_register_google_user(email, name)
        if not success:
            raise HTTPException(status_code=500, detail=token)
            
        return {"token": token, "username": username}
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Google token")

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
async def login(req: LoginRequest):
    success, token_or_err = auth_db.login_user(req.username, req.password)
    if not success:
        raise HTTPException(status_code=401, detail=token_or_err)
    return {"token": token_or_err, "username": req.username}

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
    return {"users": auth_db.get_all_users()}

class AdminUpdateUserRequest(BaseModel):
    rpm_limit: int | None = None
    expires_in_days: int | None = None
    allowed_models: str | None = None

@app.put("/admin/users/{username}")
async def admin_update_user(username: str, req: AdminUpdateUserRequest, request: Request):
    _require_admin_key(request)
    success = auth_db.admin_update_user_key(
        username=username,
        rpm_limit=req.rpm_limit,
        expires_in_days=req.expires_in_days,
        allowed_models=req.allowed_models
    )
    if not success:
        raise HTTPException(status_code=404, detail="User or key not found")
    return {"message": "User updated successfully"}

@app.delete("/admin/users/{username}")
async def admin_delete_user(username: str, req: Request):
    _require_admin_key(req)
    if auth_db.delete_user(username):
        return {"message": "User and associated data deleted"}
    raise HTTPException(status_code=404, detail="User not found")


# --- status ------------------------------------------------------------------
@app.get("/v1/models")
async def get_v1_models():
    return {
        "object": "list",
        "data": [
            {
                "id": m["slug"],
                "object": "model",
                "created": 1686935002,
                "owned_by": "easy-ai",
                "label": m.get("label", m["slug"])
            } for m in config.MODELS
        ]
    }


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
            if getattr(config, "DIRECT_WS_ENABLED", False):
                from worker.account_pool import POOL
                snap = health.H.snapshot(POOL.ready())
                snap["warm_accounts"] = POOL.ready()
                snap["pool_target"] = POOL.size
            else:
                snap = health.H.snapshot(bank.count_fresh())
            
            yield f"data: {json.dumps(snap)}\n\n"
            await asyncio.sleep(2)
            
    return StreamingResponse(gen(), media_type="text/event-stream")


# --- stateful chat -----------------------------------------------------------
def _sse_payload(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def _sse(token: str) -> str:
    return _sse_payload({"type": "token", "token": token})


@app.post("/chat")
async def chat(req: Request):
    body = await req.json()
    model = body.get("model", "default")
    _require_api_key(req, model)
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
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


# --- stateless: simple -------------------------------------------------------
@app.post("/v1/chat")
async def v1_chat(req: Request):
    body = await req.json()
    model = body.get("model", "default")
    _require_api_key(req, model)
    reply = await run_guarded(lambda: run_messages(model, body.get("messages", [])))
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
    body = await req.json()
    model = body.get("model", "default")
    _require_api_key(req, model)
    stream = bool(body.get("stream", False))
    msgs = body.get("messages", [])
    tools = body.get("tools", [])

    if tools:
        msgs = inject_tools_and_results(msgs, tools)

    if stream:
        cid = "chatcmpl-" + uuid.uuid4().hex[:24]
        created = int(time.time())

        async def gen():
            base = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model}

            if tools:
                # Buffer only if it's a tool call, otherwise stream in real-time
                valid_tool_names = {t["function"]["name"] for t in tools if t.get("type") == "function"}
                interceptor = ToolCallStreamInterceptor(valid_tools=valid_tool_names)
                async for delta in run_guarded_gen(lambda: stream_messages(model, msgs)):
                    interceptor.feed(delta)
                    for chunk in interceptor.get_passthrough():
                        yield f"data: {json.dumps({**base, **chunk})}\n\n"
                for chunk in interceptor.finish():
                    yield f"data: {json.dumps({**base, **chunk})}\n\n"
            else:
                # Normal streaming — no buffering needed
                async for delta in run_guarded_gen(lambda: stream_messages(model, msgs)):
                    chunk = {**base, "choices": [{"index": 0, "delta": {"content": delta},
                                                  "finish_reason": None}]}
                    yield f"data: {json.dumps(chunk)}\n\n"

            done = {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
            yield f"data: {json.dumps(done)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    reply = await run_guarded(lambda: run_messages(model, msgs))

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

