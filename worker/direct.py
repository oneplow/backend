"""
Headless DIRECT path: sign up a throwaway account (HTTP) and stream the reply
over use.ai's budget-agent WebSocket. No browser in the hot path.

Protocol (verified 2026-06-17):
  CONNECT wss://agents.use.ai/agents/budget-agent/<chatId>
            ?userId=<uuid>&userType=regular&userEmail=<email>&planType=free&isTestUser=false
  SEND    one JSON frame: {chatId,userId,userType,planType,selectedModel,
            messages:[{role,parts:[{type:text,text}]}],trigger,source,...}
  RECV    Vercel-AI-SDK frames wrapped as {index,streamId,chunk:{...}}:
            text-delta(delta=..) tokens, terminated by finish / stream-complete.
            Cap -> {"type":"rate-limit-error",...}
"""
import asyncio
import json
import logging
import uuid

from . import config
from .session_http import create_account

log = logging.getLogger("direct")

try:
    import websockets
except ImportError:
    websockets = None


def enabled() -> bool:
    return bool(getattr(config, "DIRECT_WS_ENABLED", False)) and websockets is not None


def _model_slug(model: str) -> str:
    return config.resolve_model(model)


def _extract_parts(content) -> list:
    if isinstance(content, str):
        if content.strip():
            return [{"type": "text", "text": content.strip()}]
        return []
    
    if isinstance(content, list):
        out_parts = []
        for item in content:
            if isinstance(item, str):
                if item.strip():
                    out_parts.append({"type": "text", "text": item.strip()})
            elif isinstance(item, dict):
                t = item.get("type")
                if t == "text":
                    text_val = item.get("text") or item.get("content") or ""
                    if text_val.strip():
                        out_parts.append({"type": "text", "text": text_val.strip()})
                elif t == "image_url":
                    img_url = item.get("image_url", {})
                    url = img_url.get("url") if isinstance(img_url, dict) else img_url if isinstance(img_url, str) else None
                    if url:
                        out_parts.append({"type": "image_url", "image_url": {"url": url}})
                elif t == "image":
                    if "image" in item:
                        out_parts.append({"type": "image", "image": item["image"]})
        return out_parts
    
    if isinstance(content, dict):
        t = content.get("type")
        if t == "text" or not t:
            text_val = content.get("text") or content.get("content") or ""
            if text_val.strip():
                return [{"type": "text", "text": text_val.strip()}]
        elif t == "image_url":
            img_url = content.get("image_url", {})
            url = img_url.get("url") if isinstance(img_url, dict) else img_url if isinstance(img_url, str) else None
            if url:
                return [{"type": "image_url", "image_url": {"url": url}}]
    return []


def _to_parts(messages: list) -> list:
    """[{role, content}] -> use.ai message-parts. Roles other than user/assistant
    (e.g. system) are relabelled to user. Consecutive messages of the same role
    are merged to satisfy models that require alternating turns."""
    out = []
    for m in messages:
        parts = _extract_parts(m.get("content"))
        if not parts:
            continue
            
        role = m.get("role")
        if role not in ("user", "assistant"):
            role = "user"
            
        # Merge if same role as previous
        if out and out[-1]["role"] == role:
            if out[-1]["parts"] and out[-1]["parts"][-1].get("type") == "text" and parts[0].get("type") == "text":
                out[-1]["parts"][-1]["text"] += "\n\n" + parts[0]["text"]
                out[-1]["parts"].extend(parts[1:])
            else:
                out[-1]["parts"].extend(parts)
        else:
            out.append({
                "id": uuid.uuid4().hex[:16], "role": role,
                "parts": parts, "metadata": {}
            })
            
    if not out:
        out.append({"id": uuid.uuid4().hex[:16], "role": "user",
                    "parts": [{"type": "text", "text": ""}], "metadata": {}})
    return out


def _build_frame(chat_id, acct, model, parts):
    email = acct["email"]
    return {
        "chatId": chat_id, "userId": acct["user_id"], "email": email,
        "userType": "regular", "userEmail": email, "planType": "free",
        "subscriptionStatus": "inactive", "isFreemium": False, "isTestUser": False,
        "selectedModel": config.MODEL_PREFIX + _model_slug(model), "locale": "en",
        "isWebSearchMode": False, "isDeepResearchMode": False,
        "isImageGenerationMode": False, "isStandaloneImageMode": False,
        "agenticMode": False,
        "deviceId": acct.get("deviceId", str(uuid.uuid4())),
        "mixpanelUserId": acct.get("mixpanelUserId", str(uuid.uuid4())),
        "needsBlurPreview": False,
        "messages": parts,
        "trigger": "submit-message", "source": "chat_page",
    }


async def _stream_gen(acct: dict, model: str, parts: list):
    """Yield text deltas as they arrive. Uses a per-token IDLE timeout (resets on
    every frame), so a long code generation never trips a total-time cap -- it
    only ends on finish/stream-complete, a closed socket, or `idle`s of silence."""
    chat_id = str(uuid.uuid4())
    import urllib.parse
    encoded_email = urllib.parse.quote(acct['email'])
    uri = (f"{config.WS_AGENT_BASE}/{chat_id}"
           f"?userId={acct['user_id']}&userType=regular"
           f"&userEmail={encoded_email}&planType=free&isTestUser=false")
    hdrs = {
        "Cookie": acct["cookie_header"],
        "Origin": "https://use.ai",
        "Referer": "https://use.ai/",
        "User-Agent": acct.get("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"),
    }
    # Merge extra browser headers from fingerprint if available
    fp_headers = acct.get("headers", {})
    for k in ("Accept-Language", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform"):
        if k in fp_headers:
            hdrs[k] = fp_headers[k]
    idle = getattr(config, "WS_IDLE_TIMEOUT", 90)

    # Build connection kwargs — try proxy first, fall back to direct
    async def _connect_ws():
        """Try proxy-based WS, fall back to direct if proxy fails."""
        if acct.get("proxy"):
            try:
                from python_socks.async_.asyncio import Proxy
                import ssl as _ssl
                proxy_client = Proxy.from_url(acct["proxy"])
                sock = await proxy_client.connect(dest_host="agents.use.ai", dest_port=443)
                return websockets.connect(uri,
                    additional_headers=hdrs, max_size=None,
                    open_timeout=config.WS_OPEN_TIMEOUT,
                    ping_interval=20, ping_timeout=60,
                    sock=sock, server_hostname="agents.use.ai",
                    ssl=_ssl.create_default_context())
            except ImportError:
                log.warning("python-socks not installed, connecting without proxy")
            except Exception as e:
                log.warning("proxy WS connect failed (%r), falling back to direct", e)

        # Direct (no proxy) fallback
        return websockets.connect(uri,
            additional_headers=hdrs, max_size=None,
            open_timeout=config.WS_OPEN_TIMEOUT,
            ping_interval=20, ping_timeout=60)

    async with await _connect_ws() as ws:
        await ws.send(json.dumps(_build_frame(
            chat_id, acct, model, parts)))
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=idle)
            except asyncio.TimeoutError:
                log.warning("WS TimeoutError waiting for frame")
                break                                  # no token for `idle`s -> stop
            except websockets.ConnectionClosed as e:
                log.warning("WS ConnectionClosed: code=%r reason=%r", e.code, e.reason)
                break
            # Skip binary frames (proxy garbage)
            if isinstance(raw, bytes):
                try:
                    raw = raw.decode("utf-8")
                except UnicodeDecodeError:
                    log.debug("skipping non-UTF8 binary frame (%d bytes)", len(raw))
                    continue
            try:
                o = json.loads(raw)
            except Exception as e:
                log.warning("WS failed to parse JSON, raw=%r, err=%r", raw, e)
                continue
            if o.get("type") == "rate-limit-error":
                raise RuntimeError("rate-limit-error: " +
                                   o.get("messageMetadata", {}).get("errorType", "?"))
            chunk = o.get("chunk")
            if isinstance(chunk, dict):
                t = chunk.get("type")
                if t == "text-delta":
                    d = chunk.get("delta", "")
                    if d:
                        yield d
                elif t == "finish":
                    break
            if o.get("type") == "stream-complete":
                break


async def stream(model: str, prompt: str | None = None,
                 messages: list | None = None, acct: dict | None = None):
    """Async generator of text deltas. Pass EITHER `prompt` or a role-tagged
    `messages` list. Retries on a FRESH account only while nothing has been
    emitted yet (once tokens start flowing we never restart -- the client already
    has partial output)."""
    if websockets is None:
        raise RuntimeError("websockets not installed")
    parts = _to_parts(messages if messages else [{"role": "user", "content": prompt or ""}])
    last = None
    for attempt in range(1, config.DIRECT_WS_RETRIES + 1):
        a = acct or await create_account()
        acct = None                       # supplied account is single-use; reroll fresh
        produced = False
        try:
            async for d in _stream_gen(a, model, parts):
                produced = True
                yield d
            if produced:
                return
            last = RuntimeError("empty reply")
        except Exception as e:
            last = e
            if produced:
                log.warning("direct stream broke mid-reply (%r) -> ending with partial", e)
                return
            log.warning("direct attempt %d/%d failed: %r",
                        attempt, config.DIRECT_WS_RETRIES, e)
    if last:
        raise last


async def complete(model: str, prompt: str | None = None,
                   messages: list | None = None, acct: dict | None = None) -> str:
    """Buffered variant: collect the whole reply (used by non-streaming callers)."""
    out = []
    async for d in stream(model, prompt=prompt, messages=messages, acct=acct):
        out.append(d)
    reply = "".join(out).strip()
    if not reply:
        raise RuntimeError("empty reply")
    return reply
