"""
API Key authentication database and rate limiter.
Stores client API keys, names, expiration timestamps, and per-minute rate limits.
"""
import math
import os
import sqlite3
import threading
import time

from . import config

_lock = threading.Lock()

def _open() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(config.AUTH_DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(config.AUTH_DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            email TEXT,
            password_hash TEXT,
            session_token TEXT,
            created_at REAL
        )""")
    c.execute("""
        CREATE TABLE IF NOT EXISTS api_keys(
            key TEXT PRIMARY KEY,
            name TEXT,
            expires_at REAL,
            rpm_limit INTEGER,
            created_at REAL,
            owner_username TEXT,
            allowed_models TEXT
        )""")
    
    # Try to add new columns if upgrading from old version
    try:
        c.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE api_keys ADD COLUMN owner_username TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE api_keys ADD COLUMN allowed_models TEXT")
    except sqlite3.OperationalError:
        pass
    # Token quota columns
    try:
        c.execute("ALTER TABLE api_keys ADD COLUMN token_limit INTEGER")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE api_keys ADD COLUMN tokens_used INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE api_keys ADD COLUMN token_reset_period TEXT DEFAULT 'weekly'")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE api_keys ADD COLUMN token_last_reset REAL")
    except sqlite3.OperationalError:
        pass
    # Role column for users
    try:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    except sqlite3.OperationalError:
        pass

    c.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits(
            key TEXT,
            minute_timestamp INTEGER,
            count INTEGER,
            PRIMARY KEY (key, minute_timestamp)
        )""")
    c.execute('''
        CREATE TABLE IF NOT EXISTS request_logs (
                id TEXT PRIMARY KEY,
                username TEXT,
                model TEXT,
                method TEXT,
                url TEXT,
                is_success INTEGER,
                input_tokens INTEGER,
                output_tokens INTEGER,
                latency_ms INTEGER,
                created_at REAL
            )
        ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS usage_logs(
            date TEXT,
            username TEXT,
            model TEXT,
            requests INTEGER DEFAULT 0,
            tokens INTEGER DEFAULT 0,
            success INTEGER DEFAULT 0,
            total_latency_ms INTEGER DEFAULT 0,
            PRIMARY KEY (date, username, model)
        )''')
    return c

import bcrypt
import secrets
import time

def register_user(username: str, password: str, email: str | None = None) -> tuple[bool, str, str]:
    """Register a user. Returns (success, token_or_error, role)."""
    with _lock:
        c = _open()
        try:
            if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                return False, "Username already exists", "user"
            
            pwd_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            token = secrets.token_hex(32)
            now = time.time()
            
            # Determine role from email
            role = 'admin' if email and email.lower() in config.DEFAULT_ADMIN_EMAILS else 'user'
            
            c.execute("INSERT INTO users(username, email, password_hash, session_token, created_at, role) VALUES(?,?,?,?,?,?)", 
                      (username, email, pwd_hash, token, now, role))
            c.commit()



            return True, token, role
        finally:
            c.close()

def login_user(username: str, password: str) -> tuple[bool, str, str]:
    """Login a user. Returns (success, token_or_error, role)."""
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT password_hash, role FROM users WHERE username=?", (username,)).fetchone()
            if not row or not bcrypt.checkpw(password.encode('utf-8'), row["password_hash"].encode('utf-8')):
                return False, "Invalid username or password", "user"
            
            token = secrets.token_hex(32)
            c.execute("UPDATE users SET session_token=? WHERE username=?", (token, username))
            

            c.commit()
            
            role = row["role"] or "user"
            return True, token, role
        finally:
            c.close()

def login_or_register_google_user(email: str, name: str) -> tuple[bool, str, str, str]:
    """Login or register a Google user. Returns (success, token_or_error, username, role)."""
    with _lock:
        c = _open()
        try:
            # Check if user with this email exists
            row = c.execute("SELECT username, role FROM users WHERE email=?", (email,)).fetchone()
            
            username = ""
            is_new_user = False
            if row:
                username = row["username"]
            else:
                # Fallback: check if they registered manually using their email as username
                row2 = c.execute("SELECT username FROM users WHERE username=?", (email,)).fetchone()
                if row2:
                    username = email
                    c.execute("UPDATE users SET email=? WHERE username=?", (email, username))
                else:
                    # Register new user: base username is email before @
                    base_username = email.split('@')[0]
                    username = base_username
                    counter = 1
                    while True:
                        if not c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                            break
                        username = f"{base_username}{counter}"
                        counter += 1
                        
                    now = time.time()
                    # Determine role from email
                    role = 'admin' if email.lower() in config.DEFAULT_ADMIN_EMAILS else 'user'
                    c.execute("INSERT INTO users(username, email, password_hash, session_token, created_at, role) VALUES(?,?,?,?,?,?)", 
                              (username, email, "", "", now, role))
                    is_new_user = True
            
            # Generate new session token
            token = secrets.token_hex(32)
            c.execute("UPDATE users SET session_token=? WHERE username=?", (token, username))
            c.commit()
            
            # Get the user's role
            if is_new_user:
                role = 'admin' if email.lower() in config.DEFAULT_ADMIN_EMAILS else 'user'
            else:
                role_row = c.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
                role = (role_row["role"] or "user") if role_row else "user"
            
            return True, token, username, role
        except Exception as e:
            return False, str(e), "", "user"
        finally:
            c.close()

def get_user_from_token(token: str) -> str | None:
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT username FROM users WHERE session_token=?", (token,)).fetchone()
            return row["username"] if row else None
        finally:
            c.close()


def _auto_create_user_key(c: sqlite3.Connection, username: str, now: float) -> None:
    """Auto-create an API key for a new user with default token limit.
    Must be called within an existing lock+connection."""
    key = "sk-" + secrets.token_hex(32)
    token_limit = config.DEFAULT_TOKEN_LIMIT
    c.execute("""
        INSERT INTO api_keys(key, name, expires_at, rpm_limit, created_at, owner_username, allowed_models, token_limit, tokens_used, token_reset_period, token_last_reset)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, 0, 'weekly', ?)
    """, (key, f"{username}'s Key", None, 60, now, username, None, token_limit, now))


def get_user_role(username: str) -> str:
    """Get the role for a user. Returns 'admin' or 'user'."""
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
            return (row["role"] or "user") if row else "user"
        finally:
            c.close()


def set_user_role(username: str, role: str) -> bool:
    """Set the role for a user. Only 'admin' and 'user' are valid."""
    if role not in ("admin", "user"):
        return False
    with _lock:
        c = _open()
        try:
            existing = c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
            if not existing:
                return False
            c.execute("UPDATE users SET role=? WHERE username=?", (role, username))
            c.commit()
            return True
        finally:
            c.close()


def get_full_user_by_token(token: str) -> dict | None:
    """Get full user info (username, email, role, created_at) from session token."""
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT username, email, role, created_at FROM users WHERE session_token=?", (token,)).fetchone()
            if not row:
                return None
            return {
                "username": row["username"],
                "email": row["email"],
                "role": row["role"] or "user",
                "created_at": row["created_at"],
            }
        finally:
            c.close()

def get_all_users() -> list[dict]:
    with _lock:
        c = _open()
        try:
            # Join with api_keys to get detailed usage
            rows = c.execute("""
                SELECT u.username, u.email, u.created_at, u.role,
                       k.key, k.rpm_limit, k.expires_at, k.allowed_models,
                       k.token_limit, k.tokens_used, k.token_reset_period, k.token_last_reset
                FROM users u
                LEFT JOIN api_keys k ON u.username = k.owner_username
                ORDER BY u.created_at DESC
            """).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()

def delete_user(username: str) -> bool:
    with _lock:
        c = _open()
        try:
            # Delete user
            cur = c.execute("DELETE FROM users WHERE username=?", (username,))
            if cur.rowcount == 0:
                return False
            
            # Find and delete all keys belonging to this user
            keys = c.execute("SELECT key FROM api_keys WHERE owner_username=?", (username,)).fetchall()
            for key_row in keys:
                key = key_row["key"]
                c.execute("DELETE FROM rate_limits WHERE key=?", (key,))
                c.execute("DELETE FROM api_keys WHERE key=?", (key,))
                
            c.commit()
            return True
        finally:
            c.close()

def create_or_update_user_key(username: str, rpm_limit: int, expires_in_days: int | None, allowed_models: str | None, default_token_limit: int | None = 1_000_000) -> dict:
    """Creates or updates the single key for a user.
    default_token_limit: default token quota for new keys (default 1M tokens)."""
    with _lock:
        c = _open()
        try:
            # Enforce max RPM
            if rpm_limit > 60:
                rpm_limit = 60
                
            now = time.time()
            expires_at = now + (expires_in_days * 86400) if expires_in_days else None
            
            # Check if user already has a key
            existing = c.execute("SELECT key FROM api_keys WHERE owner_username=?", (username,)).fetchone()
            if existing:
                key = existing["key"]
                c.execute("""
                    UPDATE api_keys 
                    SET rpm_limit=?, expires_at=?, allowed_models=?
                    WHERE key=?
                """, (rpm_limit, expires_at, allowed_models, key))
            else:
                key = "sk-" + secrets.token_hex(32)
                c.execute("""
                    INSERT INTO api_keys(key, name, expires_at, rpm_limit, created_at, owner_username, allowed_models, token_limit, token_last_reset)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (key, f"{username}'s Key", expires_at, rpm_limit, now, username, allowed_models, default_token_limit, now))
            
            c.commit()
            return {"key": key, "rpm_limit": rpm_limit, "expires_at": expires_at, "allowed_models": allowed_models}
        finally:
            c.close()

def admin_update_user_key(username: str, rpm_limit: int | None = None, expires_in_days: int | None = None, allowed_models: str | None = None) -> bool:
    with _lock:
        c = _open()
        try:
            existing = c.execute("SELECT key, rpm_limit, expires_at, allowed_models FROM api_keys WHERE owner_username=?", (username,)).fetchone()
            if not existing:
                return False
                
            new_rpm = rpm_limit if rpm_limit is not None else existing["rpm_limit"]
            new_expires = (time.time() + (expires_in_days * 86400)) if expires_in_days is not None else existing["expires_at"]
            new_models = allowed_models if allowed_models is not None else existing["allowed_models"]
            
            c.execute("""
                UPDATE api_keys 
                SET rpm_limit=?, expires_at=?, allowed_models=?
                WHERE key=?
            """, (new_rpm, new_expires, new_models, existing["key"]))
            c.commit()
            return True
        finally:
            c.close()

def get_user_key(username: str) -> dict | None:
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT * FROM api_keys WHERE owner_username=?", (username,)).fetchone()
            return dict(row) if row else None
        finally:
            c.close()

def create_key(key: str, name: str | None = None, expires_at: float | None = None, rpm_limit: int | None = None) -> dict:
    with _lock:
        c = _open()
        try:
            now = time.time()
            c.execute(
                "INSERT INTO api_keys(key, name, expires_at, rpm_limit, created_at, token_limit, tokens_used, token_reset_period, token_last_reset) VALUES(?,?,?,?,?,?,?,?,?)",
                (key, name, expires_at, rpm_limit, now, config.DEFAULT_TOKEN_LIMIT, 0, 'weekly', now),
            )
            c.commit()
            return get_key(key)
        finally:
            c.close()

def admin_update_key(key: str, name: str | None = None, rpm_limit: int | None = None, expires_in_days: int | None = None, allowed_models: str | None = None) -> bool:
    with _lock:
        c = _open()
        try:
            existing = c.execute("SELECT name, rpm_limit, expires_at, allowed_models FROM api_keys WHERE key=?", (key,)).fetchone()
            if not existing:
                return False
                
            new_name = name if name is not None else existing["name"]
            new_rpm = rpm_limit if rpm_limit is not None else existing["rpm_limit"]
            new_expires = (time.time() + (expires_in_days * 86400)) if expires_in_days is not None else existing["expires_at"]
            new_models = allowed_models if allowed_models is not None else existing["allowed_models"]
            
            c.execute("""
                UPDATE api_keys 
                SET name=?, rpm_limit=?, expires_at=?, allowed_models=?
                WHERE key=?
            """, (new_name, new_rpm, new_expires, new_models, key))
            c.commit()
            return True
        finally:
            c.close()

def get_key(key: str) -> dict | None:
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
            return dict(row) if row else None
        finally:
            c.close()

def get_username_from_key(key: str) -> str | None:
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT owner_username FROM api_keys WHERE key=?", (key,)).fetchone()
            return row["owner_username"] if row and row["owner_username"] else None
        finally:
            c.close()

def list_keys() -> list[dict]:
    with _lock:
        c = _open()
        try:
            rows = c.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()

def delete_key(key: str) -> bool:
    with _lock:
        c = _open()
        try:
            cur = c.execute("DELETE FROM api_keys WHERE key=?", (key,))
            c.execute("DELETE FROM rate_limits WHERE key=?", (key,)) # cleanup history
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()

def validate_and_track_usage(key: str, model: str) -> tuple[bool, str]:
    """
    Validates a key against expiration dates, rate limits, token limits, and allowed models.
    Returns (True, "") if valid.
    Returns (False, "reason") if invalid, expired, or rate-limited.
    """
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
            if not row:
                return False, "Invalid API key"
            
            allowed_models = row["allowed_models"]
            if allowed_models:
                models_list = [m.strip().lower() for m in allowed_models.split(",") if m.strip()]
                if models_list and model.lower() not in models_list:
                    return False, f"Model '{model}' is not allowed for this API key"

            
            now = time.time()
            if row["expires_at"] and now > row["expires_at"]:
                return False, "API key has expired"
            
            # --- Token limit check ---
            token_limit = row["token_limit"]
            if token_limit is not None:
                # Auto-reset check
                _auto_reset_if_needed(c, key, row)
                # Re-read after possible reset
                row = c.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
                tokens_used = row["tokens_used"] or 0
                if tokens_used >= token_limit:
                    return False, f"Token quota exceeded ({tokens_used}/{token_limit} tokens used)"
            
            rpm_limit = row["rpm_limit"]
            if rpm_limit is not None:
                current_minute = math.floor(now / 60)
                # Cleanup old limits to prevent DB bloat
                c.execute("DELETE FROM rate_limits WHERE minute_timestamp < ?", (current_minute - 1,))
                
                limit_row = c.execute(
                    "SELECT count FROM rate_limits WHERE key=? AND minute_timestamp=?", 
                    (key, current_minute)
                ).fetchone()
                
                count = limit_row["count"] if limit_row else 0
                if count >= rpm_limit:
                    return False, f"Rate limit exceeded ({rpm_limit} req/min)"
                
                # Increment counter
                c.execute(
                    """
                    INSERT INTO rate_limits(key, minute_timestamp, count) 
                    VALUES(?, ?, 1)
                    ON CONFLICT(key, minute_timestamp) 
                    DO UPDATE SET count=count+1
                    """,
                    (key, current_minute)
                )
                c.commit()
                
            return True, ""
        finally:
            c.close()

def reset_limit(key: str) -> bool:
    """
    Instantly resets the rate limit count for a specific key.
    """
    with _lock:
        c = _open()
        try:
            cur = c.execute("DELETE FROM rate_limits WHERE key=?", (key,))
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()


# --- Token Quota Functions ---------------------------------------------------

def _auto_reset_if_needed(c: sqlite3.Connection, key: str, row) -> None:
    """Check if token usage should be auto-reset based on the reset period.
    Called within an existing lock+connection."""
    reset_period = row["token_reset_period"] or "weekly"
    last_reset = row["token_last_reset"] or row["created_at"] or 0
    now = time.time()
    
    period_seconds = {
        "daily": 86400,
        "weekly": 7 * 86400,
        "biweekly": 14 * 86400,
        "monthly": 30 * 86400,
        "never": float("inf"),
    }
    interval = period_seconds.get(reset_period, 7 * 86400)
    
    if now - last_reset >= interval:
        c.execute("UPDATE api_keys SET tokens_used=0, token_last_reset=? WHERE key=?", (now, key))
        c.commit()


def consume_tokens(key: str, count: int) -> bool:
    """Add `count` tokens to the usage for this key. Returns True if successful."""
    if count <= 0:
        return True
    with _lock:
        c = _open()
        try:
            c.execute("UPDATE api_keys SET tokens_used = COALESCE(tokens_used, 0) + ? WHERE key=?", (count, key))
            c.commit()
            return True
        finally:
            c.close()


def get_token_usage(key: str) -> dict | None:
    """Get token limit and usage for a key."""
    with _lock:
        c = _open()
        try:
            row = c.execute(
                "SELECT token_limit, tokens_used, token_reset_period, token_last_reset FROM api_keys WHERE key=?",
                (key,)
            ).fetchone()
            if not row:
                return None
            return {
                "token_limit": row["token_limit"],
                "tokens_used": row["tokens_used"] or 0,
                "token_reset_period": row["token_reset_period"] or "weekly",
                "token_last_reset": row["token_last_reset"],
            }
        finally:
            c.close()


def get_token_usage_by_username(username: str) -> dict | None:
    """Get token usage for a user's key."""
    with _lock:
        c = _open()
        try:
            row = c.execute(
                "SELECT token_limit, tokens_used, token_reset_period, token_last_reset, key FROM api_keys WHERE owner_username=?",
                (username,)
            ).fetchone()
            if not row:
                return None
            return {
                "token_limit": row["token_limit"],
                "tokens_used": row["tokens_used"] or 0,
                "token_reset_period": row["token_reset_period"] or "weekly",
                "token_last_reset": row["token_last_reset"],
                "key": row["key"],
            }
        finally:
            c.close()


def get_total_system_tokens() -> int:
    """Get the sum of all tokens used across all api keys."""
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT SUM(tokens_used) as total FROM api_keys").fetchone()
            return row["total"] or 0
        finally:
            c.close()


def admin_set_token_limit(key: str, token_limit: int | None, reset_period: str | None = None) -> bool:
    """Set or remove the token limit for a key. None = unlimited."""
    with _lock:
        c = _open()
        try:
            existing = c.execute("SELECT 1 FROM api_keys WHERE key=?", (key,)).fetchone()
            if not existing:
                return False
            if reset_period:
                c.execute("UPDATE api_keys SET token_limit=?, token_reset_period=? WHERE key=?", 
                          (token_limit, reset_period, key))
            else:
                c.execute("UPDATE api_keys SET token_limit=? WHERE key=?", (token_limit, key))
            c.commit()
            return True
        finally:
            c.close()


def admin_set_token_limit_by_username(username: str, token_limit: int | None, reset_period: str | None = None) -> bool:
    """Set token limit for a user's key by username."""
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT key FROM api_keys WHERE owner_username=?", (username,)).fetchone()
            if not row:
                return False
            key = row["key"]
            if reset_period:
                c.execute("UPDATE api_keys SET token_limit=?, token_reset_period=? WHERE key=?", 
                          (token_limit, reset_period, key))
            else:
                c.execute("UPDATE api_keys SET token_limit=? WHERE key=?", (token_limit, key))
            c.commit()
            return True
        finally:
            c.close()


def admin_reset_tokens(key: str) -> bool:
    """Reset tokens_used to 0 for a key."""
    with _lock:
        c = _open()
        try:
            c.execute("UPDATE api_keys SET tokens_used=0, token_last_reset=? WHERE key=?", (time.time(), key))
            c.commit()
            return True
        finally:
            c.close()


def admin_reset_tokens_by_username(username: str) -> bool:
    """Reset tokens_used for a user's key."""
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT key FROM api_keys WHERE owner_username=?", (username,)).fetchone()
            if not row:
                return False
            c.execute("UPDATE api_keys SET tokens_used=0, token_last_reset=? WHERE key=?", (time.time(), row["key"]))
            c.commit()
            return True
        finally:
            c.close()


def admin_add_tokens(key: str, amount: int) -> bool:
    """Increase the token_limit by `amount` for a key."""
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT token_limit FROM api_keys WHERE key=?", (key,)).fetchone()
            if not row:
                return False
            current = row["token_limit"] or 0
            c.execute("UPDATE api_keys SET token_limit=? WHERE key=?", (current + amount, key))
            c.commit()
            return True
        finally:
            c.close()


def admin_add_tokens_by_username(username: str, amount: int) -> bool:
    """Increase token_limit for a user's key by username."""
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT key, token_limit FROM api_keys WHERE owner_username=?", (username,)).fetchone()
            if not row:
                return False
            current = row["token_limit"] or 0
            c.execute("UPDATE api_keys SET token_limit=? WHERE key=?", (current + amount, row["key"]))
            c.commit()
            return True
        finally:
            c.close()


def estimate_tokens(text: str) -> int:
    """Rough token estimation: ~4 chars per token for English, ~2 for CJK/Thai."""
    if not text:
        return 0
    # A simple heuristic: count by words and characters
    # Average English: ~0.75 tokens per word, or ~4 chars per token
    # For mixed content, use ~3.5 chars per token
    return max(1, len(text) // 4)


def log_usage(client_key: str, model: str, tokens: int, is_success: bool, latency_ms: int):
    """Logs usage for a specific request."""
    with _lock:
        c = _open()
        try:
            # Get username from key
            row = c.execute("SELECT owner_username FROM api_keys WHERE key=?", (client_key,)).fetchone()
            if not row or not row["owner_username"]:
                return
            username = row["owner_username"]
            
            # Format date as YYYY-MM-DD
            import datetime
            date_str = datetime.datetime.now().strftime("%Y-%m-%d")
            
            success_int = 1 if is_success else 0
            
            # Upsert
            c.execute("""
                INSERT INTO usage_logs(date, username, model, requests, tokens, success, total_latency_ms)
                VALUES(?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(date, username, model) DO UPDATE SET
                    requests = requests + 1,
                    tokens = tokens + ?,
                    success = success + ?,
                    total_latency_ms = total_latency_ms + ?
            """, (date_str, username, model, tokens, success_int, latency_ms, tokens, success_int, latency_ms))
            
            c.commit()
        finally:
            c.close()

def get_usage_stats(username: str, days: int = 90) -> list[dict]:
    """Get usage stats for a specific user for the last N days."""
    with _lock:
        c = _open()
        try:
            import datetime
            cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
            rows = c.execute("""
                SELECT date, model, SUM(requests) as requests, SUM(tokens) as tokens, 
                       SUM(success) as success, SUM(total_latency_ms) as total_latency_ms
                FROM usage_logs
                WHERE username=? AND date >= ?
                GROUP BY date, model
                ORDER BY date ASC
            """, (username, cutoff_date)).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()

def admin_get_usage_stats(days: int = 90) -> list[dict]:
    """Get total usage stats for all users for the last N days."""
    with _lock:
        c = _open()
        try:
            import datetime
            cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
            rows = c.execute("""
                SELECT date, model, SUM(requests) as requests, SUM(tokens) as tokens, 
                       SUM(success) as success, SUM(total_latency_ms) as total_latency_ms
                FROM usage_logs
                WHERE date >= ?
                GROUP BY date, model
                ORDER BY date ASC
            """, (cutoff_date,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()

def insert_request_log(key: str, req_id: str, model: str, method: str, url: str, is_success: bool, input_tokens: int, output_tokens: int, latency_ms: int):
    username = get_username_from_key(key)
    if not username:
        return
    with _lock:
        c = _open()
        try:
            c.execute('''
                INSERT INTO request_logs(id, username, model, method, url, is_success, input_tokens, output_tokens, latency_ms, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (req_id, username, model, method, url, 1 if is_success else 0, input_tokens, output_tokens, latency_ms, time.time()))
            
            # Cleanup old logs (> 7 days)
            cutoff = time.time() - (7 * 24 * 60 * 60)
            c.execute('DELETE FROM request_logs WHERE created_at < ?', (cutoff,))
            
            c.commit()
        finally:
            c.close()

def _merge_prompt_logs(logs: list[dict], window_seconds: int = 90) -> list[dict]:
    """Merge nearby gateway calls from one prompt into a single display row."""
    merged: list[dict] = []

    for log in logs:
        if not merged:
            merged.append({**log, "request_count": 1})
            continue

        last = merged[-1]
        same_user = last.get("username") == log.get("username")
        same_model = last.get("model") == log.get("model")
        same_route = last.get("method") == log.get("method") and last.get("url") == log.get("url")
        close_enough = abs(float(last.get("created_at", 0)) - float(log.get("created_at", 0))) <= window_seconds

        if same_user and same_model and same_route and close_enough:
            last["input_tokens"] = int(last.get("input_tokens") or 0) + int(log.get("input_tokens") or 0)
            last["output_tokens"] = int(last.get("output_tokens") or 0) + int(log.get("output_tokens") or 0)
            last["latency_ms"] = int(last.get("latency_ms") or 0) + int(log.get("latency_ms") or 0)
            last["is_success"] = bool(last.get("is_success")) and bool(log.get("is_success"))
            last["request_count"] = int(last.get("request_count") or 1) + 1
        else:
            merged.append({**log, "request_count": 1})

    return merged


def get_request_logs(username: str, limit: int = 50, offset: int = 0):
    with _lock:
        c = _open()
        try:
            rows = c.execute('SELECT id, username, model, method, url, is_success, input_tokens, output_tokens, latency_ms, created_at FROM request_logs WHERE username = ? ORDER BY created_at DESC LIMIT ? OFFSET ?', (username, limit, offset)).fetchall()

            total = c.execute('SELECT COUNT(*) FROM request_logs WHERE username = ?', (username,)).fetchone()[0]

            logs = [
                {
                    "id": r[0],
                    "username": r[1],
                    "model": r[2],
                    "method": r[3],
                    "url": r[4],
                    "is_success": bool(r[5]),
                    "input_tokens": r[6],
                    "output_tokens": r[7],
                    "latency_ms": r[8],
                    "created_at": r[9]
                }
                for r in rows
            ]
            merged_logs = _merge_prompt_logs(logs)

            return {
                "logs": merged_logs,
                "total": total
            }
        finally:
            c.close()

def admin_get_request_logs(limit: int = 50, offset: int = 0):
    with _lock:
        c = _open()
        try:
            rows = c.execute('SELECT id, username, model, method, url, is_success, input_tokens, output_tokens, latency_ms, created_at FROM request_logs ORDER BY created_at DESC LIMIT ? OFFSET ?', (limit, offset)).fetchall()
            
            total = c.execute('SELECT COUNT(*) FROM request_logs').fetchone()[0]
            
            logs = [
                {
                    "id": r[0],
                    "username": r[1],
                    "model": r[2],
                    "method": r[3],
                    "url": r[4],
                    "is_success": bool(r[5]),
                    "input_tokens": r[6],
                    "output_tokens": r[7],
                    "latency_ms": r[8],
                    "created_at": r[9]
                }
                for r in rows
            ]
            merged_logs = _merge_prompt_logs(logs)

            return {
                "logs": merged_logs,
                "total": total
            }
        finally:
            c.close()


def get_model_status_blocks(time_window_minutes: int = 60) -> dict[str, list[int]]:
    """
    Aggregate request_logs into per-minute status blocks for each model.

    Returns a dict: { model_id: [block0, block1, ..., block59] }
    Each block is:
      1 = Healthy  (success rate >= 90% or no traffic)
      3 = Degraded  (50–89%)
      2 = Warning   (20–49%)
      0 = Down      (< 20%)
    block0 is the oldest minute, block[-1] is the most recent.
    """
    now = time.time()
    window_start = now - (time_window_minutes * 60)

    with _lock:
        c = _open()
        try:
            rows = c.execute(
                """
                SELECT model,
                       CAST((created_at - ?) / 60 AS INTEGER) AS minute_bucket,
                       COUNT(*) AS total,
                       SUM(CASE WHEN is_success = 1 THEN 1 ELSE 0 END) AS successes
                FROM request_logs
                WHERE created_at >= ?
                GROUP BY model, minute_bucket
                """,
                (window_start, window_start),
            ).fetchall()

            # Build a nested dict: { model: { minute_bucket: (total, successes) } }
            model_minutes: dict[str, dict[int, tuple[int, int]]] = {}
            for r in rows:
                model_id = r[0]
                bucket = r[1]
                total = r[2]
                successes = r[3]
                if model_id not in model_minutes:
                    model_minutes[model_id] = {}
                model_minutes[model_id][bucket] = (total, successes)

            # Convert to status blocks (0..time_window_minutes-1)
            result: dict[str, list[int]] = {}
            for model_id, minutes in model_minutes.items():
                blocks: list[int] = []
                for i in range(time_window_minutes):
                    if i in minutes:
                        total, successes = minutes[i]
                        rate = successes / total if total > 0 else 1.0
                        if rate >= 0.9:
                            blocks.append(1)   # Healthy
                        elif rate >= 0.5:
                            blocks.append(3)   # Degraded (light green)
                        elif rate >= 0.2:
                            blocks.append(2)   # Warning (orange)
                        else:
                            blocks.append(0)   # Down (red)
                    else:
                        blocks.append(1)  # No traffic = assume healthy
                result[model_id] = blocks

            return result
        finally:
            c.close()


def get_user_notifications(username: str) -> list[dict]:
    """
    Generate dynamic notifications for the user.
    """
    notifications = []
    now = time.time()
    
    with _lock:
        c = _open()
        try:
            # Find the user's primary key
            row = c.execute("SELECT * FROM api_keys WHERE owner_username=?", (username,)).fetchone()
            if not row:
                return []
            
            key = row["key"]
            
            # Check Token Limits
            token_limit = row["token_limit"]
            tokens_used = row["tokens_used"] or 0
            
            if token_limit and token_limit > 0:
                if tokens_used >= token_limit:
                    notifications.append({
                        "id": "token-exceeded",
                        "title": "Token Quota Exceeded",
                        "message": f"You have reached your limit of {token_limit:,} tokens.",
                        "type": "error",
                        "date": int(now * 1000)
                    })
                elif tokens_used >= token_limit * 0.8:
                    notifications.append({
                        "id": "token-low",
                        "title": "Low Token Balance",
                        "message": f"You have used {tokens_used:,} of {token_limit:,} tokens ({(tokens_used/token_limit)*100:.1f}%).",
                        "type": "warning",
                        "date": int(now * 1000)
                    })
            
            # Check Key Expiration
            expires_at = row["expires_at"]
            if expires_at:
                days_left = (expires_at - now) / 86400
                if days_left < 0:
                    notifications.append({
                        "id": "key-expired",
                        "title": "API Key Expired",
                        "message": "Your API key has expired and can no longer be used.",
                        "type": "error",
                        "date": int(now * 1000)
                    })
                elif days_left <= 3:
                    notifications.append({
                        "id": "key-expiring",
                        "title": "API Key Expiring Soon",
                        "message": f"Your API key will expire in {int(days_left)} days.",
                        "type": "warning",
                        "date": int(now * 1000)
                    })
            
            # Check RPM Limits (Current Minute)
            rpm_limit = row["rpm_limit"]
            if rpm_limit is not None:
                current_minute = math.floor(now / 60)
                limit_row = c.execute(
                    "SELECT count FROM rate_limits WHERE key=? AND minute_timestamp=?", 
                    (key, current_minute)
                ).fetchone()
                
                count = limit_row["count"] if limit_row else 0
                if count >= rpm_limit:
                    notifications.append({
                        "id": "rpm-limit",
                        "title": "Rate Limit Reached",
                        "message": f"You have hit your {rpm_limit} RPM limit. Requests are being throttled.",
                        "type": "error",
                        "date": int(now * 1000)
                    })
                    
            return notifications
        finally:
            c.close()
