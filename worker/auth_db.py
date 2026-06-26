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

    c.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits(
            key TEXT,
            minute_timestamp INTEGER,
            count INTEGER,
            PRIMARY KEY (key, minute_timestamp)
        )""")
    return c

import bcrypt
import secrets
import time

def register_user(username: str, password: str, email: str | None = None) -> tuple[bool, str]:
    with _lock:
        c = _open()
        try:
            if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                return False, "Username already exists"
            
            pwd_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            token = secrets.token_hex(32)
            now = time.time()
            c.execute("INSERT INTO users(username, email, password_hash, session_token, created_at) VALUES(?,?,?,?,?)", 
                      (username, email, pwd_hash, token, now))
            c.commit()

            return True, token
        finally:
            c.close()

def login_user(username: str, password: str) -> tuple[bool, str]:
    with _lock:
        c = _open()
        try:
            row = c.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
            if not row or not bcrypt.checkpw(password.encode('utf-8'), row["password_hash"].encode('utf-8')):
                return False, "Invalid username or password"
            
            token = secrets.token_hex(32)
            c.execute("UPDATE users SET session_token=? WHERE username=?", (token, username))
            c.commit()
            return True, token
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

def get_all_users() -> list[dict]:
    with _lock:
        c = _open()
        try:
            # Exclude password_hash and session_token for security
            rows = c.execute("SELECT username, email, created_at FROM users ORDER BY created_at DESC").fetchall()
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

def create_or_update_user_key(username: str, rpm_limit: int, expires_in_days: int | None, allowed_models: str | None) -> dict:
    """Creates or updates the single key for a user."""
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
                    INSERT INTO api_keys(key, name, expires_at, rpm_limit, created_at, owner_username, allowed_models)
                    VALUES(?, ?, ?, ?, ?, ?, ?)
                """, (key, f"{username}'s Key", expires_at, rpm_limit, now, username, allowed_models))
            
            c.commit()
            return {"key": key, "rpm_limit": rpm_limit, "expires_at": expires_at, "allowed_models": allowed_models}
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
            c.execute(
                "INSERT INTO api_keys(key, name, expires_at, rpm_limit, created_at) VALUES(?,?,?,?,?)",
                (key, name, expires_at, rpm_limit, time.time()),
            )
            c.commit()
            return get_key(key)
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
    Validates a key against expiration dates, rate limits, and allowed models.
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
