import sqlite3
import os
import logging
from datetime import datetime
from crypto import encrypt_aes256, decrypt_aes256

DB_FILE = os.environ.get("DB_FILE", "userbot.db")
logger = logging.getLogger("Database")

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        user_id INTEGER PRIMARY KEY,
        phone TEXT UNIQUE NOT NULL,
        api_id INTEGER NOT NULL,
        encrypted_api_hash TEXT NOT NULL,
        encrypted_session TEXT NOT NULL,
        first_name TEXT,
        username TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        last_active_at TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS unauthorized_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        phone_attempted TEXT,
        action TEXT NOT NULL,
        ip_address TEXT,
        reason TEXT NOT NULL,
        severity TEXT DEFAULT 'HIGH',
        timestamp TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event TEXT NOT NULL,
        details TEXT,
        severity TEXT DEFAULT 'INFO',
        timestamp TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def save_user_session(user_id: int, phone: str, api_id: int, api_hash: str, session_string: str, first_name: str = "", username: str = ""):
    enc_hash = encrypt_aes256(api_hash)
    enc_session = encrypt_aes256(session_string)
    now = datetime.utcnow().isoformat()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO sessions (user_id, phone, api_id, encrypted_api_hash, encrypted_session, first_name, username, is_active, created_at, last_active_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
        phone=excluded.phone,
        api_id=excluded.api_id,
        encrypted_api_hash=excluded.encrypted_api_hash,
        encrypted_session=excluded.encrypted_session,
        first_name=excluded.first_name,
        username=excluded.username,
        is_active=1,
        last_active_at=excluded.last_active_at
    """, (user_id, phone, api_id, enc_hash, enc_session, first_name, username, now, now))
    conn.commit()
    conn.close()

def get_user_session(user_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    try:
        return {
            "user_id": row["user_id"],
            "phone": row["phone"],
            "api_id": row["api_id"],
            "api_hash": decrypt_aes256(row["encrypted_api_hash"]),
            "session_string": decrypt_aes256(row["encrypted_session"]),
            "first_name": row["first_name"],
            "username": row["username"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"]
        }
    except Exception:
        return None

def get_all_active_sessions():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE is_active = 1")
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        try:
            results.append({
                "user_id": r["user_id"],
                "phone": r["phone"],
                "api_id": r["api_id"],
                "api_hash": decrypt_aes256(r["encrypted_api_hash"]),
                "session_string": decrypt_aes256(r["encrypted_session"]),
                "first_name": r["first_name"],
                "username": r["username"]
            })
        except Exception:
            pass
    return results

def log_unauthorized_attempt(user_id: int, username: str, phone_attempted: str, action: str, reason: str, ip_address: str = "MTProto", severity: str = "HIGH"):
    now = datetime.utcnow().isoformat()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO unauthorized_attempts (user_id, username, phone_attempted, action, ip_address, reason, severity, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, phone_attempted, action, ip_address, reason, severity, now))
    conn.commit()
    conn.close()
    try:
        with open("security_audit.log", "a", encoding="utf-8") as f:
            f.write(f"[{now}] [UNAUTHORIZED_ATTEMPT] UserID={user_id} (@{username}) Action={action} Reason={reason}\n")
    except Exception:
        pass

def get_recent_unauthorized_attempts(limit: int = 50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM unauthorized_attempts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

init_db()
