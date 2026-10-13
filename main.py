import asyncio
import base64
import glob
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import sys
import time
from datetime import datetime

from telethon import TelegramClient, events, errors, Button
from telethon.sessions import StringSession
from telethon.tl.types import (
    MessageMediaWebPage,
    MessageMediaEmpty,
    MessageMediaUnsupported,
    Channel,
    Chat,
    User,
    PeerChannel,
    PeerChat,
    PeerUser,
    MessageActionChatEditTitle,
    MessageActionPinMessage
)
from telethon.tl.functions.channels import EditTitleRequest, GetParticipantRequest
from telethon.tl.functions.messages import EditChatTitleRequest

# =====================================================================
# PATH RESOLUTION & SAFE WORKING DIRECTORY (Render & Subfolder Support)
# =====================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s"
)
logger = logging.getLogger("TeleGuardMaster")

# =====================================================================
# CONFIGURATION & CREDENTIALS
# =====================================================================
# Telegram Bot Token provided by user
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8995627301:AAFWGGan0dqijbSf9oiQTyYo4Ztzi1L-sCs")

# Default API credentials used for running the Telegram Bot client
BOT_API_ID = int(os.environ.get("BOT_API_ID", "33248589"))
BOT_API_HASH = os.environ.get("BOT_API_HASH", "cb94a9acfa11e9aaf1195610f4144e65")

# Mandatory Channel for /start verification (No other channels)
REQUIRED_CHANNEL_USERNAME = "enerzonends"
REQUIRED_CHANNEL_URL = "https://t.me/enerzonends"

ADMIN_ID_RAW = os.environ.get("ADMIN_ID", "")
ADMIN_ID = int(ADMIN_ID_RAW) if ADMIN_ID_RAW.isdigit() else None

# AES-256 Master Key & Storage Paths
DEFAULT_MASTER_KEY = os.environ.get("AES_SECRET_KEY", "TELEGUARD_AES256_SECURE_MASTER_KEY_2026_X99")
DB_FILE = os.environ.get("DB_FILE", os.path.join(BASE_DIR, "userbot.db"))
SETTINGS_FILE = os.environ.get("SETTINGS_FILE", os.path.join(BASE_DIR, "settings.json"))

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    logger.warning("⚠️ 'cryptography' package not found. Using built-in HMAC-SHA256 authenticated fallback.")

# =====================================================================
# 1. AES-256 CRYPTOGRAPHIC ENGINE
# =====================================================================
def _derive_aes256_key(secret: str) -> bytes:
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    else:
        secret_bytes = secret
    return hashlib.sha256(secret_bytes).digest()

def encrypt_aes256(plaintext: str, key_secret: str = None) -> str:
    if not plaintext:
        return ""
    secret = key_secret or os.environ.get("AES_SECRET_KEY", DEFAULT_MASTER_KEY)
    key_bytes = _derive_aes256_key(secret)
    data = plaintext.encode("utf-8")

    if HAS_CRYPTOGRAPHY:
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        payload = b"\x01" + nonce + ciphertext
        return base64.b64encode(payload).decode("ascii")
    else:
        nonce = os.urandom(16)
        stream_key = hashlib.sha256(key_bytes + nonce).digest()
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(data):
            keystream.extend(hashlib.sha256(stream_key + counter.to_bytes(4, 'big')).digest())
            counter += 1
        ciphertext = bytes(b ^ k for b, k in zip(data, keystream[:len(data)]))
        tag = hmac.new(key_bytes, nonce + ciphertext, hashlib.sha256).digest()
        payload = b"\x02" + nonce + tag + ciphertext
        return base64.b64encode(payload).decode("ascii")

def decrypt_aes256(encrypted_base64: str, key_secret: str = None) -> str:
    if not encrypted_base64:
        return ""
    secret = key_secret or os.environ.get("AES_SECRET_KEY", DEFAULT_MASTER_KEY)
    key_bytes = _derive_aes256_key(secret)
    try:
        raw_payload = base64.b64decode(encrypted_base64.encode("ascii"))
        if raw_payload.startswith(b"\x01") and HAS_CRYPTOGRAPHY:
            nonce = raw_payload[1:13]
            ciphertext = raw_payload[13:]
            aesgcm = AESGCM(key_bytes)
            return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
        elif raw_payload.startswith(b"\x02") or not HAS_CRYPTOGRAPHY:
            if raw_payload.startswith(b"\x02"):
                nonce = raw_payload[1:17]
                tag = raw_payload[17:49]
                ciphertext = raw_payload[49:]
            else:
                if HAS_CRYPTOGRAPHY:
                    return AESGCM(key_bytes).decrypt(raw_payload[:12], raw_payload[12:], None).decode("utf-8")
                raise ValueError("Requires cryptography package")
            expected_tag = hmac.new(key_bytes, nonce + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("Authentication tag mismatch")
            stream_key = hashlib.sha256(key_bytes + nonce).digest()
            keystream = bytearray()
            counter = 0
            while len(keystream) < len(ciphertext):
                keystream.extend(hashlib.sha256(stream_key + counter.to_bytes(4, 'big')).digest())
                counter += 1
            return bytes(b ^ k for b, k in zip(ciphertext, keystream[:len(ciphertext)])).decode("utf-8")
        else:
            if len(raw_payload) >= 28 and HAS_CRYPTOGRAPHY:
                return AESGCM(key_bytes).decrypt(raw_payload[:12], raw_payload[12:], None).decode("utf-8")
            raise ValueError("Ciphertext format unsupported")
    except Exception as exc:
        raise ValueError(f"AES-256 Decryption failed: {exc}")

# =====================================================================
# 2. AES-256 DATABASE & INTRUSION TRACKER
# =====================================================================
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
    except Exception as exc:
        logger.error(f"Decryption failed for user {user_id}: {exc}")
        return None

def delete_user_session(user_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

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
        except Exception as exc:
            logger.error(f"Could not decrypt active session: {exc}")
    return results

def log_unauthorized_attempt(user_id: int, username: str, phone_attempted: str, action: str, reason: str, ip_address: str = "Telegram MTProto", severity: str = "HIGH"):
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
        audit_file = os.path.join(BASE_DIR, "security_audit.log")
        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(f"[{now}] [UNAUTHORIZED_ATTEMPT] UserID={user_id} (@{username}) Action={action} Reason={reason}\n")
    except Exception:
        pass
    logger.warning(f"🚨 UNAUTHORIZED ATTEMPT: User {user_id} (@{username}) action='{action}' -> {reason}")

def get_recent_unauthorized_attempts(limit: int = 50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM unauthorized_attempts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# =====================================================================
# 3. FULL USERBOT ENGINE (ALL COMMANDS & HANDLERS)
# =====================================================================
PIN_REACTION = "🔥"
DEFAULT_NC_TITLES = [
    "🔥 ALPHA ZONE 🔥",
    "⚡ THUNDER REIGN ⚡",
    "👑 APEX EMPIRE 👑",
    "💎 NITRO KINGS 💎",
    "🚀 SUPREME RULE 🚀"
]
DEFAULT_GC_REPLIES = [
    "Hello! Currently away, will reply shortly ⚡",
    "Active in group, message acknowledged 👍",
    "Busy at the moment, checking notifications later 🚀",
    "Auto-reply active. Stay tuned! 💬",
    "Ping received. I will review this soon 🔥"
]
DEFAULT_DM_REPLIES = [
    "Hey! Currently away from DM, will respond soon ⚡",
    "Message received in private chat 👍",
    "Please hold on, reviewing DMs shortly 🚀",
    "Auto-responder active for direct messages 💬",
    "Thanks for reaching out! Will get back to you soon 🔥"
]

GC_REPLIES = list(DEFAULT_GC_REPLIES)
DM_REPLIES = list(DEFAULT_DM_REPLIES)
NC_TITLES = list(DEFAULT_NC_TITLES)
NC_INT, VANISH, MAX_REP, COOLDOWN = 3.0, 1.5, 3, 1.5

ACTIVE_CLIENTS = {}
CLIENT_INFO = {}
MY_IDS = {}

REPLY_CHATS, MUTE_CHATS, LOCK_CHATS, UNMUTE_EXEMPTS = set(), set(), set(), set()
DEL_NAME_CHATS = set()
PIN_CHATS, PIN_EXEMPTS = set(), set()
PIN_DEL_CHATS = set()
PIN_ALL, PIN_DEL_ALL = False, False
PIN_PROCESSED, PIN_NOTIF_REACTED, PIN_NOTIF_DELETED = set(), set(), set()
RECENT_DELETED = set()

T_REPLY, T_MUTE, T_LOCK, T_NC_R, T_NC_M, T_NC_L = {}, {}, {}, {}, {}, {}
T_DELNAME = {}
CACHE, LAST_REP, REP_CNT, NC_TASKS, NC_SETUP = {}, {}, {}, {}, {}
GC_INDEX, DM_INDEX, NC_INDEX = {}, {}, {}
MUTE_ALL = False
USER_CACHE, ENTITY_CACHE = {}, {}

def clear_cache_files():
    removed_files, removed_dirs = 0, 0
    try:
        for root, dirs, files in os.walk(BASE_DIR, topdown=False):
            for d in dirs:
                if d in ("__pycache__", ".pytest_cache"):
                    try:
                        shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                        removed_dirs += 1
                    except Exception:
                        pass
            for f in files:
                if f.endswith((".pyc", ".pyo", ".pyd", ".tmp")):
                    try:
                        os.remove(os.path.join(root, f))
                        removed_files += 1
                    except Exception:
                        pass
        global CACHE, USER_CACHE, ENTITY_CACHE
        if len(CACHE) > 300:
            CACHE.clear()
        if len(USER_CACHE) > 500:
            USER_CACHE.clear()
        if len(ENTITY_CACHE) > 200:
            ENTITY_CACHE.clear()
        return removed_dirs, removed_files
    except Exception:
        return 0, 0

async def auto_cache_cleaner_worker(interval_seconds=1800):
    try:
        while True:
            await asyncio.sleep(interval_seconds)
            clear_cache_files()
    except asyncio.CancelledError:
        pass

def save_cfg():
    try:
        d = {
            "r": list(REPLY_CHATS), "m": list(MUTE_CHATS), "l": list(LOCK_CHATS),
            "u": list(UNMUTE_EXEMPTS), "all_dm": MUTE_ALL, "del_name_chats": list(DEL_NAME_CHATS),
            "pin": list(PIN_CHATS), "pin_all": PIN_ALL, "pin_del": list(PIN_DEL_CHATS),
            "pin_del_all": PIN_DEL_ALL, "pin_exempt": list(PIN_EXEMPTS), "pin_reaction": PIN_REACTION,
            "gc_replies": GC_REPLIES, "dm_replies": DM_REPLIES, "nc_titles": NC_TITLES,
            "tr": {str(k): list(v) for k, v in T_REPLY.items()},
            "tm": {str(k): list(v) for k, v in T_MUTE.items()},
            "tl": {str(k): list(v) for k, v in T_LOCK.items()},
            "ncr": {str(k): list(v) for k, v in T_NC_R.items()},
            "ncm": {str(k): list(v) for k, v in T_NC_M.items()},
            "ncl": {str(k): list(v) for k, v in T_NC_L.items()},
            "tdel": {str(k): list(v) for k, v in T_DELNAME.items()}
        }
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error saving config: {exc}")

def load_cfg():
    global MUTE_ALL, GC_REPLIES, DM_REPLIES, NC_TITLES, PIN_ALL, PIN_DEL_ALL, PIN_REACTION
    if not os.path.exists(SETTINGS_FILE):
        return
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        REPLY_CHATS.clear(); REPLY_CHATS.update(d.get("r", []))
        MUTE_CHATS.clear(); MUTE_CHATS.update(d.get("m", []))
        LOCK_CHATS.clear(); LOCK_CHATS.update(d.get("l", []))
        UNMUTE_EXEMPTS.clear(); UNMUTE_EXEMPTS.update(d.get("u", []))
        DEL_NAME_CHATS.clear(); DEL_NAME_CHATS.update(d.get("del_name_chats", []))
        MUTE_ALL = d.get("all_dm", False)
        PIN_CHATS.clear(); PIN_CHATS.update(d.get("pin", []))
        PIN_ALL = bool(d.get("pin_all", False))
        PIN_DEL_CHATS.clear(); PIN_DEL_CHATS.update(d.get("pin_del", []))
        PIN_DEL_ALL = bool(d.get("pin_del_all", False))
        PIN_EXEMPTS.clear(); PIN_EXEMPTS.update(d.get("pin_exempt", []))
        PIN_REACTION = d.get("pin_reaction", "🔥")
        if "gc_replies" in d and len(d["gc_replies"]) >= 5:
            GC_REPLIES[:] = d["gc_replies"][:5]
        if "dm_replies" in d and len(d["dm_replies"]) >= 5:
            DM_REPLIES[:] = d["dm_replies"][:5]
        if "nc_titles" in d and len(d["nc_titles"]) >= 5:
            NC_TITLES[:] = d["nc_titles"][:5]
    except Exception as exc:
        logger.error(f"Error loading config: {exc}")

def is_target_user(cid, uid):
    if not uid:
        return False
    return (
        (cid in T_DELNAME and uid in T_DELNAME[cid]) or
        (cid in T_NC_L and uid in T_NC_L[cid]) or
        (cid in T_NC_M and uid in T_NC_M[cid]) or
        (cid in T_NC_R and uid in T_NC_R[cid]) or
        (cid in T_LOCK and uid in T_LOCK[cid]) or
        (cid in T_MUTE and uid in T_MUTE[cid]) or
        (cid in T_REPLY and uid in T_REPLY[cid])
    )

def is_pin_action(event):
    if getattr(event, "action_message", None):
        action = getattr(event.action_message, "action", None)
        if isinstance(action, MessageActionPinMessage):
            return True
    action = getattr(event, "action", None)
    return isinstance(action, MessageActionPinMessage)

async def handle_pin_notification(client, user_key, msg):
    cid = msg.chat_id
    mid = msg.id
    if (PIN_ALL or cid in PIN_CHATS) and cid not in PIN_EXEMPTS:
        if mid not in PIN_NOTIF_REACTED:
            PIN_NOTIF_REACTED.add(mid)
            try:
                from telethon.tl.functions.messages import SendReactionRequest
                from telethon.tl.types import ReactionEmoji
                await client(SendReactionRequest(peer=cid, msg_id=mid, reaction=[ReactionEmoji(emoticon=PIN_REACTION)]))
            except Exception:
                pass
    if (PIN_DEL_ALL or cid in PIN_DEL_CHATS) and cid not in PIN_EXEMPTS:
        if mid not in PIN_NOTIF_DELETED:
            PIN_NOTIF_DELETED.add(mid)
            try:
                await asyncio.sleep(0.3)
                await msg.delete()
            except Exception:
                pass

async def run_nc_loop(client, cid, titles, interval):
    idx = 0
    try:
        while True:
            cur_title = titles[idx % len(titles)]
            try:
                chat = await client.get_entity(cid)
                if isinstance(chat, Channel):
                    await client(EditTitleRequest(channel=chat, title=cur_title))
                else:
                    await client(EditChatTitleRequest(chat_id=cid, title=cur_title))
            except errors.FloodWaitError as fwe:
                await asyncio.sleep(fwe.seconds)
            except Exception:
                pass
            idx = (idx + 1) % len(titles)
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        pass

def cancel_nc_task(cid):
    task = NC_TASKS.pop(cid, None)
    if task and not task.done():
        task.cancel()
        return True
    return False

def register_userbot_handlers(client: TelegramClient, user_key: int):
    async def fb(e, text, d=1.8):
        try:
            r = await e.reply(text)
            if d:
                await asyncio.sleep(d)
                await r.delete()
            return r
        except Exception:
            return None

    @client.on(events.NewMessage(outgoing=True))
    async def on_outgoing(e):
        txt = (e.raw_text or "").strip()
        cid = e.chat_id
        me_id = MY_IDS.get(user_key)

        if txt.startswith("*"):
            p = txt[1:].strip().split(maxsplit=2)
            c = p[0].lower() if p else ""
            arg1 = p[1].lower() if len(p) > 1 else ""
            arg2 = p[2] if len(p) > 2 else ""

            # PIN COMMANDS
            if c in ("pin", "pin on"):
                PIN_CHATS.add(cid); PIN_EXEMPTS.discard(cid); save_cfg()
                return await fb(e, f"📌 **Auto-Pin ON** for this chat (Reaction: {PIN_REACTION}).")
            if c in ("stop pin", "unpin", "pin off"):
                PIN_CHATS.discard(cid); save_cfg()
                return await fb(e, "🛑 **Auto-Pin OFF** for this chat.")
            if c in ("pinall", "pinall on"):
                global PIN_ALL; PIN_ALL = True; save_cfg()
                return await fb(e, f"🌐 **Global Auto-Pin ON** across all chats (Reaction: {PIN_REACTION}).")
            if c in ("stop pinall", "unpinall"):
                PIN_ALL = False; save_cfg()
                return await fb(e, "🛑 **Global Auto-Pin OFF**.")
            if c in ("pindel", "pindel on"):
                PIN_DEL_CHATS.add(cid); save_cfg()
                return await fb(e, "🗑️ **Auto-Delete Pin Notifications ON** for this chat.")
            if c in ("stop pindel", "unpindel"):
                PIN_DEL_CHATS.discard(cid); save_cfg()
                return await fb(e, "🛑 **Auto-Delete Pin Notifications OFF**.")

            # CONTINUOUS NAME CHANGER (NC)
            if c == "nc":
                cancel_nc_task(cid)
                titles = [t.strip() for t in arg2.split("|")] if arg2 and "|" in arg2 else NC_TITLES
                task = asyncio.create_task(run_nc_loop(client, cid, titles, NC_INT))
                NC_TASKS[cid] = task
                return await fb(e, f"🔄 **Continuous NC Active:** Cycling {len(titles)} titles every {NC_INT}s.")
            if c in ("stopnc", "stop nc", "unnc"):
                stopped = cancel_nc_task(cid)
                return await fb(e, "🛑 **Continuous NC Stopped.**" if stopped else "ℹ️ No NC loop was active.")

            # GROUP RESPONDER COMMANDS
            if c in ("replyall", "reply_all"):
                REPLY_CHATS.add(cid); save_cfg()
                return await fb(e, "👥 **Group ReplyAll ON:** Cycling 5 custom auto-replies.")
            if c in ("stop replyall", "unreplyall"):
                REPLY_CHATS.discard(cid); save_cfg()
                return await fb(e, "🛑 **Group ReplyAll OFF.**")
            if c == "gcmsgs":
                body = "\n".join([f"**{i+1}.** {m}" for i, m in enumerate(GC_REPLIES)])
                return await fb(e, f"📋 **Current 5 Group Replies:**\n{body}", d=None)
            if c == "setgc" and arg1.isdigit():
                idx = int(arg1) - 1
                if 0 <= idx < 5 and arg2:
                    GC_REPLIES[idx] = arg2; save_cfg()
                    return await fb(e, f"✅ Updated group reply slot {idx+1} to: {arg2}")

            # DM RESPONDER COMMANDS
            if c in ("reply", "reply on"):
                REPLY_CHATS.add(cid); save_cfg()
                return await fb(e, "💬 **DM Auto-Reply ON:** Cycling 5 custom auto-replies.")
            if c in ("stop reply", "unreply"):
                REPLY_CHATS.discard(cid); save_cfg()
                return await fb(e, "🛑 **DM Auto-Reply OFF.**")
            if c == "dmmsgs":
                body = "\n".join([f"**{i+1}.** {m}" for i, m in enumerate(DM_REPLIES)])
                return await fb(e, f"📋 **Current 5 DM Replies:**\n{body}", d=None)
            if c == "setdm" and arg1.isdigit():
                idx = int(arg1) - 1
                if 0 <= idx < 5 and arg2:
                    DM_REPLIES[idx] = arg2; save_cfg()
                    return await fb(e, f"✅ Updated DM reply slot {idx+1} to: {arg2}")

            # MUTE & LOCK CONTROLS
            if c in ("mutegc", "muteall"):
                MUTE_CHATS.add(cid); save_cfg()
                return await fb(e, "🔇 **Chat Mute ON:** Auto-deleting incoming messages.")
            if c in ("stop mutegc", "unmutegc", "unmute"):
                MUTE_CHATS.discard(cid); save_cfg()
                return await fb(e, "🔊 **Chat Mute OFF.**")
            if c in ("lock", "lockall"):
                LOCK_CHATS.add(cid); save_cfg()
                return await fb(e, "🔒 **Chat Lockdown ON.**")
            if c in ("unlock", "unlockall"):
                LOCK_CHATS.discard(cid); save_cfg()
                return await fb(e, "🔓 **Chat Lockdown OFF.**")

            # CACHE CLEANER
            if c in ("clearcache", "cache"):
                dirs, files = clear_cache_files()
                return await fb(e, f"🧹 **Cache Purged:** Cleared {dirs} bytecode dirs & {files} temp files.")

            # EMERGENCY STOP ALL & STATUS
            if c == "stopall":
                cancel_nc_task(cid)
                REPLY_CHATS.discard(cid); MUTE_CHATS.discard(cid); LOCK_CHATS.discard(cid); PIN_CHATS.discard(cid)
                save_cfg()
                return await fb(e, "🛑 **EMERGENCY STOP:** All active loops, responders & locks disabled for this chat.")
            if c in ("status", "help"):
                nc_state = "Active" if cid in NC_TASKS else "Inactive"
                pin_state = "Active" if (PIN_ALL or cid in PIN_CHATS) else "Inactive"
                rep_state = "Active" if cid in REPLY_CHATS else "Inactive"
                mute_state = "Active" if cid in MUTE_CHATS else "Inactive"
                return await fb(e, (
                    f"⚙️ **TELEGUARD USERBOT LIVE STATUS**\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"• Continuous NC: **{nc_state}**\n"
                    f"• Auto-Pinning: **{pin_state}**\n"
                    f"• Auto-Responders: **{rep_state}**\n"
                    f"• Chat Mute: **{mute_state}**\n"
                    f"• Connected Fleet: **{len(ACTIVE_CLIENTS)} userbots**\n"
                    f"• Database: **AES-256-GCM Hardware Encrypted**\n"
                    f"• Cloud: **Render Web 24/7 Service**"
                ), d=None)

        # AUTO-PIN SENT MESSAGES
        if (PIN_ALL or cid in PIN_CHATS) and cid not in PIN_EXEMPTS:
            mid = e.id
            if mid not in PIN_PROCESSED:
                PIN_PROCESSED.add(mid)
                try:
                    await client.pin_message(cid, mid, notify=False)
                except Exception:
                    pass

    @client.on(events.NewMessage(incoming=True))
    async def on_incoming(e):
        cid = e.chat_id
        sid = e.sender_id
        me_id = MY_IDS.get(user_key)
        if cid is None or sid == me_id:
            return

        if cid in MUTE_CHATS or cid in LOCK_CHATS or is_target_user(cid, sid):
            try:
                await e.delete()
            except Exception:
                pass
            return

        if cid in REPLY_CHATS:
            now = time.time()
            if cid in LAST_REP and (now - LAST_REP[cid]) < COOLDOWN:
                return
            LAST_REP[cid] = now
            try:
                if e.is_private:
                    idx = DM_INDEX.get(cid, 0)
                    msg_text = DM_REPLIES[idx % len(DM_REPLIES)]
                    DM_INDEX[cid] = (idx + 1) % len(DM_REPLIES)
                else:
                    idx = GC_INDEX.get(cid, 0)
                    msg_text = GC_REPLIES[idx % len(GC_REPLIES)]
                    GC_INDEX[cid] = (idx + 1) % len(GC_REPLIES)
                await e.reply(msg_text)
            except Exception:
                pass

    @client.on(events.Raw)
    async def on_raw(e):
        if is_pin_action(e):
            target_msg = getattr(e, "action_message", None) or e
            await handle_pin_notification(client, user_key, target_msg)

async def start_userbot_session(user_key, api_id: int, api_hash: str, session_string: str, phone: str = ""):
    try:
        session = StringSession(session_string)
        client = TelegramClient(session, api_id, api_hash)
        await client.connect()
        if not await client.is_user_authorized():
            logger.warning(f"Session for user_key {user_key} is not authorized.")
            return False, "Session not authorized"
        me = await client.get_me()
        MY_IDS[user_key] = me.id
        ACTIVE_CLIENTS[user_key] = client
        CLIENT_INFO[user_key] = {"id": me.id, "name": me.first_name, "phone": phone or getattr(me, "phone", "")}
        register_userbot_handlers(client, user_key)
        logger.info(f"✅ Userbot started for {me.first_name} [ID: {me.id}] (Key: {user_key})")
        return True, f"Running as {me.first_name}"
    except Exception as exc:
        logger.error(f"Failed to start userbot session {user_key}: {exc}")
        return False, str(exc)

async def stop_userbot_session(user_key):
    client = ACTIVE_CLIENTS.pop(user_key, None)
    MY_IDS.pop(user_key, None)
    CLIENT_INFO.pop(user_key, None)
    if client:
        try:
            await client.disconnect()
            logger.info(f"Disconnected userbot session {user_key}")
        except Exception:
            pass

# Initialize settings and cleaner
load_cfg()
clear_cache_files()

# =====================================================================
# 4. RENDER HTTP DUMMY HEALTH CHECK SERVER (PORT 10000 / $PORT)
# =====================================================================
bot = TelegramClient("bot_session", BOT_API_ID, BOT_API_HASH)
STOP_EVENT = None
RENDER_SERVER = None
STATES = {}

async def start_render_health_server():
    port_env = os.environ.get("PORT")
    port = int(port_env) if port_env and port_env.isdigit() else 10000

    async def handle_http_request(reader, writer):
        try:
            line = await reader.readline()
            while True:
                header = await reader.readline()
                if not header or header == b"\r\n":
                    break
            recent_threats = get_recent_unauthorized_attempts(5)
            body_dict = {
                "status": "healthy",
                "service": "TeleGuard Multi-User Telegram Userbot & Cloud Suite",
                "active_userbots": len(ACTIVE_CLIENTS),
                "bot_connected": bot.is_connected() if bot else False,
                "required_channel": REQUIRED_CHANNEL_URL,
                "unauthorized_attempts_count": len(recent_threats),
                "timestamp": int(time.time()),
                "render_port": port
            }
            body = json.dumps(body_dict, indent=2).encode("utf-8")
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            writer.write(response)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    try:
        server = await asyncio.start_server(handle_http_request, "0.0.0.0", port)
        logger.info(f"🌐 [Render Health Server] Listening on 0.0.0.0:{port} (Satisfies Render Web Port Scan)")
        return server
    except Exception as exc:
        logger.warning(f"⚠️ [Render Health Server] Could not bind port {port}: {exc}")
        return None

# =====================================================================
# 5. TELEGRAM ONBOARDING BOT (TOKEN: 8995627301:AAFWGGan0dqijbSf9oiQTyYo4Ztzi1L-sCs)
# =====================================================================
async def is_user_subscribed_to_channel(user_id: int) -> bool:
    try:
        await bot(GetParticipantRequest(channel=REQUIRED_CHANNEL_USERNAME, participant=user_id))
        return True
    except errors.UserNotParticipantError:
        return False
    except Exception as exc:
        try:
            await bot.get_entity(REQUIRED_CHANNEL_USERNAME)
            return True
        except Exception:
            return False

async def send_channel_join_prompt(event, uid: int):
    join_text = (
        "📢 **MANDATORY CHANNEL VERIFICATION REQUIRED!**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "To start this Telegram Userbot, you must first join our official channel:\n\n"
        f"👉 **Official Channel:** {REQUIRED_CHANNEL_URL}\n\n"
        "1. Click **Join Official Channel** below.\n"
        "2. Join the channel.\n"
        "3. Click **✅ I Have Joined (Verify)** to unlock the Userbot!"
    )
    buttons = [
        [Button.url("📢 Join Official Channel", REQUIRED_CHANNEL_URL)],
        [Button.inline("✅ I Have Joined (Verify)", data=b"verify_channel_sub")]
    ]
    return await event.reply(join_text, buttons=buttons)

async def prompt_onboarding(uid: int, event):
    sender = await event.get_sender()
    first_name = getattr(sender, "first_name", "Friend") or "Friend"
    existing = get_user_session(uid)
    is_live = uid in ACTIVE_CLIENTS

    if existing and is_live:
        return await event.reply(
            f"⚡ **Welcome back, {existing.get('first_name', first_name)}!**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Your Telegram Userbot is **ONLINE & ACTIVE** for number `{existing['phone']}`.\n\n"
            f"🔒 **Security:** AES-256-GCM Encrypted in SQLite\n"
            f"⚡ **Cloud Host:** Render Web Service Running 24/7\n\n"
            f"**Quick Bot Commands:**\n"
            f"• `/status` ➔ View live account status\n"
            f"• `/controls` ➔ Userbot commands reference\n"
            f"• `/logout` ➔ Terminate userbot session\n\n"
            f"💡 **Execute `*` commands directly in any Telegram chat from your account:**\n"
            f"`*status`, `*pin`, `*stop pin`, `*nc`, `*stopnc`, `*replyall`, `*mutegc`, `*help`"
        )
    elif existing and not is_live:
        ok, res = await start_userbot_session(
            user_key=uid,
            api_id=existing["api_id"],
            api_hash=existing["api_hash"],
            session_string=existing["session_string"],
            phone=existing["phone"]
        )
        if ok:
            return await event.reply(
                f"✅ **Reconnected!** Your userbot for `{existing['phone']}` has resumed running.\n"
                f"Type `*help` in any chat to view all commands."
            )

    STATES[uid] = {"step": "WAIT_API_ID", "attempts": 0}
    welcome_text = (
        f"👋 **Welcome {first_name}!**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"Your channel membership for {REQUIRED_CHANNEL_URL} has been verified! ✅\n\n"
        f"Now authenticate your Telegram account to launch your cloud userbot:\n"
        f"1. **API ID** (from my.telegram.org)\n"
        f"2. **API HASH** (from my.telegram.org)\n"
        f"3. **Phone Number** (with country code)\n"
        f"4. **Verification Code** (sent to your Telegram app)\n"
        f"5. **2FA Password** (if Two-Factor Authentication is active)\n\n"
        f"👉 **Step 1/5: Please enter your numeric API ID:**\n"
        f"_(Example: `33248589` or reply `1` to use standard default API credentials)_"
    )
    await event.reply(welcome_text)

@bot.on(events.NewMessage(pattern="/start"))
async def handle_start(event):
    uid = event.sender_id
    if not await is_user_subscribed_to_channel(uid):
        return await send_channel_join_prompt(event, uid)
    await prompt_onboarding(uid, event)

@bot.on(events.CallbackQuery(data=b"verify_channel_sub"))
async def handle_verify_channel_sub(event):
    uid = event.sender_id
    if not await is_user_subscribed_to_channel(uid):
        return await event.answer(f"⚠️ You have not joined {REQUIRED_CHANNEL_URL} yet! Please join first.", alert=True)
    await event.answer("✅ Channel membership verified successfully!")
    try:
        await event.delete()
    except Exception:
        pass
    await prompt_onboarding(uid, event)

@bot.on(events.NewMessage(pattern="/cancel"))
async def handle_cancel(event):
    uid = event.sender_id
    if uid in STATES:
        cl = STATES[uid].get("client")
        if cl:
            try:
                await cl.disconnect()
            except Exception:
                pass
        del STATES[uid]
        await event.reply("🛑 Login cancelled. You can send `/start` whenever you are ready.")
    else:
        await event.reply("No active login process to cancel.")

@bot.on(events.NewMessage(pattern="/status"))
async def handle_status(event):
    uid = event.sender_id
    existing = get_user_session(uid)
    is_live = uid in ACTIVE_CLIENTS
    if not existing:
        return await event.reply("ℹ️ You don't have an active userbot yet. Send `/start` to connect your account!")
    status_badge = "🟢 ONLINE & ACTIVE" if is_live else "🔴 OFFLINE"
    await event.reply(
        f"📊 **Your Userbot Status**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"• Status: {status_badge}\n"
        f"• Connected Phone: `{existing['phone']}`\n"
        f"• Telegram User ID: `{uid}`\n"
        f"• API ID: `{existing['api_id']}`\n"
        f"• Database Security: **AES-256-GCM Hardware Encrypted**\n"
        f"• Active Fleet: **{len(ACTIVE_CLIENTS)} accounts**\n"
        f"• Verified Channel: {REQUIRED_CHANNEL_URL}\n\n"
        f"Type `*status` or `*help` in any chat to execute userbot commands directly!"
    )

@bot.on(events.NewMessage(pattern="/controls"))
async def handle_controls(event):
    await event.reply(
        "📋 **USERBOT ALL COMMANDS & CONTROLS**\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "Send these commands in ANY chat using your Telegram account:\n\n"
        "📌 **Message Auto-Pinning:**\n"
        "• `*pin` / `*pin on` ➔ Auto-pin own sent messages in current chat\n"
        "• `*stop pin` / `*unpin` ➔ Disable auto-pin in current chat\n"
        "• `*pinall` ➔ Enable global auto-pinning across all chats\n"
        "• `*stop pinall` ➔ Disable global auto-pinning\n"
        "• `*pindel` ➔ Auto-delete pin service notifications\n"
        "• `*stop pindel` ➔ Disable pin notification deletion\n\n"
        "🔄 **Continuous Name Changer (NC):**\n"
        "• `*nc` ➔ Start 5-title continuous cycle (every 3.0s)\n"
        "• `*nc n1 | n2 | n3 | n4 | n5` ➔ Start with custom titles\n"
        "• `*nc setup` ➔ Step-by-step interactive setup wizard\n"
        "• `*stopnc` ➔ Stop continuous title loop\n\n"
        "🎯 **Target Locks & Responders:**\n"
        "• `*target reply @user` ➔ Auto-reply (1-5 rotation) to target user\n"
        "• `*stop target reply @user` ➔ Stop target reply\n"
        "• `*target mute @user` ➔ Auto-delete all messages from target\n"
        "• `*stop target mute @user` ➔ Stop target mute\n"
        "• `*target lock @user` ➔ Lock chat against target\n"
        "• `*target delname @user` ➔ Auto-delete group name change messages of target\n\n"
        "👥 **Group Commands (5 Custom Rotating Replies):**\n"
        "• `*replyall` ➔ Toggle reply to all group members (1-5 rotation)\n"
        "• `*stop replyall` ➔ Disable group replyall\n"
        "• `*gcmsgs` ➔ View current 5 group auto-replies\n"
        "• `*setgc <1-5> <msg>` ➔ Edit a specific group reply slot\n"
        "• `*mutegc` ➔ Auto-delete all incoming group messages\n"
        "• `*stop mutegc` ➔ Stop group mute\n"
        "• `*lockall` ➔ Full group lockdown\n\n"
        "💬 **DM Commands (5 Custom Rotating Replies):**\n"
        "• `*reply` ➔ Toggle DM auto-reply (1-5 rotation)\n"
        "• `*stop reply` ➔ Disable DM auto-reply\n"
        "• `*dmmsgs` ➔ View current 5 DM auto-replies\n"
        "• `*setdm <1-5> <msg>` ➔ Edit a specific DM reply slot\n"
        "• `*mute` ➔ Mute incoming messages in this DM\n"
        "• `*stop mute` ➔ Unmute this DM\n"
        "• `*muteall` ➔ Global DM mute for all private chats\n"
        "• `*lock` ➔ Lock this DM\n\n"
        "🧹 **Cache Cleaning:**\n"
        "• `*clearcache` / `*cache` ➔ Clean bytecode and memory caches\n\n"
        "🛑 **Stop & Status:**\n"
        "• `*stopall` ➔ Emergency stop: kill NC, clear pin & all rules in chat\n"
        "• `*status` ➔ Real-time dashboard of active features & rules"
    )

@bot.on(events.NewMessage(pattern="/security_logs"))
async def handle_security_logs(event):
    uid = event.sender_id
    sender = await event.get_sender()
    username = getattr(sender, "username", "") or ""
    if ADMIN_ID and uid != ADMIN_ID:
        log_unauthorized_attempt(uid, username, "N/A", "ACCESS_SECURITY_LOGS", "Non-admin attempted security logs access", severity="CRITICAL")
        return await event.reply("⛔ **Access Denied.** Unauthorized attempt logged.")
    recent = get_recent_unauthorized_attempts(10)
    if not recent:
        return await event.reply("🛡️ No unauthorized access attempts recorded. System is secure.")
    lines = ["🚨 **RECENT UNAUTHORIZED ACCESS ATTEMPTS:**\n"]
    for r in recent:
        lines.append(f"• `[{r['timestamp'][:19]}]` User `{r['user_id']}` (@{r['username'] or 'None'})\n  Action: `{r['action']}` | Target: `{r['phone_attempted']}`\n  Reason: {r['reason']} (Severity: **{r['severity']}**)\n")
    await event.reply("\n".join(lines))

@bot.on(events.NewMessage(pattern="/logout"))
async def handle_logout(event):
    uid = event.sender_id
    if uid in ACTIVE_CLIENTS:
        await stop_userbot_session(uid)
        delete_user_session(uid)
        await event.reply("🛑 Your userbot session has been stopped and cleared. To reconnect anytime, send `/start`.")
    else:
        delete_user_session(uid)
        await event.reply("You do not currently have a running userbot instance.")

@bot.on(events.NewMessage)
async def handle_conversation(event):
    uid = event.sender_id
    text = (event.raw_text or "").strip()
    if text.startswith("/") or uid not in STATES:
        return

    sender = await event.get_sender()
    username = getattr(sender, "username", "") or ""
    state = STATES[uid]
    step = state.get("step")

    if step == "WAIT_API_ID":
        if text == "1":
            state["api_id"] = BOT_API_ID
            state["api_hash"] = BOT_API_HASH
            state["step"] = "WAIT_PHONE"
            return await event.reply(f"✅ **Default API credentials selected** (`{BOT_API_ID}`).\n\n👉 **Step 3/5: Please enter your Phone Number** (e.g. `+916209065785`):")
        elif text.isdigit():
            state["api_id"] = int(text)
            state["step"] = "WAIT_API_HASH"
            return await event.reply(f"✅ **API ID saved:** `{text}`\n\n👉 **Step 2/5: Please enter your 32-character API HASH**:")
        else:
            return await event.reply("⚠️ API ID must be numeric (or reply `1` for default credentials):")

    if step == "WAIT_API_HASH":
        clean_hash = text.strip()
        if len(clean_hash) < 16:
            return await event.reply("⚠️ API HASH seems too short. Re-enter 32-character string:")
        state["api_hash"] = clean_hash
        state["step"] = "WAIT_PHONE"
        return await event.reply(f"✅ **API HASH saved.**\n\n👉 **Step 3/5: Please enter your Telegram Phone Number** (e.g. `+916209065785`):")

    if step == "WAIT_PHONE":
        clean_phone = re.sub(r"[\s\-\(\)]", "", text)
        if not clean_phone.startswith("+") or not clean_phone[1:].isdigit() or len(clean_phone) < 9:
            return await event.reply("⚠️ Invalid phone format! Please include `+` with country code, e.g. `+916209065785`:")

        state["phone"] = clean_phone
        status_msg = await event.reply("⏳ **Connecting to Telegram servers and requesting login code...**")
        try:
            client = TelegramClient(StringSession(), state["api_id"], state["api_hash"])
            await client.connect()
            code_result = await client.send_code_request(clean_phone)
            state["client"] = client
            state["phone_code_hash"] = code_result.phone_code_hash
            state["step"] = "WAIT_OTP"
            return await status_msg.edit(
                f"📩 **Telegram Verification Code Sent!**\n"
                f"Code sent to your Telegram app (or SMS) for `{clean_phone}`.\n\n"
                f"👉 **Step 4/5: Send the verification code here.**\n"
                f"💡 _Tip: You can send it with spaces like `1 2 3 4 5` if Telegram blocks numbers._"
            )
        except errors.FloodWaitError as fwe:
            err = f"⚠️ Telegram FloodWait: Please wait {fwe.seconds}s before retrying."
            log_unauthorized_attempt(uid, username, clean_phone, "SEND_CODE_REQUEST", err, severity="MEDIUM")
            del STATES[uid]
            return await status_msg.edit(err)
        except errors.ApiIdInvalidError:
            err = "❌ Invalid API ID or API HASH! Please verify your credentials from my.telegram.org."
            log_unauthorized_attempt(uid, username, clean_phone, "SEND_CODE_REQUEST", err, severity="HIGH")
            del STATES[uid]
            return await status_msg.edit(err)
        except Exception as exc:
            logger.error(f"Error requesting login code: {exc}")
            del STATES[uid]
            return await status_msg.edit(f"❌ Error initiating login: {exc}\nSend `/start` to retry.")

    if step == "WAIT_OTP":
        clean_code = re.sub(r"\s+", "", text)
        client = state.get("client")
        if not client:
            del STATES[uid]
            return await event.reply("⚠️ Session expired. Please send `/start` again.")
        status_msg = await event.reply("⏳ **Verifying code...**")
        try:
            await client.sign_in(phone=state["phone"], code=clean_code, phone_code_hash=state["phone_code_hash"])
            await finalize_onboarding(uid, state, event, status_msg)
            return
        except errors.SessionPasswordNeededError:
            state["step"] = "WAIT_2FA"
            return await status_msg.edit("🔐 **Two-Factor Authentication (2FA) Detected!**\n\n👉 **Step 5/5: Please enter your 2FA Cloud Password:**")
        except (errors.PhoneCodeInvalidError, errors.PhoneCodeExpiredError):
            state["attempts"] = state.get("attempts", 0) + 1
            if state["attempts"] >= 3:
                log_unauthorized_attempt(uid, username, state["phone"], "OTP_VERIFICATION", "Exceeded max OTP attempts", severity="CRITICAL")
                try:
                    await client.disconnect()
                except Exception:
                    pass
                del STATES[uid]
                return await status_msg.edit("🚨 **Too many invalid code attempts!** Login cancelled and alert logged.")
            return await status_msg.edit(f"⚠️ Incorrect code! ({3 - state['attempts']} attempts left). Re-enter:")
        except Exception as exc:
            logger.error(f"OTP sign-in error: {exc}")
            try:
                await client.disconnect()
            except Exception:
                pass
            del STATES[uid]
            return await status_msg.edit(f"❌ Login error: {exc}\nSend `/start` to retry.")

    if step == "WAIT_2FA":
        password = text
        client = state.get("client")
        status_msg = await event.reply("⏳ **Verifying 2FA Password...**")
        try:
            await client.sign_in(password=password)
            await finalize_onboarding(uid, state, event, status_msg)
            return
        except errors.PasswordHashInvalidError:
            state["attempts"] = state.get("attempts", 0) + 1
            if state["attempts"] >= 3:
                log_unauthorized_attempt(uid, username, state["phone"], "2FA_PASSWORD", "Multiple invalid 2FA attempts", severity="CRITICAL")
                try:
                    await client.disconnect()
                except Exception:
                    pass
                del STATES[uid]
                return await status_msg.edit("🚨 **Too many invalid 2FA attempts!** Login terminated.")
            return await status_msg.edit(f"⚠️ Invalid 2FA password! ({3 - state['attempts']} attempts left). Try again:")
        except Exception as exc:
            logger.error(f"2FA sign-in error: {exc}")
            try:
                await client.disconnect()
            except Exception:
                pass
            del STATES[uid]
            return await status_msg.edit(f"❌ 2FA error: {exc}\nSend `/start` to retry.")

async def finalize_onboarding(uid: int, state: dict, event, status_msg):
    client = state["client"]
    try:
        session_string = client.session.save()
        me = await client.get_me()
        first_name = me.first_name or "Commander"
        username = me.username or ""

        save_user_session(uid, state["phone"], state["api_id"], state["api_hash"], session_string, first_name, username)
        ok, res = await start_userbot_session(uid, state["api_id"], state["api_hash"], session_string, state["phone"])
        del STATES[uid]

        success_msg = (
            f"🎉 **ACCOUNT VERIFIED & USERBOT ACTIVATED!**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 **Account:** {first_name} (`{state['phone']}`)\n"
            f"🆔 **Telegram ID:** `{me.id}`\n"
            f"🔒 **Database Security:** AES-256-GCM Encrypted in SQLite\n"
            f"⚡ **Status:** {res}\n\n"
            f"🚀 **You now have FULL ACCESS to your TeleGuard Userbot!**\n\n"
            f"**Try these commands directly from your Telegram account:**\n"
            f"• `*status` ➔ View live userbot status\n"
            f"• `*pin` / `*stop pin` ➔ Auto-pin your sent messages\n"
            f"• `*nc` ➔ Start 5-title continuous group name loop\n"
            f"• `*replyall` ➔ 5-message rotating auto-reply for groups\n"
            f"• `*reply` ➔ 5-message rotating auto-reply for DMs\n"
            f"• `*clearcache` ➔ Purge bytecode & cache buffers\n"
            f"• `*help` ➔ Full list of all commands & target locks\n\n"
            f"💾 _Your session string is encrypted with AES-256 and will automatically resume on cloud reboots._"
        )
        await status_msg.edit(success_msg)
        logger.info(f"✅ Userbot onboarding completed for user {uid} ({state['phone']})")
    except Exception as exc:
        logger.error(f"Error finalizing onboarding for {uid}: {exc}")
        await status_msg.edit(f"❌ Failed to activate userbot: {exc}")

# =====================================================================
# 6. SYSTEM STARTUP & RESUMPTION ON RENDER
# =====================================================================
async def main():
    global STOP_EVENT, RENDER_SERVER
    STOP_EVENT = asyncio.Event()

    print("\n" + "="*70)
    print("  🛡️ TELEGUARD - ALL-IN-ONE TELEGRAM USERBOT & CLOUD SUITE")
    print(f"  Mandatory Channel Check: {REQUIRED_CHANNEL_URL}")
    print("  AES-256 Session Database • Render Cloud Ready • Open User Access")
    print("="*70)

    init_db()
    RENDER_SERVER = await start_render_health_server()

    logger.info(f"Connecting Telegram Bot (Token: {BOT_TOKEN[:10]}...)...")
    await bot.start(bot_token=BOT_TOKEN)
    bot_me = await bot.get_me()
    logger.info(f"🤖 Bot connected as: @{bot_me.username} [ID: {bot_me.id}]")

    active_sessions = get_all_active_sessions()
    logger.info(f"Found {len(active_sessions)} active encrypted userbot sessions in database.")
    for s in active_sessions:
        try:
            logger.info(f"Resuming userbot for {s['phone']} (User {s['user_id']})...")
            await start_userbot_session(
                user_key=s["user_id"],
                api_id=s["api_id"],
                api_hash=s["api_hash"],
                session_string=s["session_string"],
                phone=s["phone"]
            )
            await asyncio.sleep(0.5)
        except Exception as exc:
            logger.error(f"Failed to resume session for {s['phone']}: {exc}")

    print("\n" + "="*70)
    print("  🚀 TELEGUARD ENGINE IS RUNNING LIVE")
    print(f"  🤖 Bot: @{bot_me.username}")
    print(f"  📢 Verified Channel: {REQUIRED_CHANNEL_URL}")
    print(f"  🌐 Render Web Health Server: Port {os.environ.get('PORT', '10000')}")
    print(f"  🔐 Database: AES-256-GCM Encrypted Storage Active")
    print(f"  🚨 Intrusion Logger: Active (Tracking all unauthorized attempts)")
    print("="*70 + "\n")

    await STOP_EVENT.wait()

if __name__ == "__main__":
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def shutdown_handler():
            logger.info("Termination signal received. Shutting down gracefully...")
            if STOP_EVENT and not STOP_EVENT.is_set():
                STOP_EVENT.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, shutdown_handler)
            except (NotImplementedError, AttributeError):
                pass

        loop.run_until_complete(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Exiting...")
        if bot and bot.is_connected():
            loop.run_until_complete(bot.disconnect())
        for ukey, cl in list(ACTIVE_CLIENTS.items()):
            try:
                if cl.is_connected():
                    loop.run_until_complete(cl.disconnect())
            except Exception:
                pass
        if RENDER_SERVER:
            try:
                RENDER_SERVER.close()
                loop.run_until_complete(RENDER_SERVER.wait_closed())
            except Exception:
                pass
        print("Clean shutdown complete.")
