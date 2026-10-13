import asyncio
import json
import logging
import os
import re
import signal
import sys
import time
from telethon import TelegramClient, events, errors
from telethon.sessions import StringSession

from crypto import encrypt_aes256, decrypt_aes256
from database import (
    init_db,
    save_user_session,
    get_user_session,
    get_all_active_sessions,
    log_unauthorized_attempt,
    get_recent_unauthorized_attempts
)
from userbot_engine import (
    start_userbot_session,
    stop_userbot_session,
    ACTIVE_CLIENTS,
    CLIENT_INFO
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s"
)
logger = logging.getLogger("TeleGuardMain")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8995627301:AAFWGGan0dqijbSf9oiQTyYo4Ztzi1L-sCs")
BOT_API_ID = int(os.environ.get("BOT_API_ID", "33248589"))
BOT_API_HASH = os.environ.get("BOT_API_HASH", "cb94a9acfa11e9aaf1195610f4144e65")

ADMIN_ID_RAW = os.environ.get("ADMIN_ID", "")
ADMIN_ID = int(ADMIN_ID_RAW) if ADMIN_ID_RAW.isdigit() else None

# Stores state per user: supports unlimited concurrent users
STATES = {}

bot = TelegramClient("bot_session", BOT_API_ID, BOT_API_HASH)
STOP_EVENT = None
RENDER_SERVER = None

async def start_render_health_server():
    """Asynchronous HTTP server to satisfy Render's port binding on 0.0.0.0:$PORT."""
    port_env = os.environ.get("PORT")
    port = int(port_env) if port_env and port_env.isdigit() else 10000

    async def handle_http_request(reader, writer):
        try:
            line = await reader.readline()
            while True:
                header = await reader.readline()
                if not header or header == b"\r\n":
                    break

            body_dict = {
                "status": "healthy",
                "service": "TeleGuard Unlimited Multi-User Telegram Userbot",
                "active_userbots": len(ACTIVE_CLIENTS),
                "bot_connected": bot.is_connected() if bot else False,
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
        logger.info(f"🌐 [Render Health Server] Listening on 0.0.0.0:{port}")
        return server
    except Exception as exc:
        logger.warning(f"⚠️ [Render Health Server] Could not bind to port {port}: {exc}")
        return None

@bot.on(events.NewMessage(pattern="/start"))
async def handle_start(event):
    uid = event.sender_id
    sender = await event.get_sender()
    first_name = getattr(sender, "first_name", "Friend") or "Friend"

    existing = get_user_session(uid)
    is_live = uid in ACTIVE_CLIENTS

    if existing and is_live:
        return await event.reply(
            f"⚡ **Welcome back, {existing.get('first_name', first_name)}!**\n\n"
            f"Your Telegram Userbot is **ONLINE & RUNNING** for number `{existing['phone']}`.\n\n"
            f"• Storage: **AES-256-GCM** in SQLite\n"
            f"• Cloud Engine: Running on Render\n"
            f"• Send `/status` to view active features\n"
            f"• Send `/controls` for userbot commands cheat sheet\n"
            f"• Send `/logout` to terminate userbot session\n\n"
            f"💡 **In any chat from your account, use `*` commands directly:**\n"
            f"`*status`, `*pin`, `*stop pin`, `*nc`, `*replyall`, `*mutegc`, `*help`"
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
            return await event.reply(f"✅ Reconnected! Your userbot for `{existing['phone']}` is active.")

    STATES[uid] = {"step": "WAIT_API_ID", "attempts": 0}
    welcome_text = (
        f"👋 **Hello {first_name}! Welcome to the Multi-User Telegram Userbot.**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"Anyone can connect and run their own userbot instance here!\n\n"
        f"👉 **Step 1/5: Please enter your numeric API ID:**\n"
        f"_(Example: `33248589` or reply `1` to use standard default credentials)_"
    )
    await event.reply(welcome_text)

@bot.on(events.NewMessage(pattern="/status"))
async def handle_status(event):
    uid = event.sender_id
    existing = get_user_session(uid)
    is_live = uid in ACTIVE_CLIENTS
    if not existing:
        return await event.reply("ℹ️ You don't have an active userbot yet. Send `/start` to connect!")
    status_badge = "🟢 ONLINE & ACTIVE" if is_live else "🔴 OFFLINE"
    await event.reply(
        f"📊 **Userbot Status:** {status_badge}\n"
        f"• Connected Phone: `{existing['phone']}`\n"
        f"• Encryption: AES-256-GCM in SQLite\n"
        f"• Total Active Users in System: {len(ACTIVE_CLIENTS)}"
    )

@bot.on(events.NewMessage(pattern="/controls"))
async def handle_controls(event):
    await event.reply(
        "📋 **USERBOT COMMANDS CHEATSHEET**\n"
        "• `*status` ➔ View live state\n"
        "• `*pin` / `*stop pin` ➔ Message auto-pinning\n"
        "• `*nc` / `*stopnc` ➔ 5-title continuous name changer\n"
        "• `*replyall` / `*gcmsgs` ➔ Rotating group auto-reply\n"
        "• `*reply` / `*dmmsgs` ➔ Rotating DM auto-reply\n"
        "• `*mutegc` / `*lockall` ➔ Auto-delete incoming spam\n"
        "• `*stopall` ➔ Emergency stop"
    )

@bot.on(events.NewMessage(pattern="/security_logs"))
async def handle_security_logs(event):
    uid = event.sender_id
    sender = await event.get_sender()
    username = getattr(sender, "username", "") or ""
    if ADMIN_ID and uid != ADMIN_ID:
        log_unauthorized_attempt(uid, username, "N/A", "ACCESS_SECURITY_LOGS", "Non-admin attempted security logs", "CRITICAL")
        return await event.reply("⛔ Access Denied.")
    recent = get_recent_unauthorized_attempts(10)
    lines = ["🚨 **RECENT UNAUTHORIZED ATTEMPTS:**\n"]
    for r in recent:
        lines.append(f"• `[{r['timestamp'][:19]}]` User `{r['user_id']}` (@{r['username'] or 'None'}) - {r['action']}: {r['reason']}")
    await event.reply("\n".join(lines) if recent else "🛡️ No security incidents.")

@bot.on(events.NewMessage(pattern="/logout"))
async def handle_logout(event):
    uid = event.sender_id
    if uid in ACTIVE_CLIENTS:
        await stop_userbot_session(uid)
        await event.reply("🛑 Userbot disconnected. Send `/start` anytime to reconnect.")
    else:
        await event.reply("No running userbot found.")

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

    # STEP 1: API ID
    if step == "WAIT_API_ID":
        if text == "1":
            state["api_id"] = BOT_API_ID
            state["api_hash"] = BOT_API_HASH
            state["step"] = "WAIT_PHONE"
            return await event.reply(
                f"✅ **Default API credentials selected** (`{BOT_API_ID}`).\n\n"
                f"👉 **Step 3/5: Please enter your Phone Number** (e.g. `+916209065785`):"
            )
        elif text.isdigit():
            state["api_id"] = int(text)
            state["step"] = "WAIT_API_HASH"
            return await event.reply(f"✅ API ID saved.\n\n👉 **Step 2/5: Enter your 32-character API HASH:**")
        else:
            return await event.reply("⚠️ API ID must be numeric (or reply `1` for default credentials):")

    # STEP 2: API HASH
    if step == "WAIT_API_HASH":
        clean_hash = text.strip()
        if len(clean_hash) < 16:
            return await event.reply("⚠️ API HASH seems too short. Re-enter 32-character string:")
        state["api_hash"] = clean_hash
        state["step"] = "WAIT_PHONE"
        return await event.reply("✅ API HASH saved.\n\n👉 **Step 3/5: Enter your Phone Number** (e.g. `+916209065785`):")

    # STEP 3: PHONE NUMBER
    if step == "WAIT_PHONE":
        clean_phone = re.sub(r"[\s\-\(\)]", "", text)
        if not clean_phone.startswith("+") or not clean_phone[1:].isdigit() or len(clean_phone) < 9:
            return await event.reply("⚠️ Invalid format. Please include country code with `+` (e.g. `+916209065785`):")

        state["phone"] = clean_phone
        status_msg = await event.reply("⏳ Connecting to Telegram servers and requesting login code...")
        try:
            client = TelegramClient(StringSession(), state["api_id"], state["api_hash"])
            await client.connect()
            code_result = await client.send_code_request(clean_phone)
            state["client"] = client
            state["phone_code_hash"] = code_result.phone_code_hash
            state["step"] = "WAIT_OTP"
            return await status_msg.edit(
                f"📩 **Verification Code Sent!**\n"
                f"Code sent to your Telegram app for `{clean_phone}`.\n\n"
                f"👉 **Step 4/5: Send the verification code here.**\n"
                f"💡 _Tip: You can send it with spaces like `1 2 3 4 5` if Telegram prevents numbers._"
            )
        except Exception as exc:
            log_unauthorized_attempt(uid, username, clean_phone, "SEND_CODE_REQUEST", str(exc), severity="HIGH")
            del STATES[uid]
            return await status_msg.edit(f"❌ Error initiating login: {exc}\nSend `/start` to retry.")

    # STEP 4: VERIFICATION CODE
    if step == "WAIT_OTP":
        clean_code = re.sub(r"\s+", "", text)
        client = state.get("client")
        status_msg = await event.reply("⏳ Verifying code...")
        try:
            await client.sign_in(phone=state["phone"], code=clean_code, phone_code_hash=state["phone_code_hash"])
            await finalize_onboarding(uid, state, event, status_msg)
        except errors.SessionPasswordNeededError:
            state["step"] = "WAIT_2FA"
            return await status_msg.edit("🔐 **2FA Password Detected!**\n\n👉 **Step 5/5: Enter your 2FA Cloud Password:**")
        except Exception as exc:
            state["attempts"] = state.get("attempts", 0) + 1
            if state["attempts"] >= 3:
                log_unauthorized_attempt(uid, username, state["phone"], "OTP_ATTEMPTS", "Max attempts exceeded", "CRITICAL")
                del STATES[uid]
                return await status_msg.edit("🚨 Too many invalid attempts! Session terminated.")
            return await status_msg.edit(f"⚠️ Invalid code ({3 - state['attempts']} attempts left). Try again:")

    # STEP 5: 2FA PASSWORD
    if step == "WAIT_2FA":
        client = state.get("client")
        status_msg = await event.reply("⏳ Verifying 2FA Password...")
        try:
            await client.sign_in(password=text)
            await finalize_onboarding(uid, state, event, status_msg)
        except Exception as exc:
            state["attempts"] = state.get("attempts", 0) + 1
            if state["attempts"] >= 3:
                log_unauthorized_attempt(uid, username, state["phone"], "2FA_ATTEMPTS", "Max attempts exceeded", "CRITICAL")
                del STATES[uid]
                return await status_msg.edit("🚨 Too many invalid 2FA attempts! Terminated.")
            return await status_msg.edit(f"⚠️ Invalid 2FA password ({3 - state['attempts']} left). Re-enter:")

async def finalize_onboarding(uid: int, state: dict, event, status_msg):
    client = state["client"]
    session_string = client.session.save()
    me = await client.get_me()
    first_name = me.first_name or "Commander"
    username = me.username or ""

    save_user_session(uid, state["phone"], state["api_id"], state["api_hash"], session_string, first_name, username)
    ok, res = await start_userbot_session(uid, state["api_id"], state["api_hash"], session_string, state["phone"])
    del STATES[uid]

    await status_msg.edit(
        f"🎉 **ACCOUNT VERIFIED & USERBOT ACTIVATED!**\n"
        f"👤 **Account:** {first_name} (`{state['phone']}`)\n"
        f"🔒 **Security:** AES-256-GCM Encrypted in SQLite\n"
        f"⚡ **Status:** {res}\n\n"
        f"🚀 **You now have FULL ACCESS to the TeleGuard Userbot!**\n\n"
        f"Use commands like `*status`, `*pin`, `*nc`, `*help` from your Telegram account!"
    )

async def main():
    global STOP_EVENT, RENDER_SERVER
    STOP_EVENT = asyncio.Event()
    init_db()
    RENDER_SERVER = await start_render_health_server()
    await bot.start(bot_token=BOT_TOKEN)
    logger.info("Bot connected!")
    for s in get_all_active_sessions():
        await start_userbot_session(s["user_id"], s["api_id"], s["api_hash"], s["session_string"], s["phone"])
    await STOP_EVENT.wait()

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
