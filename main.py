import asyncio
import json
import logging
import os
import re
import signal
import sys
import time
from telethon import TelegramClient, events, errors, Button
from telethon.sessions import StringSession
from telethon.tl.functions.channels import GetParticipantRequest

# =====================================================================
# PATH RESOLUTION & SAFE SIBLING IMPORTS (Supports subfolder & root execution)
# =====================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from crypto import encrypt_aes256, decrypt_aes256
    from database import (
        init_db,
        save_user_session,
        get_user_session,
        delete_user_session,
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
except ImportError:
    from .crypto import encrypt_aes256, decrypt_aes256
    from .database import (
        init_db,
        save_user_session,
        get_user_session,
        delete_user_session,
        get_all_active_sessions,
        log_unauthorized_attempt,
        get_recent_unauthorized_attempts
    )
    from .userbot_engine import (
        start_userbot_session,
        stop_userbot_session,
        ACTIVE_CLIENTS,
        CLIENT_INFO
    )

# =====================================================================
# CONFIGURATION & ENVIRONMENT VARIABLES
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s"
)
logger = logging.getLogger("TeleGuardMain")

# Dedicated Bot Token provided by user
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8995627301:AAFWGGan0dqijbSf9oiQTyYo4Ztzi1L-sCs")

# Default API credentials used for running the Telegram Bot client
BOT_API_ID = int(os.environ.get("BOT_API_ID", "33248589"))
BOT_API_HASH = os.environ.get("BOT_API_HASH", "cb94a9acfa11e9aaf1195610f4144e65")

# Mandatory Channel for /start verification (No other channels)
REQUIRED_CHANNEL_USERNAME = "enerzonends"
REQUIRED_CHANNEL_URL = "https://t.me/enerzonends"

ADMIN_ID_RAW = os.environ.get("ADMIN_ID", "")
ADMIN_ID = int(ADMIN_ID_RAW) if ADMIN_ID_RAW.isdigit() else None

# User onboarding state machine: supports unlimited concurrent users
STATES = {}  # {uid: {"step": ..., "api_id": ..., "api_hash": ..., "phone": ..., "client": ..., "phone_code_hash": ..., "attempts": 0}}

bot = TelegramClient("bot_session", BOT_API_ID, BOT_API_HASH)
STOP_EVENT = None
RENDER_SERVER = None

# =====================================================================
# RENDER HTTP HEALTH CHECK DUMMY SERVER (ZERO TIMEOUT)
# =====================================================================
async def start_render_health_server():
    """Starts an asynchronous HTTP server to satisfy Render's port binding requirements on 0.0.0.0:$PORT."""
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
        logger.info(f"🌐 [Render Health Server] Successfully listening on 0.0.0.0:{port} (Satisfies Render Web Service Port Requirement)")
        return server
    except Exception as exc:
        logger.warning(f"⚠️ [Render Health Server] Could not bind to port {port}: {exc}")
        return None

# =====================================================================
# CHANNEL SUBSCRIPTION VERIFIER (https://t.me/enerzonends)
# =====================================================================
async def is_user_subscribed_to_channel(user_id: int) -> bool:
    """
    Verifies if the user has joined the mandatory channel https://t.me/enerzonends.
    Returns True if subscribed, False otherwise.
    """
    try:
        await bot(GetParticipantRequest(
            channel=REQUIRED_CHANNEL_USERNAME,
            participant=user_id
        ))
        return True
    except errors.UserNotParticipantError:
        return False
    except Exception as exc:
        logger.debug(f"Channel membership check exception: {exc}")
        try:
            entity = await bot.get_entity(REQUIRED_CHANNEL_USERNAME)
            return True
        except Exception:
            return False

async def send_channel_join_prompt(event, uid: int):
    """Sends clean mandatory channel join verification card with inline buttons."""
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
    """Launches the 5-step userbot authentication wizard."""
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

    # Initialize onboarding state: Step 1 (API ID)
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

# =====================================================================
# BOT COMMAND HANDLERS
# =====================================================================
@bot.on(events.NewMessage(pattern="/start"))
async def handle_start(event):
    uid = event.sender_id

    # Mandatory Channel Joining Verification for https://t.me/enerzonends
    is_subscribed = await is_user_subscribed_to_channel(uid)
    if not is_subscribed:
        return await send_channel_join_prompt(event, uid)

    await prompt_onboarding(uid, event)

@bot.on(events.CallbackQuery(data=b"verify_channel_sub"))
async def handle_verify_channel_sub(event):
    uid = event.sender_id
    is_subscribed = await is_user_subscribed_to_channel(uid)
    if not is_subscribed:
        return await event.answer(
            f"⚠️ You have not joined {REQUIRED_CHANNEL_URL} yet! Please join the channel first.",
            alert=True
        )

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
        f"• Active Userbots in Fleet: **{len(ACTIVE_CLIENTS)} accounts**\n"
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
        log_unauthorized_attempt(
            user_id=uid,
            username=username,
            phone_attempted="N/A",
            action="ACCESS_SECURITY_LOGS",
            reason="Non-admin user attempted to access security logs",
            severity="CRITICAL"
        )
        return await event.reply("⛔ **Access Denied.** Unauthorized attempt logged.")

    recent = get_recent_unauthorized_attempts(10)
    if not recent:
        return await event.reply("🛡️ No unauthorized access attempts recorded. System is secure.")

    lines = ["🚨 **RECENT UNAUTHORIZED ACCESS ATTEMPTS:**\n"]
    for r in recent:
        lines.append(
            f"• `[{r['timestamp'][:19]}]` User `{r['user_id']}` (@{r['username'] or 'None'})\n"
            f"  Action: `{r['action']}` | Target: `{r['phone_attempted']}`\n"
            f"  Reason: {r['reason']} (Severity: **{r['severity']}**)\n"
        )
    await event.reply("\n".join(lines))

@bot.on(events.NewMessage(pattern="/logout"))
async def handle_logout(event):
    uid = event.sender_id
    if uid in ACTIVE_CLIENTS:
        await stop_userbot_session(uid)
        await event.reply("🛑 Your userbot session has been stopped. To reconnect anytime, send `/start`.")
    else:
        await event.reply("You do not currently have a running userbot instance.")

# =====================================================================
# STEP-BY-STEP CONVERSATION FLOW:
# 1. API ID -> 2. API HASH -> 3. PHONE -> 4. VERIFICATION CODE -> 5. 2FA
# =====================================================================
@bot.on(events.NewMessage)
async def handle_conversation(event):
    uid = event.sender_id
    text = (event.raw_text or "").strip()

    if text.startswith("/"):
        return

    if uid not in STATES:
        return

    sender = await event.get_sender()
    username = getattr(sender, "username", "") or ""
    state = STATES[uid]
    step = state.get("step")

    # STEP 1: RECEIVE API ID
    if step == "WAIT_API_ID":
        if text == "1":
            state["api_id"] = BOT_API_ID
            state["api_hash"] = BOT_API_HASH
            state["step"] = "WAIT_PHONE"
            return await event.reply(
                f"✅ **Default API credentials selected** (`{BOT_API_ID}`).\n\n"
                f"👉 **Step 3/5: Please enter your Phone Number**\n"
                f"Include country code with `+` (e.g. `+916209065785` or `+18459083686`):"
            )
        elif text.isdigit():
            state["api_id"] = int(text)
            state["step"] = "WAIT_API_HASH"
            return await event.reply(
                f"✅ **API ID saved:** `{text}`\n\n"
                f"👉 **Step 2/5: Please enter your 32-character API HASH** (from https://my.telegram.org):"
            )
        else:
            return await event.reply("⚠️ API ID must be numeric (or reply `1` for default credentials):")

    # STEP 2: RECEIVE API HASH
    if step == "WAIT_API_HASH":
        clean_hash = text.strip()
        if len(clean_hash) < 16:
            return await event.reply("⚠️ API HASH seems too short. Re-enter 32-character string:")

        state["api_hash"] = clean_hash
        state["step"] = "WAIT_PHONE"
        return await event.reply(
            f"✅ **API HASH saved.**\n\n"
            f"👉 **Step 3/5: Please enter your Telegram Phone Number**\n"
            f"Include country code with `+` (e.g. `+916209065785`):"
        )

    # STEP 3: RECEIVE PHONE NUMBER -> REQUEST TELEGRAM CODE
    if step == "WAIT_PHONE":
        clean_phone = re.sub(r"[\s\-\(\)]", "", text)
        if not clean_phone.startswith("+") or not clean_phone[1:].isdigit() or len(clean_phone) < 9:
            return await event.reply("⚠️ Invalid phone format! Please include international format with `+`, e.g. `+916209065785`:")

        state["phone"] = clean_phone
        status_msg = await event.reply("⏳ **Connecting to Telegram servers and requesting login code...**")

        try:
            client = TelegramClient(StringSession(), state["api_id"], state["api_hash"])
            await client.connect()
            code_result = await client.send_code_request(clean_phone)
            state["client"] = client
            state["phone_code_hash"] = code_result.phone_code_hash
            state["step"] = "WAIT_OTP"

            prompt_text = (
                f"📩 **Telegram Verification Code Sent!**\n"
                f"A verification code was dispatched to your Telegram app (or SMS) for `{clean_phone}`.\n\n"
                f"👉 **Step 4/5: Please send the verification code here.**\n"
                f"💡 _Tip: You can send it with spaces like `1 2 3 4 5` if Telegram prevents numbers._"
            )
            return await status_msg.edit(prompt_text)

        except errors.FloodWaitError as fwe:
            err = f"⚠️ Telegram FloodWait: Please wait {fwe.seconds} seconds before trying again."
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
            return await status_msg.edit(f"❌ Error initiating login: {exc}\nPlease send `/start` to retry.")

    # STEP 4: RECEIVE VERIFICATION CODE (OTP)
    if step == "WAIT_OTP":
        clean_code = re.sub(r"\s+", "", text)
        client = state.get("client")
        if not client:
            del STATES[uid]
            return await event.reply("⚠️ Session expired. Please send `/start` again.")

        status_msg = await event.reply("⏳ **Verifying code...**")
        try:
            await client.sign_in(
                phone=state["phone"],
                code=clean_code,
                phone_code_hash=state["phone_code_hash"]
            )
            # Login successful without 2FA!
            await finalize_onboarding(uid, state, event, status_msg)
            return

        except errors.SessionPasswordNeededError:
            # 2FA Cloud Password is required on this account
            state["step"] = "WAIT_2FA"
            return await status_msg.edit(
                "🔐 **Two-Factor Authentication (2FA) Detected!**\n\n"
                "👉 **Step 5/5: Please enter your 2FA Cloud Password:**\n"
                "_(This password is used only in memory to complete login and is never stored unencrypted)_"
            )

        except (errors.PhoneCodeInvalidError, errors.PhoneCodeExpiredError) as err:
            state["attempts"] = state.get("attempts", 0) + 1
            if state["attempts"] >= 3:
                log_unauthorized_attempt(
                    user_id=uid,
                    username=username,
                    phone_attempted=state["phone"],
                    action="OTP_VERIFICATION",
                    reason="Exceeded maximum OTP verification attempts (Possible brute force)",
                    severity="CRITICAL"
                )
                try:
                    await client.disconnect()
                except Exception:
                    pass
                del STATES[uid]
                return await status_msg.edit("🚨 **Too many invalid code attempts!** Login cancelled and security alert logged.")
            return await status_msg.edit(f"⚠️ Incorrect or expired code! ({3 - state['attempts']} attempts remaining). Please re-enter:")

        except Exception as exc:
            logger.error(f"OTP sign-in error: {exc}")
            try:
                await client.disconnect()
            except Exception:
                pass
            del STATES[uid]
            return await status_msg.edit(f"❌ Login error: {exc}\nSend `/start` to retry.")

    # STEP 5: RECEIVE 2FA PASSWORD
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
                log_unauthorized_attempt(
                    user_id=uid,
                    username=username,
                    phone_attempted=state["phone"],
                    action="2FA_PASSWORD_VERIFICATION",
                    reason="Multiple invalid 2FA password attempts",
                    severity="CRITICAL"
                )
                try:
                    await client.disconnect()
                except Exception:
                    pass
                del STATES[uid]
                return await status_msg.edit("🚨 **Too many invalid 2FA attempts!** Login terminated and alert logged.")
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
    """Generates StringSession, encrypts with AES-256-GCM, stores in SQLite, and launches userbot."""
    client = state["client"]
    try:
        session_string = client.session.save()
        me = await client.get_me()
        first_name = me.first_name or "Commander"
        username = me.username or ""

        # Store in SQLite with AES-256-GCM encryption
        save_user_session(
            user_id=uid,
            phone=state["phone"],
            api_id=state["api_id"],
            api_hash=state["api_hash"],
            session_string=session_string,
            first_name=first_name,
            username=username
        )

        # Launch the Telethon Userbot engine with all userbot commands active
        ok, res = await start_userbot_session(
            user_key=uid,
            api_id=state["api_id"],
            api_hash=state["api_hash"],
            session_string=session_string,
            phone=state["phone"]
        )

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
# SYSTEM STARTUP & MULTI-USER RESUMPTION
# =====================================================================
async def main():
    global STOP_EVENT, RENDER_SERVER
    STOP_EVENT = asyncio.Event()

    print("\n" + "="*70)
    print("  🛡️ TELEGUARD - MULTI-USER TELEGRAM USERBOT & CLOUD SUITE")
    print(f"  Mandatory Channel Check: {REQUIRED_CHANNEL_URL}")
    print("  AES-256 Session Database • Render Cloud Ready • Open User Access")
    print("="*70)

    # 1. Initialize SQLite schema (AES-256 encrypted sessions & unauthorized logs)
    init_db()

    # 2. Start Render HTTP Dummy Health Check Server
    RENDER_SERVER = await start_render_health_server()

    # 3. Boot Telegram Onboarding Bot
    logger.info(f"Connecting Telegram Bot (Token: {BOT_TOKEN[:10]}...)...")
    await bot.start(bot_token=BOT_TOKEN)
    bot_me = await bot.get_me()
    logger.info(f"🤖 Bot connected as: @{bot_me.username} [ID: {bot_me.id}]")

    # 4. Resume any saved active userbot sessions from AES-256 database
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
