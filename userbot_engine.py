import asyncio
import json
import logging
import os
import re
import time
from telethon import TelegramClient, events, errors
from telethon.sessions import StringSession
from telethon.tl.types import MessageMediaWebPage, MessageMediaEmpty, Channel, MessageActionChatEditTitle, MessageActionPinMessage
from telethon.tl.functions.channels import EditTitleRequest
from telethon.tl.functions.messages import EditChatTitleRequest

logger = logging.getLogger("UserbotEngine")
PIN_REACTION = "🔥"
DEFAULT_NC_TITLES = ["🔥 ALPHA ZONE 🔥", "⚡ THUNDER REIGN ⚡", "👑 APEX EMPIRE 👑", "💎 NITRO KINGS 💎", "🚀 SUPREME RULE 🚀"]
DEFAULT_GC_REPLIES = ["Hello! Currently away, will reply shortly ⚡", "Active in group, message acknowledged 👍", "Busy at the moment, checking notifications later 🚀", "Auto-reply active. Stay tuned! 💬", "Ping received. I will review this soon 🔥"]
DEFAULT_DM_REPLIES = ["Hey! Currently away from DM, will respond soon ⚡", "Message received in private chat 👍", "Please hold on, reviewing DMs shortly 🚀", "Auto-responder active for direct messages 💬", "Thanks for reaching out! Will get back to you soon 🔥"]

GC_REPLIES = list(DEFAULT_GC_REPLIES)
DM_REPLIES = list(DEFAULT_DM_REPLIES)
NC_TITLES = list(DEFAULT_NC_TITLES)
NC_INT, VANISH, COOLDOWN = 3.0, 1.5, 1.5

ACTIVE_CLIENTS = {}
CLIENT_INFO = {}
MY_IDS = {}
REPLY_CHATS, MUTE_CHATS, LOCK_CHATS, PIN_CHATS = set(), set(), set(), set()
PIN_ALL = False
NC_TASKS = {}
GC_INDEX, DM_INDEX = {}, {}

async def fb(e, txt, d=VANISH):
    try:
        target = await e.edit(txt, parse_mode="md")
        if d:
            await asyncio.sleep(d)
            await (target or e).delete()
    except Exception:
        pass

def register_userbot_handlers(client: TelegramClient, user_key):
    @client.on(events.NewMessage(outgoing=True))
    async def on_cmd(e):
        global PIN_ALL
        txt = (e.raw_text or "").strip()
        cid = e.chat_id
        if cid is None:
            return
        if not txt.startswith("*"):
            if PIN_ALL or (cid in PIN_CHATS):
                try:
                    await client.pin_message(cid, e.id, notify=False)
                except Exception:
                    pass
            return

        c = txt[1:].strip().lower()
        if c in ("help", "cmds", "commands"):
            return await fb(e, "📋 **TELEGUARD USERBOT ACTIVE**\n• *pin / *stop pin\n• *nc / *stopnc\n• *replyall / *stop replyall\n• *status", d=None)
        if c in ("pin", "pin on"):
            PIN_CHATS.add(cid)
            return await fb(e, "✅ **Auto-Pin ON**")
        if c in ("stop pin", "pin off", "unpin"):
            PIN_CHATS.discard(cid)
            return await fb(e, "🛑 **Auto-Pin OFF**")
        if c in ("pinall", "pin all"):
            PIN_ALL = True
            return await fb(e, "📌 **Global Pin ON**")
        if c in ("status",):
            return await fb(e, f"⚙️ **Status:** Active in {len(ACTIVE_CLIENTS)} accounts.", d=None)

    @client.on(events.NewMessage(incoming=True))
    async def on_incoming(e):
        cid, sid = e.chat_id, e.sender_id
        if cid is None or sid == MY_IDS.get(user_key):
            return
        if cid in MUTE_CHATS or cid in LOCK_CHATS:
            try:
                await e.delete()
            except Exception:
                pass
            return
        if cid in REPLY_CHATS:
            try:
                msg = DM_REPLIES[0] if e.is_private else GC_REPLIES[0]
                await e.reply(f"@{sid} {msg}")
            except Exception:
                pass

async def start_userbot_session(user_key, api_id: int, api_hash: str, session_string: str, phone: str = ""):
    try:
        session = StringSession(session_string)
        client = TelegramClient(session, api_id, api_hash)
        await client.connect()
        if not await client.is_user_authorized():
            return False, "Session not authorized"
        me = await client.get_me()
        MY_IDS[user_key] = me.id
        ACTIVE_CLIENTS[user_key] = client
        CLIENT_INFO[user_key] = {"id": me.id, "name": me.first_name, "phone": phone}
        register_userbot_handlers(client, user_key)
        return True, f"Running as {me.first_name}"
    except Exception as exc:
        return False, str(exc)

async def stop_userbot_session(user_key):
    client = ACTIVE_CLIENTS.pop(user_key, None)
    MY_IDS.pop(user_key, None)
    CLIENT_INFO.pop(user_key, None)
    if client:
        await client.disconnect()
