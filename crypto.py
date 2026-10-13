import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_MASTER_KEY = os.environ.get("AES_SECRET_KEY", "TELEGUARD_AES256_SECURE_MASTER_KEY_2026_X99")

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
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)
    data = plaintext.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, data, None)
    payload = nonce + ciphertext
    return base64.b64encode(payload).decode("ascii")

def decrypt_aes256(encrypted_base64: str, key_secret: str = None) -> str:
    if not encrypted_base64:
        return ""
    secret = key_secret or os.environ.get("AES_SECRET_KEY", DEFAULT_MASTER_KEY)
    key_bytes = _derive_aes256_key(secret)
    aesgcm = AESGCM(key_bytes)
    try:
        raw_payload = base64.b64decode(encrypted_base64.encode("ascii"))
        if len(raw_payload) < 28:
            raise ValueError("Ciphertext payload is too short or malformed")
        nonce = raw_payload[:12]
        ciphertext = raw_payload[12:]
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode("utf-8")
    except Exception as exc:
        raise ValueError(f"AES-256 Decryption failed (Key mismatch or corrupted ciphertext): {exc}")
