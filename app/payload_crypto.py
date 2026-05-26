import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_bytes(session_key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, None)
    envelope = {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
    return json.dumps(envelope, ensure_ascii=False).encode("utf-8")


def decrypt_bytes(session_key: bytes, body: bytes) -> bytes:
    envelope = json.loads(body.decode("utf-8"))
    nonce = bytes.fromhex(envelope["nonce"])
    ciphertext = bytes.fromhex(envelope["ciphertext"])
    return AESGCM(session_key).decrypt(nonce, ciphertext, None)


def encrypt_json(session_key: bytes, payload: Any) -> bytes:
    return encrypt_bytes(session_key, json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def decrypt_json(session_key: bytes, body: bytes) -> Any:
    return json.loads(decrypt_bytes(session_key, body).decode("utf-8"))
