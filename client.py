import argparse
import hashlib
import json

import requests
from pqcrypto.kem import ml_kem_768
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from app.payload_crypto import decrypt_bytes, encrypt_bytes


def derive_hybrid_key(pq_secret: bytes, classic_secret: bytes) -> bytes:
    salt = hashlib.sha256(b"vkr-pqc-demo-salt").digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"hybrid-session-key",
    )
    return hkdf.derive(pq_secret + classic_secret)


def run(base_url: str) -> None:
    print("[1/5] Генерация ML-KEM ключевой пары клиента...")
    client_pq_public, client_pq_secret = ml_kem_768.generate_keypair()

    print("[2/5] Генерация классической пары X25519...")
    client_classic_private = x25519.X25519PrivateKey.generate()
    client_classic_public = client_classic_private.public_key()
    client_classic_public_hex = client_classic_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    print("[3/5] Отправка handshake на сервер...")
    response = requests.post(
        f"{base_url}/api/handshake",
        json={
            "pq_public_key": client_pq_public.hex(),
            "classic_public_key": client_classic_public_hex,
        },
        timeout=20,
    )
    response.raise_for_status()
    data = response.json()

    session_id = data["session_id"]
    pq_ciphertext = data["pq_ciphertext"]
    server_classic_public_key = data["server_classic_public_key"]
    print(f"    session_id: {session_id}")

    print("[4/5] Декпсуляция ML-KEM и вычисление гибридного ключа...")
    pq_shared_secret = ml_kem_768.decrypt(client_pq_secret, bytes.fromhex(pq_ciphertext))

    server_pub = x25519.X25519PublicKey.from_public_bytes(
        bytes.fromhex(server_classic_public_key)
    )
    classic_shared_secret = client_classic_private.exchange(server_pub)
    client_session_key = derive_hybrid_key(pq_shared_secret, classic_shared_secret)
    print(f"    client_session_key (hex, first 16 bytes): {client_session_key.hex()[:32]}...")

    print("[5/6] Запрос защищенных данных (X-Session-ID + AES-GCM)...")
    protected = requests.get(
        f"{base_url}/api/protected/{session_id}",
        headers={"X-Session-ID": session_id},
        timeout=20,
    )
    protected.raise_for_status()
    protected_data = json.loads(decrypt_bytes(client_session_key, protected.content))
    print("    Ответ protected endpoint:", protected_data["message"])
    print("    proof:", protected_data["proof"])

    print("[6/6] Отправка зашифрованного POST через CryptoMiddleware...")
    encrypted_body = encrypt_bytes(
        client_session_key,
        json.dumps({"action": "verify_access", "client": "demo"}).encode("utf-8"),
    )
    submit = requests.post(
        f"{base_url}/api/protected/submit",
        headers={"X-Session-ID": session_id, "Content-Type": "application/json"},
        data=encrypted_body,
        timeout=20,
    )
    submit.raise_for_status()
    submit_data = json.loads(decrypt_bytes(client_session_key, submit.content))
    print("    Ответ submit:", submit_data["message"])

    print("\nГотово: в dashboard должны быть видны шаги handshake в реальном времени.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC client emulator for diploma demo.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="API URL")
    args = parser.parse_args()
    run(args.base_url)
