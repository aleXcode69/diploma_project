"""
Нагрузочное тестирование POST /api/handshake (Locust), глава 4.2.

Запуск (API на :8000):
  pip install locust
  locust -f load_test.py --host http://127.0.0.1:8000

Браузер: http://localhost:8089
  - Number of users: 50–100
  - Spawn rate: 5–10
  - Start → вкладка Charts → скрин RPS и Response times

Режимы (переменная окружения LOAD_TEST_MODE):
  - pregen (по умолчанию) — один раз при старте Locust генерируются валидные
    ключи; нагрузка идёт на сервер (реальный ML-KEM + X25519), клиент не тормозит.
  - mock — только hex нужной длины (2368 + 64 символа), без pqcrypto на клиенте;
    сервер может отвечать 400, подходит только для проверки пропускной способности HTTP.
"""

import os
import secrets
from typing import Dict

from locust import HttpUser, between, task

LOAD_TEST_MODE = os.getenv("LOAD_TEST_MODE", "pregen").lower()

# ML-KEM-768 public key: 1184 байта → 2368 hex-символов; X25519: 32 байта → 64 hex.
PQ_PUBLIC_KEY_HEX_LEN = 2368
CLASSIC_PUBLIC_KEY_HEX_LEN = 64

_PREGEN_PAYLOAD: Dict[str, str] | None = None


def _build_pregen_payload() -> Dict[str, str]:
    global _PREGEN_PAYLOAD
    if _PREGEN_PAYLOAD is not None:
        return _PREGEN_PAYLOAD

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from pqcrypto.kem import ml_kem_768

    pq_public, _ = ml_kem_768.generate_keypair()
    classic_private = x25519.X25519PrivateKey.generate()
    classic_public_hex = classic_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    _PREGEN_PAYLOAD = {
        "pq_public_key": pq_public.hex(),
        "classic_public_key": classic_public_hex,
    }
    return _PREGEN_PAYLOAD


def _build_mock_payload() -> Dict[str, str]:
    return {
        "pq_public_key": secrets.token_hex(PQ_PUBLIC_KEY_HEX_LEN // 2),
        "classic_public_key": secrets.token_hex(CLASSIC_PUBLIC_KEY_HEX_LEN // 2),
    }


def build_handshake_payload() -> Dict[str, str]:
    if LOAD_TEST_MODE == "mock":
        return _build_mock_payload()
    return _build_pregen_payload()


class HandshakeUser(HttpUser):
    wait_time = between(0.2, 0.8)

    @task
    def hybrid_handshake(self) -> None:
        self.client.post(
            "/api/handshake",
            json=build_handshake_payload(),
            name="POST /api/handshake",
        )
