import hashlib
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Tuple

from pqcrypto.kem import ml_kem_768
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class SessionState:
    session_id: str
    session_key: bytes
    created_at: str
    kem_algorithm: str
    key_fingerprint: str


class HybridCryptoService:
    def __init__(self, kem_alg: str = "ML-KEM-768") -> None:
        self.kem_alg = kem_alg
        self.sessions: Dict[str, SessionState] = {}

    def server_handshake(
        self,
        client_pq_public_key_hex: str,
        client_classic_public_key_hex: str,
    ) -> Tuple[str, str, str]:
        client_pq_public_key = bytes.fromhex(client_pq_public_key_hex)
        client_classic_public_key = x25519.X25519PublicKey.from_public_bytes(
            bytes.fromhex(client_classic_public_key_hex)
        )
        pq_ciphertext, pq_shared_secret = ml_kem_768.encrypt(client_pq_public_key)
        server_classic_private = x25519.X25519PrivateKey.generate()
        server_classic_public = server_classic_private.public_key()
        classic_shared_secret = server_classic_private.exchange(client_classic_public_key)
        session_key = self._derive_session_key(pq_shared_secret, classic_shared_secret)
        session_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        key_fingerprint = hashlib.sha256(session_key).hexdigest()[:16]
        self.sessions[session_id] = SessionState(
            session_id=session_id,
            session_key=session_key,
            created_at=created_at,
            kem_algorithm=self.kem_alg,
            key_fingerprint=key_fingerprint,
        )
        # Персистентное хранение (Fernet + PostgreSQL) — SessionRepository.save_session в main.py
        server_classic_public_hex = server_classic_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        return session_id, pq_ciphertext.hex(), server_classic_public_hex

    @staticmethod
    def _derive_session_key(pq_secret: bytes, classic_secret: bytes) -> bytes:
        salt = hashlib.sha256(b"vkr-pqc-demo-salt").digest()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"hybrid-session-key",
        )
        return hkdf.derive(pq_secret + classic_secret)

    def get_session_key_hex(self, session_id: str) -> str:
        state = self.sessions.get(session_id)
        if not state:
            raise KeyError("Сессия не найдена")
        return state.session_key.hex()

    def get_proof(self, session_id: str) -> str:
        state = self.sessions.get(session_id)
        if not state:
            raise KeyError("Сессия не найдена")
        return hashlib.sha256(state.session_key + os.urandom(16)).hexdigest()

    def list_sessions(self) -> list[dict]:
        records = []
        for state in self.sessions.values():
            records.append(
                {
                    "session_id": state.session_id,
                    "created_at": state.created_at,
                    "kem_algorithm": state.kem_algorithm,
                    "key_fingerprint": state.key_fingerprint,
                }
            )
        return sorted(records, key=lambda x: x["created_at"], reverse=True)
