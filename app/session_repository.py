import base64
import hashlib
import os
from datetime import datetime, timezone
from typing import Any, List, Optional

from cryptography.fernet import Fernet, InvalidToken

from app.repository_storage import SessionStorage


class SessionRepository:
    """
    Репозиторий сессий и аудита (Repository Pattern).
    Ключи в PostgreSQL — только как Fernet-блоб (SECRET_KEY), открытый текст не пишется.
    """

    def __init__(self, secret_key: Optional[str] = None) -> None:
        master = secret_key or os.getenv("SECRET_KEY", "dev-secret-change-me")
        digest = hashlib.sha256(master.encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))
        self._storage = SessionStorage()

    @property
    def db_enabled(self) -> bool:
        return self._storage.db_enabled

    async def initialize(self) -> None:
        await self._storage.connect()

    async def close(self) -> None:
        await self._storage.disconnect()

    def _encrypt_session_key(self, raw_session_key: bytes) -> bytes:
        return self._fernet.encrypt(raw_session_key)

    def _decrypt_session_key(self, encrypted_session_key: bytes) -> bytes:
        try:
            return self._fernet.decrypt(encrypted_session_key)
        except InvalidToken as exc:
            raise KeyError("Не удалось расшифровать сессионный ключ") from exc

    async def save_session(
        self,
        session_id: str,
        raw_session_key: bytes,
        fingerprint: str,
        kem_algorithm: str,
        created_at: Optional[str] = None,
    ) -> None:
        encrypted = self._encrypt_session_key(raw_session_key)
        ts = created_at or datetime.now(timezone.utc).isoformat()
        await self._storage.save(session_id, encrypted, fingerprint, kem_algorithm, ts)

    async def get_session_key(self, session_id: str) -> bytes:
        encrypted = await self._storage.load_encrypted_key(session_id)
        return self._decrypt_session_key(encrypted)

    async def log_security_event(
        self,
        event_type: str,
        session_id: Optional[str],
        ip_address: str,
    ) -> None:
        await self._storage.audit(event_type, session_id, ip_address or "unknown")

    async def list_sessions(self, limit: int = 10) -> List[dict[str, Any]]:
        return await self._storage.list_recent(limit)
