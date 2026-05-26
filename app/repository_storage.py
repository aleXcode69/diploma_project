import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, close_db, init_db
from app.db_models import CryptoSession, SecurityAuditLog

logger = logging.getLogger("crypto.storage")


class SessionStorage:
    """Низкоуровневый доступ к PostgreSQL (asyncpg) и in-memory fallback."""

    def __init__(self) -> None:
        self._db_enabled = False
        self._memory_encrypted: Dict[str, bytes] = {}
        self._memory_meta: Dict[str, dict] = {}

    @property
    def db_enabled(self) -> bool:
        return self._db_enabled

    async def connect(self) -> None:
        try:
            self._db_enabled = await init_db()
        except Exception as exc:
            logger.warning("PostgreSQL недоступна (%s), in-memory fallback", exc)
            self._db_enabled = False
            return
        if self._db_enabled:
            logger.info("SessionStorage: PostgreSQL подключена")
        else:
            logger.warning("SessionStorage: DATABASE_URL не задан, in-memory fallback")

    async def disconnect(self) -> None:
        await close_db()

    async def save(
        self,
        session_id: str,
        encrypted_key: bytes,
        fingerprint: str,
        kem_algorithm: str,
        created_at: str,
    ) -> None:
        if self._db_enabled and AsyncSessionLocal is not None:
            async with AsyncSessionLocal() as db:
                db.add(
                    CryptoSession(
                        session_id=session_id,
                        encrypted_session_key=encrypted_key,
                        fingerprint=fingerprint,
                        kem_algorithm=kem_algorithm,
                    )
                )
                await db.commit()
            return
        self._memory_encrypted[session_id] = encrypted_key
        self._memory_meta[session_id] = {
            "session_id": session_id,
            "fingerprint": fingerprint,
            "kem_algorithm": kem_algorithm,
            "created_at": created_at,
        }

    async def load_encrypted_key(self, session_id: str) -> bytes:
        if self._db_enabled and AsyncSessionLocal is not None:
            async with AsyncSessionLocal() as db:
                record = await self._fetch_session(db, session_id)
                if record is None:
                    raise KeyError("Сессия не найдена")
                return record.encrypted_session_key
        encrypted = self._memory_encrypted.get(session_id)
        if encrypted is None:
            raise KeyError("Сессия не найдена")
        return encrypted

    async def audit(self, event_type: str, session_id: Optional[str], ip_address: str) -> None:
        if self._db_enabled and AsyncSessionLocal is not None:
            async with AsyncSessionLocal() as db:
                db.add(
                    SecurityAuditLog(
                        event_type=event_type,
                        session_id=session_id,
                        ip_address=ip_address,
                    )
                )
                await db.commit()
            logger.warning("Security audit: %s session=%s ip=%s", event_type, session_id, ip_address)
            return
        logger.warning("Security audit (memory): %s session=%s ip=%s", event_type, session_id, ip_address)

    async def list_recent(self, limit: int) -> List[dict[str, Any]]:
        if self._db_enabled and AsyncSessionLocal is not None:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(CryptoSession).order_by(CryptoSession.created_at.desc()).limit(limit)
                )
                return [
                    {
                        "session_id": row.session_id,
                        "created_at": row.created_at.isoformat(),
                        "kem_algorithm": row.kem_algorithm,
                        "key_fingerprint": row.fingerprint,
                    }
                    for row in result.scalars().all()
                ]
        records = list(self._memory_meta.values())
        return sorted(records, key=lambda item: item["created_at"], reverse=True)[:limit]

    @staticmethod
    async def _fetch_session(db: AsyncSession, session_id: str) -> Optional[CryptoSession]:
        result = await db.execute(
            select(CryptoSession).where(CryptoSession.session_id == session_id)
        )
        return result.scalar_one_or_none()
