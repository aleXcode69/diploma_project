import os
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


engine: Optional[AsyncEngine] = None
AsyncSessionLocal: Optional[async_sessionmaker[AsyncSession]] = None


def get_async_database_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url and not url.startswith("postgresql+asyncpg://"):
        raise ValueError("DATABASE_URL must use postgresql+asyncpg driver")
    return url


async def init_db() -> bool:
    global engine, AsyncSessionLocal
    database_url = get_async_database_url()
    if not database_url:
        return False

    from app.db_models import CryptoSession, SecurityAuditLog  # noqa: F401

    try:
        engine = create_async_engine(database_url, echo=False, pool_pre_ping=True)
        AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return True
    except Exception:
        await close_db()
        raise


async def close_db() -> None:
    global engine, AsyncSessionLocal
    if engine is not None:
        await engine.dispose()
    engine = None
    AsyncSessionLocal = None


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    if AsyncSessionLocal is None:
        raise RuntimeError("Database is not initialized")
    async with AsyncSessionLocal() as session:
        yield session
