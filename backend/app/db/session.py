"""AI Software Trust Gateway - 数据库会话与连接管理器 (SQLAlchemy 2.0 Async)
支持本地嵌入式 SQLite 以及生产级 PostgreSQL。
"""
from typing import AsyncGenerator
from sqlalchemy import event
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

from backend.app.core.config import settings

if settings.ASTG_DATABASE_URL.startswith("sqlite"):
    sqlite_database = make_url(settings.ASTG_DATABASE_URL).database
    if sqlite_database and sqlite_database != ":memory:":
        from pathlib import Path
        Path(sqlite_database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)

# 创建异步引擎
engine = create_async_engine(
    settings.ASTG_DATABASE_URL,
    echo=False,
    future=True,
)

if settings.ASTG_DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# 会话工厂
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI 依赖注入：获取数据库会话"""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """初始化数据库表结构并显式加载 ORM 模型"""
    import backend.app.db.models  # noqa: F401
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
