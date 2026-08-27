"""AI Software Trust Gateway - 系统配置 (Pydantic Settings)
"""
import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


def _default_data_dir() -> str:
    """Return a per-user writable data directory suitable for an installed app."""
    explicit = os.environ.get("ASTG_DATA_DIR")
    if explicit:
        return str(Path(explicit).expanduser().resolve())
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if root:
            return str((Path(root) / "AI Software Trust Gateway").resolve())
    xdg_root = os.environ.get("XDG_DATA_HOME")
    if xdg_root:
        return str((Path(xdg_root) / "astg").expanduser().resolve())
    return str((Path.home() / ".local" / "share" / "astg").resolve())


def _default_database_url() -> str:
    db_path = (Path(_default_data_dir()) / "astg.db").as_posix()
    return f"sqlite+aiosqlite:///{db_path}"


def _default_artifacts_dir() -> str:
    return str(Path(_default_data_dir()) / "artifacts")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # 环境与监听
    ASTG_ENV: str = "development"
    ASTG_HOST: str = "127.0.0.1"
    ASTG_PORT: int = 8000
    ASTG_RELOAD: bool = False
    ASTG_CORS_ORIGINS: List[str] = Field(default_factory=lambda: ["http://127.0.0.1:3000", "http://localhost:3000"])
    ASTG_LOG_LEVEL: str = "INFO"

    # 数据库
    ASTG_DATA_DIR: str = Field(default_factory=_default_data_dir)
    ASTG_DATABASE_URL: str = Field(default_factory=_default_database_url)

    # 队列
    ASTG_QUEUE_MODE: str = "inprocess"  # "inprocess" 或 "celery"
    ASTG_REDIS_URL: str = "redis://127.0.0.1:6379/0"

    # GitHub 与外部服务
    GITHUB_TOKEN: Optional[str] = None
    OSV_API_URL: str = "https://api.osv.dev/v1/querybatch"
    OSV_TIMEOUT_SECONDS: int = 15

    # AI 配置
    ASTG_AI_ENABLED: bool = False
    ASTG_AI_PROVIDER: str = "disabled"  # "disabled", "openai_compatible", "local_llm"
    ASTG_AI_BASE_URL: str = "https://api.openai.com/v1"
    ASTG_AI_API_KEY: Optional[str] = None
    ASTG_AI_MODEL: str = "gpt-4o-mini"
    ASTG_AI_TIMEOUT_SECONDS: int = 30

    # 存储与限制
    ASTG_ARTIFACTS_DIR: str = Field(default_factory=_default_artifacts_dir)
    ASTG_MAX_REPO_SIZE_MB: int = 500
    ASTG_MAX_REPO_FILES: int = 100000
    ASTG_MAX_SINGLE_FILE_MB: int = 10
    ASTG_SCAN_TIMEOUT_MINUTES: int = 20
    ASTG_REQUIRE_EXTERNAL_SCANNERS: bool = False
    ASTG_DYNAMIC_ENABLED: bool = False
    ASTG_DYNAMIC_PROVIDER: str = "disabled"


settings = Settings()
