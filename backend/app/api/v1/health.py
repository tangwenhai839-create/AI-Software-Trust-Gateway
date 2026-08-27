"""AI Software Trust Gateway - 运行健康与能力检查 API (/health/live, /health/ready, /capabilities)
"""
import shutil
import sys
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text
from backend.app.db.session import async_session_factory
from backend.app.services.queue import ScanQueueManager
from backend.app.domain.schemas import CapabilityResponse
from backend.app.core.config import settings

router = APIRouter(tags=["Health & Capabilities"])


@router.get("/health/live")
async def health_live():
    """Liveness 探针"""
    return {"status": "alive", "service": "astg-control-api"}


@router.get("/health/ready")
async def health_ready():
    """Readiness 探针"""
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        if settings.ASTG_QUEUE_MODE.lower() == "celery":
            try:
                from redis.asyncio import Redis
            except ImportError as exc:
                raise RuntimeError("Celery queue mode is configured but Redis support is not installed") from exc
            redis_client = Redis.from_url(settings.ASTG_REDIS_URL)
            try:
                await redis_client.ping()
            finally:
                await redis_client.aclose()
        queue = ScanQueueManager.get_instance()
        return {
            "status": "ready",
            "database": "ok",
            "queue": "ok",
            "queue_mode": settings.ASTG_QUEUE_MODE,
            "running_tasks": len(queue.running_tasks) if settings.ASTG_QUEUE_MODE.lower() == "inprocess" else None,
        }
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "not_ready", "database": "error", "queue": "unknown", "detail": str(exc)})


@router.get("/capabilities", response_model=CapabilityResponse)
async def get_capabilities():
    """查询 ASTG 网关支持的扫描器、AI 模型提供者、语言生态和运行能力"""
    return CapabilityResponse(
        version="1.0.0",
        mode="mvp-static-v1",
        platform=sys.platform,
        scanners=["astg_ast_python", "astg_js_pattern", "semgrep", "bandit", "osv"],
        scanner_status={
            "astg_ast_python": "available",
            "astg_js_pattern": "available",
            "semgrep": "available" if shutil.which("semgrep") else "not_installed",
            "bandit": "available" if shutil.which("bandit") else "not_installed",
            "osv": "network_required",
        },
        ai_providers=["disabled", "openai_compatible"],
        supported_ecosystems=["PyPI", "npm"],
        dynamic_sandbox_available=(settings.ASTG_DYNAMIC_ENABLED and settings.ASTG_DYNAMIC_PROVIDER != "disabled"),
        sandbox_notice=(
            f"动态分析提供者: {settings.ASTG_DYNAMIC_PROVIDER}。"
            if settings.ASTG_DYNAMIC_ENABLED and settings.ASTG_DYNAMIC_PROVIDER != "disabled"
            else "动态沙箱未启用；系统不会直接在宿主机执行目标代码。"
        ),
    )
