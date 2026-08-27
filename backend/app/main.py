"""AI Software Trust Gateway - FastAPI 应用程序入口 (Control Plane API)
"""
from contextlib import asynccontextmanager
import time
import uuid
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.v1.router import api_v1_router
from backend.app.core.config import settings
from backend.app.core.errors import ASTGException
from backend.app.core.logging import logger
from backend.app.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理器"""
    logger.info("ASTG 控制平面 API 启动中", env=settings.ASTG_ENV, host=settings.ASTG_HOST, port=settings.ASTG_PORT)
    try:
        await init_db()
    except Exception as e:
        logger.warning("数据库自动初始化提示", info=str(e))
    yield
    logger.info("ASTG 控制平面 API 正在优雅关闭")


app = FastAPI(
    title="AI Software Trust Gateway (ASTG)",
    description="本地开源 AI 软件可信安全网关 - 面向开源代码、AI 插件与 MCP 工具的前置可信安全审查",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ASTG_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_and_tracing_middleware(request: Request, call_next):
    """请求追踪与安全响应头中间件"""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start_time = time.time()

    response = await call_next(request)

    # 注入安全响应头
    process_time = time.time() - start_time
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"

    return response


@app.exception_handler(ASTGException)
async def astg_exception_handler(request: Request, exc: ASTGException):
    """统一 ASTG 业务异常响应"""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "code": exc.code,
            "message": exc.message,
            "details": exc.details,
        },
    )


# 注册 API v1 路由
app.include_router(api_v1_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host=settings.ASTG_HOST,
        port=settings.ASTG_PORT,
        reload=settings.ASTG_RELOAD,
    )
