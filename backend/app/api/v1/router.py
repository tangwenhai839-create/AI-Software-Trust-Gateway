"""AI Software Trust Gateway - API v1 路由聚合器
"""
from fastapi import APIRouter
from backend.app.api.v1.findings import router as findings_router
from backend.app.api.v1.dependencies import router as dependencies_router
from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.reports import router as reports_router
from backend.app.api.v1.scans import router as scans_router
from backend.app.api.v1.scores import router as scores_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(scans_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(dependencies_router)
api_v1_router.include_router(scores_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(health_router)
