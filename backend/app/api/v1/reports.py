"""AI Software Trust Gateway - 报告获取与下载 API (/api/v1/scans/{id}/report)
"""
from datetime import datetime, timezone
import os
from pathlib import Path
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import FileResponse

from backend.app.core.config import settings
import json
from backend.app.db.session import async_session_factory
from backend.app.domain.schemas import AnalysisResponse, ReportResponse
from backend.app.repositories.scan_repository import ScanRepository
from backend.app.services.queue import ScanQueueManager

router = APIRouter(prefix="/scans", tags=["Reports"])


@router.get("/{scan_id}/report", response_model=ReportResponse)
async def get_report_meta(scan_id: str):
    """获取报告下载元数据与链接"""
    qm = ScanQueueManager.get_instance()
    scan = qm.scans_cache.get(scan_id)
    if not scan:
        async with async_session_factory() as session:
            scan = await ScanRepository(session).get_scan_by_id(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"未找到扫描任务: {scan_id}"})

    scan_dir = Path(settings.ASTG_ARTIFACTS_DIR) / scan_id
    if not (scan_dir / "report.json").exists():
        raise HTTPException(status_code=400, detail={"code": "REPORT_NOT_READY", "message": "报告尚未生成或任务未完成"})

    return ReportResponse(
        scan_id=scan_id,
        schema_version="1.0",
        html_url=f"/api/v1/scans/{scan_id}/report.html",
        json_url=f"/api/v1/scans/{scan_id}/report.json",
        generated_at=scan.completed_at or datetime.now(timezone.utc),
    )


@router.get("/{scan_id}/analysis", response_model=AnalysisResponse)
async def get_analysis(scan_id: str):
    scan_dir = Path(settings.ASTG_ARTIFACTS_DIR) / scan_id
    json_path = scan_dir / "report.json"
    if not json_path.exists():
        raise HTTPException(status_code=404, detail={"code": "REPORT_NOT_FOUND", "message": "分析报告尚未生成"})
    with open(json_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return AnalysisResponse(
        scan_id=scan_id,
        purpose_profile=data.get("purpose_profile", {}),
        provenance=data.get("provenance", {}),
        ai_analysis=data.get("ai_analysis", {}),
        scanner_runs=data.get("scanner_runs", []),
        coverage=data.get("coverage", {}),
        dynamic_analysis=data.get("dynamic_analysis", {}),
    )


@router.get("/{scan_id}/report.json")
async def download_json_report(scan_id: str):
    """下载或查看 JSON 格式报告"""
    scan_dir = Path(settings.ASTG_ARTIFACTS_DIR) / scan_id
    json_path = scan_dir / "report.json"
    if not json_path.exists():
        raise HTTPException(status_code=404, detail={"code": "REPORT_NOT_FOUND", "message": "JSON 报告文件不存在"})

    return FileResponse(
        str(json_path),
        media_type="application/json",
        filename=f"astg-report-{scan_id}.json",
    )


@router.get("/{scan_id}/report.html")
async def download_html_report(scan_id: str):
    """下载或直接在浏览器中浏览单文件独立 HTML 报告"""
    scan_dir = Path(settings.ASTG_ARTIFACTS_DIR) / scan_id
    html_path = scan_dir / "report.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail={"code": "REPORT_NOT_FOUND", "message": "HTML 报告文件不存在"})

    return FileResponse(
        str(html_path),
        media_type="text/html",
        filename=f"astg-report-{scan_id}.html",
    )
