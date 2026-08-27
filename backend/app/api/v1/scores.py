"""AI Software Trust Gateway - 安全评分 API (/api/v1/scans/{id}/score)
"""
from fastapi import APIRouter, HTTPException

from backend.app.domain.schemas import ScoreSchema
from backend.app.services.queue import ScanQueueManager
from backend.app.db.session import async_session_factory
from backend.app.repositories.scan_repository import ScanRepository

router = APIRouter(prefix="/scans", tags=["Scores"])


@router.get("/{scan_id}/score", response_model=ScoreSchema)
async def get_scan_score(scan_id: str):
    """
    获取扫描任务的安全评分、风险分、覆盖率、分项及应用的上限规则。
    """
    qm = ScanQueueManager.get_instance()
    score_obj = qm.scores_cache.get(scan_id)
    if not score_obj:
        async with async_session_factory() as session:
            repository = ScanRepository(session)
            scan = await repository.get_scan_by_id(scan_id)
            score_obj = await repository.get_score_by_scan_id(scan_id) if scan else None
        if not scan:
            raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"未找到扫描任务: {scan_id}"})
        if not score_obj:
            raise HTTPException(status_code=400, detail={"code": "SCORE_NOT_READY", "message": "该扫描任务尚未完成评分计算"})

    return ScoreSchema(
        scoring_version=score_obj.scoring_version,
        safety_score=score_obj.safety_score,
        risk_score=score_obj.risk_score,
        risk_level=score_obj.risk_level,
        confidence=score_obj.confidence,
        coverage=score_obj.coverage,
        components=score_obj.components,
        caps_applied=score_obj.caps_applied,
    )
