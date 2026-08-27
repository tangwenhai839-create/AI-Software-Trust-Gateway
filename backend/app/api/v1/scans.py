"""AI Software Trust Gateway - 扫描任务管理 API (/api/v1/scans)
"""
from typing import List, Optional
from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import JSONResponse

from backend.app.core.errors import ASTGException, ScanNotFoundError, SSRFValidationError
from backend.app.db.models import ScanModel
from backend.app.db.session import async_session_factory, init_db
from backend.app.domain.enums import RiskLevel, ScanStage, ScanStatus
from backend.app.domain.models import Project, Scan
from backend.app.domain.schemas import CreateScanRequest, CreateScanResponse, ScanListResponse, ScanSummaryResponse, ScoreSchema
from backend.app.ingestion.url_validator import GitHubUrlValidator
from backend.app.repositories.scan_repository import ScanRepository
from backend.app.services.queue import ScanQueueManager
from backend.app.services.dispatcher import cancel_scan as dispatch_cancel_scan, submit_scan

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=CreateScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(req: CreateScanRequest, idempotency_key: Optional[str] = Header(None)):
    """
    创建并提交新的软件可信评估任务。
    返回 202 Accepted 及任务状态查询 URL。
    """
    await init_db()
    target_url = req.source.url.strip()

    # URL 与 SSRF 校验 (除非是显式的 local:// 用于内部测试)
    if not target_url.startswith("local://"):
        try:
            canonical_url, owner, repo_name = GitHubUrlValidator.validate(target_url)
        except SSRFValidationError as e:
            raise HTTPException(status_code=400, detail={"code": e.code, "message": e.message})
    else:
        canonical_url = target_url
        owner, repo_name = "local", "local-project"

    project = Project(
        source_type=req.source.type,
        canonical_url=canonical_url,
        owner=owner,
        name=repo_name,
        default_branch=req.source.ref or "main",
    )

    ai_dict = req.ai.model_dump() if req.ai else {}

    scan = Scan(
        project_id=project.id,
        target_url=canonical_url,
        target_ref=req.source.ref or "main",
        profile=req.profile,
        ai_config=ai_dict,
    )

    async with async_session_factory() as session:
        repository = ScanRepository(session)
        await repository.ensure_domain_scan(project, scan)
        await session.commit()

    submit_scan(scan, project)

    return CreateScanResponse(
        scan_id=scan.id,
        status=scan.status,
        stage=scan.stage,
        status_url=f"/api/v1/scans/{scan.id}",
        created_at=scan.requested_at,
    )


def _score_schema(score_obj):
    if not score_obj:
        return None
    return ScoreSchema(
        scoring_version=score_obj.scoring_version,
        safety_score=score_obj.safety_score,
        risk_score=score_obj.risk_score,
        risk_level=score_obj.risk_level,
        confidence=score_obj.confidence,
        coverage=score_obj.coverage,
        components=score_obj.components or {},
        caps_applied=score_obj.caps_applied or [],
    )


async def _db_summary(scan_model: ScanModel) -> ScanSummaryResponse:
    async with async_session_factory() as session:
        repository = ScanRepository(session)
        artifact = await repository.get_artifact(scan_model.artifact_id) if scan_model.artifact_id else None
        findings_count, dependencies_count, vulnerabilities_count = await repository.get_scan_counts(
            scan_model.id, scan_model.artifact_id
        )
        score_obj = await repository.get_score_by_scan_id(scan_model.id)
    return ScanSummaryResponse(
        scan_id=scan_model.id,
        target_url=scan_model.target_url,
        target_ref=scan_model.target_ref,
        resolved_commit_sha=scan_model.resolved_commit_sha,
        status=scan_model.status,
        stage=scan_model.stage,
        progress_pct=scan_model.progress_pct,
        error_summary=scan_model.error_summary,
        languages=(artifact.languages or []) if artifact else [],
        findings_count=findings_count,
        dependencies_count=dependencies_count,
        vulnerabilities_count=vulnerabilities_count,
        score=_score_schema(score_obj),
        ai_enabled=bool((scan_model.ai_config or {}).get("enabled", False)),
        requested_at=scan_model.requested_at,
        started_at=scan_model.started_at,
        completed_at=scan_model.completed_at,
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(limit: int = 20):
    limit = max(1, min(limit, 100))
    async with async_session_factory() as session:
        models = await ScanRepository(session).list_recent_scans(limit)
    items = [await _db_summary(item) for item in models]
    return ScanListResponse(items=items, total=len(items))


@router.get("/{scan_id}", response_model=ScanSummaryResponse)
async def get_scan_summary(scan_id: str):
    """
    查询扫描任务的当前状态、执行阶段、进度、发现数与安全评分摘要。
    """
    qm = ScanQueueManager.get_instance()
    scan = qm.scans_cache.get(scan_id)
    if not scan:
        async with async_session_factory() as session:
            scan_model = await ScanRepository(session).get_scan_by_id(scan_id)
        if not scan_model:
            raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"未找到扫描任务: {scan_id}"})
        return await _db_summary(scan_model)

    # The orchestrator mutates the in-memory Scan object before the queue
    # publishes its result caches. During that tiny terminal-state window,
    # prefer the last transactionally consistent database snapshot instead
    # of briefly reporting completed + zero findings/no score.
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL) and (
        scan_id not in qm.scores_cache
        or scan_id not in qm.findings_cache
        or scan_id not in qm.dependencies_cache
    ):
        async with async_session_factory() as session:
            scan_model = await ScanRepository(session).get_scan_by_id(scan_id)
        if scan_model:
            return await _db_summary(scan_model)

    findings = qm.findings_cache.get(scan_id, [])
    deps = qm.dependencies_cache.get(scan_id, [])
    score_obj = qm.scores_cache.get(scan_id)

    total_vulns = sum(len(d.vulnerabilities) for d in deps)

    score_schema = _score_schema(score_obj)
    artifact = qm.artifacts_cache.get(scan_id)

    return ScanSummaryResponse(
        scan_id=scan.id,
        target_url=scan.target_url,
        target_ref=scan.target_ref,
        resolved_commit_sha=scan.resolved_commit_sha,
        status=scan.status,
        stage=scan.stage,
        progress_pct=scan.progress_pct,
        error_summary=scan.error_summary,
        languages=artifact.languages if artifact else [],
        findings_count=len(findings),
        dependencies_count=len(deps),
        vulnerabilities_count=total_vulns,
        score=score_schema,
        ai_enabled=scan.ai_config.get("enabled", False),
        requested_at=scan.requested_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """
    取消正在进行中的扫描任务。
    """
    success = dispatch_cancel_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"任务不存在或无法取消: {scan_id}"})
    async with async_session_factory() as session:
        await ScanRepository(session).update_scan_status(
            scan_id=scan_id,
            status=ScanStatus.CANCELLED.value,
            stage=ScanStage.FINISHED.value,
        )
        await session.commit()
    return {"message": "扫描任务已请求取消", "scan_id": scan_id}
