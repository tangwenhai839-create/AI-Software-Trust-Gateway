"""AI Software Trust Gateway - 安全发现项 API (/api/v1/scans/{id}/findings)
"""
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from backend.app.domain.schemas import EvidenceSchema, FindingPageResponse, FindingSchema
from backend.app.db.session import async_session_factory
from backend.app.repositories.scan_repository import ScanRepository
from backend.app.services.queue import ScanQueueManager

router = APIRouter(prefix="/scans", tags=["Findings"])


@router.get("/{scan_id}/findings", response_model=FindingPageResponse)
async def list_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="筛选严重度: info, low, medium, high, critical"),
    category: Optional[str] = Query(None, description="筛选类别"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """
    分页并按类别/严重度筛选扫描发现项列表。
    """
    qm = ScanQueueManager.get_instance()
    scan = qm.scans_cache.get(scan_id)
    if not scan or (
        scan.status.value in ("completed", "partial")
        and scan_id not in qm.findings_cache
    ):
        async with async_session_factory() as session:
            repository = ScanRepository(session)
            scan_model = await repository.get_scan_by_id(scan_id)
            if not scan_model:
                raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"未找到扫描任务: {scan_id}"})
            db_items, total = await repository.get_findings_paged(
                scan_id, severity=severity, category=category, offset=(page - 1) * page_size, limit=page_size
            )
        schemas = [FindingSchema(
            id=f.id, fingerprint=f.fingerprint, scanner_name=f.scanner_name,
            category=f.category, title=f.title, severity=f.severity,
            confidence=f.confidence, file_path=f.file_path, line_start=f.line_start,
            line_end=f.line_end, remediation=f.remediation,
            evidences=[EvidenceSchema(id=e.id, kind=e.kind, source=e.source,
                location=e.location, excerpt_redacted=e.excerpt_redacted,
                sha256=e.sha256, attributes=e.attributes or {}) for e in f.evidences],
            ai_assessment=f.ai_assessment, status=f.status,
        ) for f in db_items]
        return FindingPageResponse(items=schemas, total=total, page=page, page_size=page_size)

    raw_findings = qm.findings_cache.get(scan_id, [])

    # 过滤
    filtered = []
    for f in raw_findings:
        if severity and f.severity.value != severity.lower():
            continue
        if category and f.category.value != category.lower():
            continue
        filtered.append(f)

    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    paged_items = filtered[start:end]

    schemas = []
    for f in paged_items:
        evs = [
            EvidenceSchema(
                id=e.id,
                kind=e.kind,
                source=e.source,
                location=e.location,
                excerpt_redacted=e.excerpt_redacted,
                sha256=e.sha256,
                attributes=e.attributes,
            )
            for e in f.evidences
        ]
        schemas.append(
            FindingSchema(
                id=f.id,
                fingerprint=f.fingerprint,
                scanner_name=f.scanner_name,
                category=f.category,
                title=f.title,
                severity=f.severity,
                confidence=f.confidence,
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                remediation=f.remediation,
                evidences=evs,
                ai_assessment=f.ai_assessment,
                status=f.status,
            )
        )

    return FindingPageResponse(
        items=schemas,
        total=total,
        page=page,
        page_size=page_size,
    )
