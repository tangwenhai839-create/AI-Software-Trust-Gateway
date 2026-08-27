"""Dependency and vulnerability API."""
from fastapi import APIRouter, HTTPException

from backend.app.db.session import async_session_factory
from backend.app.domain.schemas import DependencyPageResponse, DependencySchema, VulnerabilitySchema
from backend.app.repositories.scan_repository import ScanRepository

router = APIRouter(prefix="/scans", tags=["Dependencies"])


@router.get("/{scan_id}/dependencies", response_model=DependencyPageResponse)
async def list_dependencies(scan_id: str):
    async with async_session_factory() as session:
        repository = ScanRepository(session)
        scan = await repository.get_scan_by_id(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"code": "SCAN_NOT_FOUND", "message": f"未找到扫描任务: {scan_id}"})
        items = await repository.get_dependencies_by_artifact_id(scan.artifact_id) if scan.artifact_id else []

    result = []
    for item in items:
        vulns = [VulnerabilitySchema(
            id=v.get("id", ""), advisory_id=v.get("advisory_id", ""), aliases=v.get("aliases", []),
            summary=v.get("summary", ""), details=v.get("details", ""),
            cvss_score=v.get("cvss_score"), severity=v.get("severity", "medium"),
            fixed_versions=v.get("fixed_versions", []), source_url=v.get("source_url", ""),
        ) for v in (item.vulnerabilities_json or [])]
        result.append(DependencySchema(
            id=item.id, ecosystem=item.ecosystem, name=item.name, version=item.version,
            scope=item.scope, manifest_path=item.manifest_path, vulnerabilities=vulns,
        ))
    return DependencyPageResponse(items=result, total=len(result))
