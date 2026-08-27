"""Serializable Celery scan tasks."""
import asyncio

from backend.app.db.session import async_session_factory, init_db
from backend.app.domain.enums import ScanStage, ScanStatus
from backend.app.domain.models import Project, Scan
from backend.app.repositories.scan_repository import ScanRepository
from backend.app.services.orchestrator import ScanOrchestrator
from backend.app.workers.celery_app import celery_app


async def _execute_persisted_scan(scan_id: str) -> None:
    await init_db()
    async with async_session_factory() as session:
        repository = ScanRepository(session)
        model = await repository.get_scan_by_id(scan_id)
        if not model or not model.project:
            raise RuntimeError(f"Scan not found: {scan_id}")
        project = Project(
            id=model.project.id,
            source_type=model.project.source_type,
            canonical_url=model.project.canonical_url,
            owner=model.project.owner,
            name=model.project.name,
            default_branch=model.project.default_branch,
        )
        scan = Scan(
            id=model.id,
            project_id=model.project_id or "",
            artifact_id=model.artifact_id or "",
            target_url=model.target_url,
            target_ref=model.target_ref,
            resolved_commit_sha=model.resolved_commit_sha or "",
            profile=model.profile,
            status=ScanStatus(model.status),
            stage=ScanStage(model.stage),
            progress_pct=model.progress_pct,
            requested_at=model.requested_at,
            ai_config=model.ai_config or {},
        )
    await ScanOrchestrator().execute_scan(scan, project)


@celery_app.task(name="astg.execute_scan")
def execute_scan_task(scan_id: str) -> None:
    asyncio.run(_execute_persisted_scan(scan_id))
