"""AI Software Trust Gateway - 数据持久化仓储层 (SQLAlchemy 2.0 Async Repository)
"""
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.db.models import (
    ArtifactModel,
    DependencyModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
    ReportModel,
    ScanModel,
    ScoreModel,
)
from backend.app.domain.enums import DependencyScope, Ecosystem, FindingCategory, RiskLevel, ScanStage, ScanStatus, Severity
from backend.app.domain.models import Artifact, Dependency, Evidence, Finding, Project, Scan, Score, Vulnerability


class ScanRepository:
    """持久化仓储操作实现"""

    def __init__(self, session: AsyncSession):
        self.session = session

    # ==========================================
    # Project 仓储
    # ==========================================
    async def get_or_create_project(self, canonical_url: str, owner: str, name: str, source_type: str = "github", default_branch: str = "main") -> ProjectModel:
        stmt = select(ProjectModel).where(ProjectModel.canonical_url == canonical_url)
        res = await self.session.execute(stmt)
        project = res.scalar_one_or_none()
        if not project:
            project = ProjectModel(
                canonical_url=canonical_url,
                owner=owner,
                name=name,
                source_type=source_type,
                default_branch=default_branch,
            )
            self.session.add(project)
            await self.session.flush()
        return project

    # ==========================================
    # Scan 仓储
    # ==========================================
    async def create_scan(self, scan: ScanModel) -> ScanModel:
        self.session.add(scan)
        await self.session.flush()
        return scan

    async def ensure_domain_scan(self, project: Project, scan: Scan) -> ScanModel:
        """Ensure the project and scan exist before workflow state is persisted."""
        project_model = await self.get_or_create_project(
            canonical_url=project.canonical_url,
            owner=project.owner or "local",
            name=project.name or "project",
            source_type=project.source_type,
            default_branch=project.default_branch,
        )
        project.id = project_model.id
        scan.project_id = project_model.id

        existing = await self.get_scan_by_id(scan.id)
        if existing:
            return existing

        model = ScanModel(
            id=scan.id,
            project_id=project_model.id,
            artifact_id=scan.artifact_id or None,
            target_url=scan.target_url,
            target_ref=scan.target_ref,
            resolved_commit_sha=scan.resolved_commit_sha or None,
            profile=scan.profile,
            status=scan.status.value if isinstance(scan.status, ScanStatus) else str(scan.status),
            stage=scan.stage.value if isinstance(scan.stage, ScanStage) else str(scan.stage),
            progress_pct=scan.progress_pct,
            error_summary=scan.error_summary,
            error_details=scan.error_details,
            ai_config=scan.ai_config,
            requested_at=scan.requested_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
        )
        return await self.create_scan(model)

    async def update_scan_status(
        self,
        scan_id: str,
        status: Optional[str] = None,
        stage: Optional[str] = None,
        progress_pct: Optional[int] = None,
        resolved_commit_sha: Optional[str] = None,
        artifact_id: Optional[str] = None,
        error_summary: Optional[str] = None,
        error_details: Optional[Dict[str, Any]] = None,
        started_at: Optional[Any] = None,
        completed_at: Optional[Any] = None,
    ) -> Optional[ScanModel]:
        stmt = select(ScanModel).where(ScanModel.id == scan_id)
        res = await self.session.execute(stmt)
        scan = res.scalar_one_or_none()
        if not scan:
            return None

        if status is not None:
            scan.status = status
        if stage is not None:
            scan.stage = stage
        if progress_pct is not None:
            scan.progress_pct = progress_pct
        if resolved_commit_sha is not None:
            scan.resolved_commit_sha = resolved_commit_sha
        if artifact_id is not None:
            scan.artifact_id = artifact_id
        if error_summary is not None:
            scan.error_summary = error_summary
        if error_details is not None:
            scan.error_details = error_details
        if started_at is not None:
            scan.started_at = started_at
        if completed_at is not None:
            scan.completed_at = completed_at

        await self.session.flush()
        return scan

    async def get_scan_by_id(self, scan_id: str) -> Optional[ScanModel]:
        stmt = select(ScanModel).options(
            selectinload(ScanModel.score),
            selectinload(ScanModel.project),
            selectinload(ScanModel.report),
        ).where(ScanModel.id == scan_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_recent_scans(self, limit: int = 20) -> List[ScanModel]:
        stmt = select(ScanModel).options(
            selectinload(ScanModel.score),
            selectinload(ScanModel.project),
        ).order_by(desc(ScanModel.requested_at)).limit(limit)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def get_scan_counts(self, scan_id: str, artifact_id: Optional[str]) -> Tuple[int, int, int]:
        finding_result = await self.session.execute(
            select(func.count(FindingModel.id)).where(FindingModel.scan_id == scan_id)
        )
        findings_count = int(finding_result.scalar_one())
        if not artifact_id:
            return findings_count, 0, 0
        dependencies = await self.get_dependencies_by_artifact_id(artifact_id)
        vulnerabilities_count = sum(len(item.vulnerabilities_json or []) for item in dependencies)
        return findings_count, len(dependencies), vulnerabilities_count

    # ==========================================
    # Artifact 仓储
    # ==========================================
    async def save_artifact(self, artifact: Artifact) -> ArtifactModel:
        model = ArtifactModel(
            id=artifact.id,
            project_id=artifact.project_id,
            commit_sha=artifact.commit_sha,
            sha256=artifact.sha256,
            local_path=artifact.local_path,
            size_bytes=artifact.size_bytes,
            file_count=artifact.file_count,
            languages=artifact.languages,
            manifest_paths=artifact.manifest_paths,
            entrypoints=artifact.entrypoints,
        )
        self.session.add(model)
        await self.session.flush()
        return model

    async def get_artifact(self, artifact_id: str) -> Optional[ArtifactModel]:
        stmt = select(ArtifactModel).where(ArtifactModel.id == artifact_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    # ==========================================
    # Findings 仓储
    # ==========================================
    async def save_findings(self, findings: List[Finding]) -> None:
        for f in findings:
            f_model = FindingModel(
                id=f.id,
                scan_id=f.scan_id,
                scanner_name=f.scanner_name,
                fingerprint=f.fingerprint,
                category=f.category.value if isinstance(f.category, FindingCategory) else str(f.category),
                title=f.title,
                severity=f.severity.value if isinstance(f.severity, Severity) else str(f.severity),
                confidence=f.confidence,
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                remediation=f.remediation,
                ai_assessment=f.ai_assessment,
                status=f.status,
            )
            self.session.add(f_model)
            await self.session.flush()

            for ev in f.evidences:
                ev_model = EvidenceModel(
                    id=ev.id,
                    finding_id=f_model.id,
                    kind=ev.kind,
                    source=ev.source,
                    location=ev.location,
                    excerpt_redacted=ev.excerpt_redacted,
                    sha256=ev.sha256,
                    attributes=ev.attributes,
                )
                self.session.add(ev_model)
        await self.session.flush()

    async def get_findings_paged(
        self, scan_id: str, severity: Optional[str] = None, category: Optional[str] = None, offset: int = 0, limit: int = 50
    ) -> Tuple[List[FindingModel], int]:
        query = select(FindingModel).options(selectinload(FindingModel.evidences)).where(FindingModel.scan_id == scan_id)
        if severity:
            query = query.where(FindingModel.severity == severity.lower())
        if category:
            query = query.where(FindingModel.category == category.lower())

        count_query = select(func.count(FindingModel.id)).where(FindingModel.scan_id == scan_id)
        if severity:
            count_query = count_query.where(FindingModel.severity == severity.lower())
        if category:
            count_query = count_query.where(FindingModel.category == category.lower())

        total_res = await self.session.execute(count_query)
        total = total_res.scalar_one()

        paged_query = query.order_by(FindingModel.line_start).offset(offset).limit(limit)
        res = await self.session.execute(paged_query)
        items = list(res.scalars().all())

        return items, total

    # ==========================================
    # Dependencies 仓储
    # ==========================================
    async def save_dependencies(self, dependencies: List[Dependency]) -> None:
        for dep in dependencies:
            vulns_json = [
                {
                    "id": v.id,
                    "advisory_id": v.advisory_id,
                    "aliases": v.aliases,
                    "summary": v.summary,
                    "details": v.details,
                    "cvss_score": v.cvss_score,
                    "severity": v.severity.value if isinstance(v.severity, Severity) else str(v.severity),
                    "fixed_versions": v.fixed_versions,
                    "source_url": v.source_url,
                }
                for v in dep.vulnerabilities
            ]
            dep_model = DependencyModel(
                id=dep.id,
                artifact_id=dep.artifact_id,
                ecosystem=dep.ecosystem.value if isinstance(dep.ecosystem, Ecosystem) else str(dep.ecosystem),
                name=dep.name,
                version=dep.version,
                scope=dep.scope.value if isinstance(dep.scope, DependencyScope) else str(dep.scope),
                manifest_path=dep.manifest_path,
                vulnerabilities_json=vulns_json,
            )
            self.session.add(dep_model)
        await self.session.flush()

    async def get_dependencies_by_artifact_id(self, artifact_id: str) -> List[DependencyModel]:
        stmt = select(DependencyModel).where(DependencyModel.artifact_id == artifact_id)
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def get_score_by_scan_id(self, scan_id: str) -> Optional[ScoreModel]:
        stmt = select(ScoreModel).where(ScoreModel.scan_id == scan_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_report_by_scan_id(self, scan_id: str) -> Optional[ReportModel]:
        stmt = select(ReportModel).where(ReportModel.scan_id == scan_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    # ==========================================
    # Score 仓储
    # ==========================================
    async def save_score(self, score: Score) -> ScoreModel:
        model = ScoreModel(
            id=score.id,
            scan_id=score.scan_id,
            scoring_version=score.scoring_version,
            safety_score=score.safety_score,
            risk_score=score.risk_score,
            risk_level=score.risk_level.value if isinstance(score.risk_level, RiskLevel) else str(score.risk_level),
            confidence=score.confidence,
            coverage=score.coverage,
            components=score.components,
            caps_applied=score.caps_applied,
        )
        self.session.add(model)
        await self.session.flush()
        return model

    # ==========================================
    # Report 仓储
    # ==========================================
    async def save_report_meta(self, scan_id: str, json_path: str, html_path: str, json_sha256: str, html_sha256: str) -> ReportModel:
        model = ReportModel(
            scan_id=scan_id,
            schema_version="1.0",
            json_path=json_path,
            html_path=html_path,
            json_sha256=json_sha256,
            html_sha256=html_sha256,
        )
        self.session.add(model)
        await self.session.flush()
        return model
