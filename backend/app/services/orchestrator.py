"""AI Software Trust Gateway - 扫描任务全生命周期编排器 (Scan Orchestrator)
"""
import shutil
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.app.core.config import settings
from backend.app.core.errors import ASTGException
from backend.app.core.logging import logger
from backend.app.db.session import async_session_factory, init_db
from backend.app.dependencies.analyzer import DependencyAnalyzer
from backend.app.dynamic.disabled import DisabledDynamicAnalysisProvider
from backend.app.domain.enums import ScanStage, ScanStatus
from backend.app.domain.models import Artifact, Dependency, Finding, Project, PurposeProfile, Scan, Score
from backend.app.ingestion.fetcher import SafeRepoFetcher
from backend.app.ingestion.project_analyzer import ProjectStructureAnalyzer
from backend.app.provenance.github_client import ProvenanceAnalyzer
from backend.app.reasoning.disabled import DisabledAIProvider
from backend.app.reasoning.openai_adapter import OpenAICompatibleAIProvider
from backend.app.reasoning.purpose import PurposeExtractor
from backend.app.reports.reporter import ReportGenerator
from backend.app.repositories.scan_repository import ScanRepository
from backend.app.scanners.bandit import BanditScanner
from backend.app.scanners.deduplicator import FindingDeduplicator
from backend.app.scanners.regex_rules import NativeASTPythonScanner, NativeJSPatternScanner
from backend.app.scanners.semgrep import SemgrepScanner
from backend.app.services.scoring import DeterministicScoringEngine


class ScanOrchestrator:
    """编排一次完整的安全可信评估生命周期，包含真实数据库持久化与降级处理"""

    def __init__(self):
        self.fetcher = SafeRepoFetcher()
        self.dep_analyzer = DependencyAnalyzer()
        self.scoring_engine = DeterministicScoringEngine()
        self.report_generator = ReportGenerator()
        self.scanners = [
            NativeASTPythonScanner(),
            NativeJSPatternScanner(),
            SemgrepScanner(),
            BanditScanner(),
        ]

    async def execute_scan(
        self,
        scan: Scan,
        project: Project,
        is_cancelled_func=None,
    ) -> Tuple[Scan, Optional[Artifact], Optional[Score], List[Finding], List[Dependency], Dict[str, Any]]:
        """
        执行扫描任务：
        queued -> ingesting -> scanning -> reasoning -> scoring -> reporting -> completed / partial / failed
        """
        scan.status = ScanStatus.INGESTING
        scan.stage = ScanStage.INGESTION
        scan.started_at = datetime.now(timezone.utc)
        scan.progress_pct = 10
        logger.info("开始执行扫描任务", scan_id=scan.id, url=scan.target_url)

        findings: List[Finding] = []
        dependencies: List[Dependency] = []
        provenance: Dict[str, Any] = {}
        ai_result: Dict[str, Any] = {}
        dynamic_result: Dict[str, Any] = {}
        scanner_runs: List[Dict[str, Any]] = []

        coverage = {"static": 1.0, "dependencies": 1.0, "dynamic": 0.0}
        is_degraded = False

        # Ensure direct orchestrator callers and queued API callers share the
        # same persistence invariant: a scan row always exists first.
        await init_db()
        async with async_session_factory() as session:
            repo = ScanRepository(session)
            await repo.ensure_domain_scan(project, scan)
            await repo.update_scan_status(
                scan_id=scan.id,
                status=scan.status.value,
                stage=scan.stage.value,
                progress_pct=scan.progress_pct,
                started_at=scan.started_at,
            )
            await session.commit()

        try:
            if is_cancelled_func and is_cancelled_func():
                scan.status = ScanStatus.CANCELLED
                await self._persist_failure(scan, "用户手动取消任务")
                return scan, None, None, [], [], {}

            # ==========================================
            # 阶段 1: 安全获取与仓库解压 (Ingestion)
            # ==========================================
            if scan.target_url.startswith("local://"):
                local_dir = scan.target_url.replace("local://", "")
                repo_dir, commit_sha, archive_sha256, sz, count = self.fetcher.ingest_local_directory(
                    local_dir, scan_id=scan.id
                )
            else:
                repo_dir, commit_sha, archive_sha256, sz, count = await self.fetcher.fetch_github_repository(
                    scan.target_url, ref=scan.target_ref, scan_id=scan.id
                )

            scan.resolved_commit_sha = commit_sha
            languages, manifest_paths, entrypoints = ProjectStructureAnalyzer.analyze(repo_dir)

            artifact = Artifact(
                project_id=project.id,
                commit_sha=commit_sha,
                sha256=archive_sha256,
                local_path=repo_dir,
                size_bytes=sz,
                file_count=count,
                languages=languages,
                manifest_paths=manifest_paths,
                entrypoints=entrypoints,
            )
            scan.artifact_id = artifact.id
            scan.progress_pct = 25

            # 持久化 Artifact
            async with async_session_factory() as session:
                repo = ScanRepository(session)
                await repo.save_artifact(artifact)
                await repo.update_scan_status(
                    scan_id=scan.id,
                    artifact_id=artifact.id,
                    resolved_commit_sha=commit_sha,
                    progress_pct=scan.progress_pct,
                )
                await session.commit()

            if is_cancelled_func and is_cancelled_func():
                scan.status = ScanStatus.CANCELLED
                await self._persist_failure(scan, "用户手动取消任务")
                return scan, artifact, None, [], [], {}

            # ==========================================
            # 阶段 2: 静态扫描与依赖分析 (Scanning)
            # ==========================================
            scan.status = ScanStatus.SCANNING
            scan.stage = ScanStage.STATIC_ANALYSIS

            # 执行静态扫描器并追踪状态
            raw_findings: List[Finding] = []
            applicable_scanners = 0
            successful_scanners = 0

            for sc in self.scanners:
                normalized_languages = {lang.lower() for lang in languages}
                external_expected = (
                    (sc.name == "semgrep" and bool(normalized_languages & {"python", "javascript", "typescript"}))
                    or (sc.name == "bandit" and "python" in normalized_languages)
                )
                if external_expected and shutil.which(sc.name) is None:
                    scanner_runs.append({
                        "scanner": sc.name,
                        "version": sc.version,
                        "status": "unavailable",
                        "error": f"{sc.name} executable is not installed",
                    })
                    if settings.ASTG_REQUIRE_EXTERNAL_SCANNERS:
                        applicable_scanners += 1
                        is_degraded = True
                    continue
                if sc.is_applicable(languages, repo_dir):
                    applicable_scanners += 1
                    try:
                        sf = await sc.scan(repo_dir, scan.id)
                        raw_findings.extend(sf)
                        successful_scanners += 1
                        scanner_runs.append({"scanner": sc.name, "version": sc.version, "status": "success", "findings_count": len(sf)})
                    except Exception as e:
                        logger.warning(f"扫描器 {sc.name} 执行异常", scan_id=scan.id, error=str(e))
                        scanner_runs.append({"scanner": sc.name, "version": sc.version, "status": "failed", "error": str(e)})
                        is_degraded = True

            if applicable_scanners > 0:
                coverage["static"] = round(successful_scanners / applicable_scanners, 2)
            else:
                coverage["static"] = 1.0

            # 去重与证据融合
            findings = FindingDeduplicator.deduplicate_and_fuse(raw_findings)
            scan.progress_pct = 50

            # 依赖分析与 OSV 查询
            scan.stage = ScanStage.DEPENDENCY_ANALYSIS
            dependencies, osv_success = await self.dep_analyzer.analyze_dependencies(
                repo_dir, manifest_paths, artifact_id=artifact.id
            )
            if not osv_success:
                coverage["dependencies"] = 0.50
                is_degraded = True

            scan.progress_pct = 65

            # 溯源分析
            if not scan.target_url.startswith("local://"):
                provenance = await ProvenanceAnalyzer.analyze_github_repo(scan.target_url)

            # Dynamic execution is a strict provider boundary. The built-in
            # provider records non-execution; it never runs untrusted code on
            # the host when an isolated provider is unavailable.
            dynamic_provider = DisabledDynamicAnalysisProvider()
            dynamic_result = await dynamic_provider.analyze(repo_dir, scan.id)
            coverage["dynamic"] = float(dynamic_result.get("coverage", 0.0))
            scanner_runs.append({
                "scanner": "dynamic_sandbox",
                "version": "1.0",
                "status": dynamic_result.get("status", "not_run"),
                "provider": dynamic_result.get("provider", "disabled"),
            })
            if settings.ASTG_DYNAMIC_ENABLED and settings.ASTG_DYNAMIC_PROVIDER == "disabled":
                is_degraded = True
                dynamic_result["configuration_error"] = (
                    "ASTG_DYNAMIC_ENABLED=true, but no isolated dynamic provider is configured"
                )

            # ==========================================
            # 阶段 3: 用途提取与 AI 推理 (Reasoning)
            # ==========================================
            scan.status = ScanStatus.REASONING
            scan.stage = ScanStage.AI_REASONING

            purpose_profile = PurposeExtractor.extract_purpose(repo_dir, scan.id)
            readme_excerpt = PurposeExtractor.read_readme_excerpt(repo_dir, max_chars=2000)

            ai_cfg = scan.ai_config or {}
            ai_provider_name = ai_cfg.get("provider", settings.ASTG_AI_PROVIDER)
            ai_enabled = ai_cfg.get("enabled", settings.ASTG_AI_ENABLED)

            if ai_enabled and ai_provider_name == "openai_compatible":
                ai_provider = OpenAICompatibleAIProvider(model=ai_cfg.get("model") or settings.ASTG_AI_MODEL)
            else:
                ai_provider = DisabledAIProvider()

            target_info = {
                "type": "github" if not scan.target_url.startswith("local://") else "local",
                "commit_sha": commit_sha,
                "languages": languages,
            }

            try:
                ai_result = await ai_provider.reason(
                    scan_id=scan.id,
                    purpose_profile=purpose_profile,
                    target_info=target_info,
                    findings=findings,
                    coverage=coverage,
                    dependencies=dependencies,
                    provenance=provenance,
                    dynamic_analysis=dynamic_result,
                    untrusted_readme_excerpt=readme_excerpt,
                )

                # 回填 AI Finding Assessments 至各 Finding 对象
                if ai_result and "finding_assessments" in ai_result:
                    ai_finding_map = {item.get("finding_id"): item for item in ai_result["finding_assessments"]}
                    for f in findings:
                        if f.id in ai_finding_map:
                            f.ai_assessment = ai_finding_map[f.id]

            except Exception as e:
                logger.warning("AI 推理模块执行失败或校验回退", scan_id=scan.id, error=str(e))
                ai_result = {}

            scan.progress_pct = 80

            # ==========================================
            # 阶段 4: 确定性评分 (Scoring)
            # ==========================================
            scan.status = ScanStatus.SCORING
            scan.stage = ScanStage.SCORING

            score = self.scoring_engine.calculate_score(
                scan_id=scan.id,
                findings=findings,
                dependencies=dependencies,
                provenance=provenance,
                ai_assessment=ai_result,
                coverage=coverage,
            )
            scan.progress_pct = 90

            # ==========================================
            # 阶段 5: 报告生成与持久化 (Reporting & Persistence)
            # ==========================================
            scan.status = ScanStatus.REPORTING
            scan.stage = ScanStage.REPORT_GENERATION

            # 最终任务状态判定
            final_status = ScanStatus.PARTIAL if is_degraded else ScanStatus.COMPLETED

            scan.status = final_status
            scan.stage = ScanStage.FINISHED
            scan.progress_pct = 100
            scan.completed_at = datetime.now(timezone.utc)

            json_p, html_p, j_hash, h_hash = self.report_generator.generate_reports(
                scan=scan,
                project=project,
                artifact=artifact,
                score=score,
                findings=findings,
                dependencies=dependencies,
                provenance=provenance,
                purpose=purpose_profile,
                ai_analysis=ai_result,
                coverage=coverage,
                scanner_runs=scanner_runs,
                dynamic_analysis=dynamic_result,
            )

            # 持久化 Findings, Dependencies, Score, Report
            async with async_session_factory() as session:
                repo = ScanRepository(session)
                await repo.save_findings(findings)
                await repo.save_dependencies(dependencies)
                await repo.save_score(score)
                await repo.save_report_meta(scan.id, json_p, html_p, j_hash, h_hash)
                await repo.update_scan_status(
                    scan_id=scan.id,
                    status=scan.status.value,
                    stage=scan.stage.value,
                    progress_pct=100,
                    completed_at=scan.completed_at,
                )
                await session.commit()

            logger.info("扫描任务顺利完成并持久化", scan_id=scan.id, score=score.safety_score, status=final_status.value)
            return scan, artifact, score, findings, dependencies, ai_result

        except Exception as e:
            logger.error("扫描流程发生异常", scan_id=scan.id, error=str(e), traceback=traceback.format_exc())
            scan.status = ScanStatus.FAILED
            scan.stage = ScanStage.FINISHED
            scan.error_summary = str(e)
            scan.error_details = {"traceback": traceback.format_exc()}
            scan.completed_at = datetime.now(timezone.utc)
            await self._persist_failure(scan, str(e))
            return scan, None, None, findings, dependencies, ai_result

    async def _persist_failure(self, scan: Scan, error_msg: str):
        try:
            async with async_session_factory() as session:
                repo = ScanRepository(session)
                await repo.update_scan_status(
                    scan_id=scan.id,
                    status=scan.status.value,
                    stage=scan.stage.value,
                    progress_pct=scan.progress_pct,
                    error_summary=error_msg,
                    completed_at=datetime.now(timezone.utc),
                )
                await session.commit()
        except Exception:
            pass
