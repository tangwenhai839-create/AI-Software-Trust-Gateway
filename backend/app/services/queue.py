"""AI Software Trust Gateway - 后台任务调度与状态管理器 (In-process Async Queue Manager)
"""
import asyncio
from typing import Any, Callable, Dict, Optional

from backend.app.core.logging import logger
from backend.app.domain.enums import ScanStatus
from backend.app.domain.models import Project, Scan
from backend.app.services.orchestrator import ScanOrchestrator


class ScanQueueManager:
    """本地内置异步任务队列管理器，支持状态更新与任务取消"""

    _instance: Optional["ScanQueueManager"] = None

    def __init__(self):
        self.orchestrator = ScanOrchestrator()
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.cancel_flags: Dict[str, bool] = {}
        self.scans_cache: Dict[str, Scan] = {}
        self.projects_cache: Dict[str, Project] = {}
        self.findings_cache: Dict[str, list] = {}
        self.dependencies_cache: Dict[str, list] = {}
        self.scores_cache: Dict[str, Any] = {}
        self.artifacts_cache: Dict[str, Any] = {}

    @classmethod
    def get_instance(cls) -> "ScanQueueManager":
        if cls._instance is None:
            cls._instance = ScanQueueManager()
        return cls._instance

    def submit_scan(self, scan: Scan, project: Project) -> None:
        """提交并启动异步扫描任务"""
        self.scans_cache[scan.id] = scan
        self.projects_cache[project.id] = project
        self.cancel_flags[scan.id] = False

        task = asyncio.create_task(self._run_scan_job(scan.id, project.id))
        self.running_tasks[scan.id] = task

    async def _run_scan_job(self, scan_id: str, project_id: str) -> None:
        scan = self.scans_cache.get(scan_id)
        project = self.projects_cache.get(project_id)
        if not scan or not project:
            return

        def is_cancelled() -> bool:
            return self.cancel_flags.get(scan_id, False)

        try:
            res_scan, res_artifact, res_score, res_findings, res_deps, _ = await self.orchestrator.execute_scan(
                scan, project, is_cancelled_func=is_cancelled
            )
            self.scans_cache[scan_id] = res_scan
            self.findings_cache[scan_id] = res_findings
            self.dependencies_cache[scan_id] = res_deps
            if res_artifact:
                self.artifacts_cache[scan_id] = res_artifact
            if res_score:
                self.scores_cache[scan_id] = res_score
        except Exception as e:
            logger.error("异步扫描任务异常终止", scan_id=scan_id, error=str(e))
        finally:
            self.running_tasks.pop(scan_id, None)

    def cancel_scan(self, scan_id: str) -> bool:
        """取消指定扫描任务"""
        if scan_id in self.cancel_flags:
            self.cancel_flags[scan_id] = True
            scan = self.scans_cache.get(scan_id)
            if scan and scan.status.value in ("queued", "ingesting", "scanning", "reasoning"):
                scan.status = ScanStatus.CANCELLED
            if scan_id in self.running_tasks:
                self.running_tasks[scan_id].cancel()
            return True
        return False
