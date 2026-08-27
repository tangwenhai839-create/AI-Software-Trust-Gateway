"""Select the local or Celery task dispatcher from configuration."""
from backend.app.core.config import settings
from backend.app.domain.models import Project, Scan
from backend.app.services.queue import ScanQueueManager


def submit_scan(scan: Scan, project: Project) -> None:
    if settings.ASTG_QUEUE_MODE.lower() == "celery":
        try:
            from backend.app.workers.tasks import execute_scan_task
        except ImportError as exc:
            raise RuntimeError("Celery queue mode requires the 'celery' optional dependencies") from exc
        execute_scan_task.apply_async(args=[scan.id], task_id=scan.id)
        return
    ScanQueueManager.get_instance().submit_scan(scan, project)


def cancel_scan(scan_id: str) -> bool:
    if settings.ASTG_QUEUE_MODE.lower() == "celery":
        try:
            from backend.app.workers.celery_app import celery_app
        except ImportError:
            return False
        celery_app.control.revoke(scan_id, terminate=True)
        return True
    return ScanQueueManager.get_instance().cancel_scan(scan_id)
