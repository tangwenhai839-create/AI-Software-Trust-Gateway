"""Celery application used by production deployments."""
from celery import Celery

from backend.app.core.config import settings

celery_app = Celery(
    "astg",
    broker=settings.ASTG_REDIS_URL,
    backend=settings.ASTG_REDIS_URL,
    include=["backend.app.workers.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    timezone="UTC",
)
