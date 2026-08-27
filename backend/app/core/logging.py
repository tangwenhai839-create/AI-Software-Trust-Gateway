"""AI Software Trust Gateway - 结构化日志 (带敏感信息自动脱敏)
"""
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict

from backend.app.core.config import settings
from backend.app.core.security import redact_secrets


class RedactingJsonFormatter(logging.Formatter):
    """JSON 格式化器，在输出前对敏感信息进行正则脱敏"""
    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # 附加自定义字段
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated", "thread", "threadName",
                "processName", "process", "message"
            ):
                log_entry[key] = value

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        raw_json = json.dumps(log_entry, ensure_ascii=False)
        return redact_secrets(raw_json)


class StructuredLoggerWrapper:
    """包装标准 Logger，支持直接传递关键字参数至 extra"""
    def __init__(self, raw_logger: logging.Logger):
        self._raw = raw_logger

    def info(self, msg: str, *args, **kwargs):
        self._raw.info(msg, *args, extra=kwargs)

    def warning(self, msg: str, *args, **kwargs):
        self._raw.warning(msg, *args, extra=kwargs)

    def error(self, msg: str, *args, **kwargs):
        self._raw.error(msg, *args, extra=kwargs)

    def debug(self, msg: str, *args, **kwargs):
        self._raw.debug(msg, *args, extra=kwargs)


def setup_logger(name: str = "astg") -> StructuredLoggerWrapper:
    # Windows may inherit a legacy console code page. UTF-8 prevents Chinese
    # status messages from raising UnicodeEncodeError in installed builds.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="backslashreplace")
            except (OSError, ValueError):
                pass
    raw_logger = logging.getLogger(name)
    if not raw_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(RedactingJsonFormatter())
        raw_logger.addHandler(handler)
        raw_logger.setLevel(getattr(logging, settings.ASTG_LOG_LEVEL.upper(), logging.INFO))
        raw_logger.propagate = False
    return StructuredLoggerWrapper(raw_logger)


logger = setup_logger()
