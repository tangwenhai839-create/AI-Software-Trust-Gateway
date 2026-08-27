"""Isolated test database configuration."""
import os
import tempfile
import uuid
from pathlib import Path

_TEST_DB = Path(tempfile.gettempdir()) / f"astg-test-{uuid.uuid4().hex}.db"
os.environ["ASTG_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DB.as_posix()}"
os.environ["ASTG_ARTIFACTS_DIR"] = str(Path(tempfile.gettempdir()) / f"astg-artifacts-{uuid.uuid4().hex}")


def pytest_sessionfinish(session, exitstatus):
    try:
        _TEST_DB.unlink(missing_ok=True)
    except OSError:
        pass
