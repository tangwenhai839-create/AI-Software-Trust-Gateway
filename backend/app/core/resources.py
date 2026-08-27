"""Locate rule/schema resources in source, wheel, and frozen installations."""
import os
import sys
from pathlib import Path


def resource_path(relative_path: str) -> Path:
    relative = Path(relative_path)
    candidates = []
    configured = os.environ.get("ASTG_RESOURCE_DIR")
    if configured:
        candidates.append(Path(configured).expanduser() / relative)
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        candidates.append(Path(frozen_root) / relative)
    candidates.append(Path(__file__).resolve().parents[3] / relative)
    candidates.append(Path(sys.prefix) / "share" / "astg" / relative)
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return candidates[0].resolve()
