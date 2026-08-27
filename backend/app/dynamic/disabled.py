"""Safe default dynamic provider which never executes target code."""
from typing import Any, Dict

from backend.app.dynamic.base import DynamicAnalysisProvider


class DisabledDynamicAnalysisProvider(DynamicAnalysisProvider):
    @property
    def provider_type(self) -> str:
        return "disabled"

    async def analyze(self, repo_dir: str, scan_id: str) -> Dict[str, Any]:
        return {
            "provider": self.provider_type,
            "status": "not_run",
            "coverage": 0.0,
            "executed_target_code": False,
            "file_events": [],
            "network_events": [],
            "process_events": [],
            "system_events": [],
            "limitations": [
                "动态沙箱未启用",
                "未观察文件、网络、进程或系统修改行为",
            ],
        }
