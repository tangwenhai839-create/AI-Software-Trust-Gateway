"""AI Software Trust Gateway - Bandit 适配器 (Bandit Python Security Scanner)
"""
import hashlib
import json
import os
import shutil
import subprocess
from typing import List

from backend.app.core.logging import logger
from backend.app.core.security import redact_secrets
from backend.app.domain.enums import FindingCategory, Severity
from backend.app.domain.models import Evidence, Finding
from backend.app.scanners.base import ScannerAdapter


class BanditScanner(ScannerAdapter):
    """Bandit Python AST 安全检测工具适配器"""

    @property
    def name(self) -> str:
        return "bandit"

    @property
    def version(self) -> str:
        return "1.7.8"

    def is_applicable(self, languages: List[str], repo_dir: str) -> bool:
        has_cli = shutil.which("bandit") is not None
        has_python = "python" in [l.lower() for l in languages]
        return has_cli and has_python

    async def scan(self, repo_dir: str, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        cmd = [
            "bandit",
            "-r", repo_dir,
            "-f", "json",
            "-q",
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if res.stdout:
                data = json.loads(res.stdout)
                results = data.get("results", [])
                for item in results:
                    f = self._normalize_item(item, repo_dir, scan_id)
                    if f:
                        findings.append(f)
        except Exception as e:
            logger.warning("Bandit 执行失败或跳过", scan_id=scan_id, error=str(e))

        return findings

    def _normalize_item(self, item: dict, repo_dir: str, scan_id: str) -> Finding:
        test_id = item.get("test_id", "B000")
        filename = item.get("filename", "")
        rel_path = os.path.relpath(filename, repo_dir).replace("\\", "/") if os.path.isabs(filename) else filename.replace("\\", "/")

        line_no = item.get("line_number", 1)
        code = item.get("code", "")
        issue_text = item.get("issue_text", "Bandit issue detected")
        issue_severity = item.get("issue_severity", "MEDIUM").upper()
        issue_confidence = item.get("issue_confidence", "MEDIUM").upper()

        if issue_severity == "HIGH":
            severity = Severity.HIGH
        elif issue_severity == "MEDIUM":
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        conf_map = {"HIGH": 0.9, "MEDIUM": 0.75, "LOW": 0.5}
        confidence = conf_map.get(issue_confidence, 0.75)

        category = FindingCategory.SUSPICIOUS_PATTERN
        if "subprocess" in issue_text.lower() or "exec" in issue_text.lower() or "shell" in issue_text.lower():
            category = FindingCategory.COMMAND_EXECUTION
        elif "eval" in issue_text.lower():
            category = FindingCategory.DYNAMIC_EXECUTION
        elif "yaml" in issue_text.lower() or "pickle" in issue_text.lower():
            category = FindingCategory.CODE_INJECTION

        redacted_code = redact_secrets(code.strip())
        fp_str = f"bandit:{test_id}:{rel_path}:{line_no}:{redacted_code}"
        fingerprint = hashlib.sha256(fp_str.encode("utf-8")).hexdigest()

        evidence = Evidence(
            kind="code_snippet",
            source=f"bandit:{test_id}",
            location=f"{rel_path}:{line_no}",
            excerpt_redacted=redacted_code,
            attributes={"issue_text": issue_text, "more_info": item.get("more_info", "")},
        )

        return Finding(
            scan_id=scan_id,
            scanner_name=self.name,
            fingerprint=fingerprint,
            category=category,
            title=issue_text,
            severity=severity,
            confidence=confidence,
            file_path=rel_path,
            line_start=line_no,
            line_end=line_no,
            remediation=f"参考 Bandit 安全指南优化代码: {item.get('more_info', '')}",
            evidences=[evidence],
        )
