"""AI Software Trust Gateway - Semgrep 适配器 (Semgrep Scanner Adapter)
"""
import json
import os
import shutil
import subprocess
from typing import List

from backend.app.core.logging import logger
from backend.app.core.resources import resource_path
from backend.app.core.security import redact_secrets
from backend.app.domain.enums import FindingCategory, Severity
from backend.app.domain.models import Evidence, Finding
from backend.app.scanners.base import ScannerAdapter


class SemgrepScanner(ScannerAdapter):
    """Semgrep 静态分析适配器"""

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def version(self) -> str:
        return "1.65.0"

    def is_applicable(self, languages: List[str], repo_dir: str) -> bool:
        # 检查 semgrep 是否可用或有规则
        has_cli = shutil.which("semgrep") is not None
        langs = [l.lower() for l in languages]
        has_supported_lang = any(l in ("python", "javascript", "typescript") for l in langs)
        return has_cli and has_supported_lang

    async def scan(self, repo_dir: str, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []
        rules_dir = resource_path("rules/semgrep")
        if not rules_dir.exists():
            return findings

        cmd = [
            "semgrep",
            "--config", str(rules_dir),
            "--json",
            "--quiet",
            "--no-git-ignore",
            repo_dir,
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
            logger.warning("Semgrep 执行失败或跳过", scan_id=scan_id, error=str(e))

        return findings

    def _normalize_item(self, item: dict, repo_dir: str, scan_id: str) -> Finding:
        check_id = item.get("check_id", "semgrep-rule")
        path = item.get("path", "")
        rel_path = os.path.relpath(path, repo_dir).replace("\\", "/") if os.path.isabs(path) else path.replace("\\", "/")

        start = item.get("start", {})
        end = item.get("end", {})
        line_start = start.get("line", 1)
        line_end = end.get("line", line_start)

        extra = item.get("extra", {})
        raw_msg = extra.get("message", "Semgrep security finding")
        raw_lines = extra.get("lines", "")
        metadata = extra.get("metadata", {})
        cat_str = metadata.get("category", "suspicious_pattern")

        # 映射 category
        category = FindingCategory.SUSPICIOUS_PATTERN
        for c in FindingCategory:
            if c.value == cat_str:
                category = c
                break

        # 映射 severity
        raw_sev = extra.get("severity", "WARNING").upper()
        if raw_sev == "ERROR":
            severity = Severity.HIGH
        elif raw_sev == "WARNING":
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        confidence = float(metadata.get("confidence", 0.8))
        remediation = metadata.get("remediation", "建议审查该代码段的安全意图并确保边界可控。")
        redacted_lines = redact_secrets(raw_lines.strip())

        evidence = Evidence(
            kind="code_snippet",
            source=f"semgrep:{check_id}",
            location=f"{rel_path}:{line_start}",
            excerpt_redacted=redacted_lines,
            attributes={"raw_message": raw_msg},
        )

        import hashlib
        fp_str = f"semgrep:{check_id}:{rel_path}:{line_start}:{redacted_lines}"
        fingerprint = hashlib.sha256(fp_str.encode("utf-8")).hexdigest()

        return Finding(
            scan_id=scan_id,
            scanner_name=self.name,
            fingerprint=fingerprint,
            category=category,
            title=raw_msg,
            severity=severity,
            confidence=confidence,
            file_path=rel_path,
            line_start=line_start,
            line_end=line_end,
            remediation=remediation,
            evidences=[evidence],
        )
