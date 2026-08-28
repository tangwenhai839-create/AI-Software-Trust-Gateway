"""AI Software Trust Gateway - 原生 AST 与规则扫描引擎 (Native Python AST & JS Pattern Scanner)
提供零外部二进制依赖的安全规则分析能力。
"""
import ast
import hashlib
import os
import re
from pathlib import Path
from typing import List

from backend.app.core.security import redact_secrets
from backend.app.domain.enums import FindingCategory, Severity
from backend.app.domain.models import Evidence, Finding
from backend.app.scanners.base import ScannerAdapter

SENSITIVE_PATH_REGEX = re.compile(
    r"(?i)(\.ssh|id_rsa|id_ed25519|\.aws|\.kube/config|cookies\.sqlite|Login Data|keychain|wallet\.dat|\.env|\.git/config)"
)

EXFILTRATION_HOST_REGEX = re.compile(
    r"(?i)(discord\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com|ngrok\.io|transfer\.sh|temp\.sh|pipedream\.net|webhook\.site)"
)


class NativeASTPythonScanner(ScannerAdapter):
    """基于 Python 内置 AST 模块的安全特征分析器"""

    @property
    def name(self) -> str:
        return "astg_ast_python"

    @property
    def version(self) -> str:
        return "1.0.0"

    def is_applicable(self, languages: List[str], repo_dir: str) -> bool:
        return "python" in [lang.lower() for lang in languages]

    async def scan(self, repo_dir: str, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []
        root_path = Path(repo_dir).resolve()

        ignore_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file in files:
                if file.endswith((".py", ".pyw")):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, root_path).replace("\\", "/")
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            lines = content.splitlines()

                        tree = ast.parse(content, filename=rel_path)
                        file_findings = self._inspect_ast(tree, rel_path, lines, scan_id)
                        findings.extend(file_findings)
                    except Exception:
                        continue

        return findings

    def _inspect_ast(self, tree: ast.AST, rel_path: str, lines: List[str], scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        for node in ast.walk(tree):
            # 1. 动态代码执行: eval / exec
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                line_no = getattr(node, "lineno", 1)
                snippet = lines[line_no - 1] if 0 < line_no <= len(lines) else ""

                if func_name in ("eval", "exec", "__import__"):
                    f = self._create_finding(
                        scan_id=scan_id,
                        rule_id="py-dynamic-execution",
                        category=FindingCategory.DYNAMIC_EXECUTION,
                        title=f"检测到动态代码执行 ({func_name})",
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        snippet=snippet,
                        remediation="避免使用动态执行代码函数，改用受控解析器或静态逻辑。",
                    )
                    findings.append(f)

                # 2. 系统命令与子进程执行: os.system / subprocess(shell=True)
                if func_name in ("system", "popen") and isinstance(node.func, ast.Attribute):
                    f = self._create_finding(
                        scan_id=scan_id,
                        rule_id="py-os-command-execution",
                        category=FindingCategory.COMMAND_EXECUTION,
                        title=f"检测到调用系统命令接口 (os.{func_name})",
                        severity=Severity.MEDIUM,
                        confidence=0.80,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        snippet=snippet,
                        remediation="避免直接调用 os.system，改用带参数列表的 subprocess.run(..., shell=False)。",
                    )
                    findings.append(f)

                if func_name in ("run", "Popen", "call", "check_output", "check_call"):
                    # 检查是否有 shell=True
                    has_shell_true = any(
                        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in node.keywords
                    )
                    if has_shell_true:
                        f = self._create_finding(
                            scan_id=scan_id,
                            rule_id="py-subprocess-shell-true",
                            category=FindingCategory.COMMAND_EXECUTION,
                            title="检测到使用 subprocess (shell=True) 执行命令",
                            severity=Severity.MEDIUM,
                            confidence=0.85,
                            file_path=rel_path,
                            line_start=line_no,
                            line_end=line_no,
                            snippet=snippet,
                            remediation="移除 shell=True，将命令与参数切分为列表传递以防止注入。",
                        )
                        findings.append(f)

            # 3. 敏感文件访问特征扫描
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                line_no = getattr(node, "lineno", 1)
                snippet = lines[line_no - 1] if 0 < line_no <= len(lines) else ""

                if SENSITIVE_PATH_REGEX.search(val):
                    f = self._create_finding(
                        scan_id=scan_id,
                        rule_id="py-sensitive-path-reference",
                        category=FindingCategory.SENSITIVE_FILE_ACCESS,
                        title=f"检测到引用系统敏感凭据路径 ({val})",
                        severity=Severity.MEDIUM,
                        confidence=0.80,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        snippet=snippet,
                        remediation="检查敏感路径访问是否符合该工具公开声明的功能，防止隐蔽窃取凭据。",
                    )
                    findings.append(f)

                # 4. 可疑外传端点
                if EXFILTRATION_HOST_REGEX.search(val):
                    f = self._create_finding(
                        scan_id=scan_id,
                        rule_id="py-suspicious-exfiltration-endpoint",
                        category=FindingCategory.NETWORK_EXFILTRATION,
                        title=f"检测到引用可疑数据外传或 Webhook 接口 ({val})",
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        file_path=rel_path,
                        line_start=line_no,
                        line_end=line_no,
                        snippet=snippet,
                        remediation="确认网络请求端点是否受控，避免未经声明的第三方数据传输通道。",
                    )
                    findings.append(f)

        return findings

    def _create_finding(
        self,
        scan_id: str,
        rule_id: str,
        category: FindingCategory,
        title: str,
        severity: Severity,
        confidence: float,
        file_path: str,
        line_start: int,
        line_end: int,
        snippet: str,
        remediation: str,
    ) -> Finding:
        redacted_snippet = redact_secrets(snippet.strip())
        fp_str = f"{self.name}:{rule_id}:{file_path}:{line_start}:{redacted_snippet}"
        fingerprint = hashlib.sha256(fp_str.encode("utf-8")).hexdigest()

        evidence = Evidence(
            kind="code_snippet",
            source=f"{self.name}:{rule_id}",
            location=f"{file_path}:{line_start}",
            excerpt_redacted=redacted_snippet,
            sha256=hashlib.sha256(redacted_snippet.encode("utf-8")).hexdigest(),
        )

        return Finding(
            scan_id=scan_id,
            scanner_name=self.name,
            fingerprint=fingerprint,
            category=category,
            title=title,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            remediation=remediation,
            evidences=[evidence],
        )


class NativeJSPatternScanner(ScannerAdapter):
    """基于模式匹配的 JavaScript / TypeScript 安全特征分析器"""

    @property
    def name(self) -> str:
        return "astg_js_pattern"

    @property
    def version(self) -> str:
        return "1.0.0"

    def is_applicable(self, languages: List[str], repo_dir: str) -> bool:
        langs = [l.lower() for l in languages]
        return "javascript" in langs or "typescript" in langs

    async def scan(self, repo_dir: str, scan_id: str) -> List[Finding]:
        findings: List[Finding] = []
        root_path = Path(repo_dir).resolve()

        ignore_dirs = {".git", "node_modules", "dist", "build", ".next"}

        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file in files:
                if file.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, root_path).replace("\\", "/")
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()

                        for idx, line in enumerate(lines, 1):
                            # eval
                            if re.search(r"\beval\s*\(", line):
                                findings.append(self._make_finding(
                                    scan_id, "js-eval", FindingCategory.DYNAMIC_EXECUTION,
                                    "检测到 JavaScript eval 动态代码执行", Severity.MEDIUM, 0.85,
                                    rel_path, idx, line, "避免使用 eval() 执行不可信动态代码。"
                                ))
                            # child_process exec
                            if re.search(r"\b(exec|execSync)\s*\(", line) and ("child_process" in line or "exec" in line):
                                findings.append(self._make_finding(
                                    scan_id, "js-exec", FindingCategory.COMMAND_EXECUTION,
                                    "检测到 child_process.exec 系统命令执行", Severity.MEDIUM, 0.80,
                                    rel_path, idx, line, "改用 execFile 或 spawn 并传递参数数组。"
                                ))
                            # sensitive path
                            if SENSITIVE_PATH_REGEX.search(line):
                                findings.append(self._make_finding(
                                    scan_id, "js-sensitive-path", FindingCategory.SENSITIVE_FILE_ACCESS,
                                    "检测到敏感凭据文件路径引用", Severity.MEDIUM, 0.80,
                                    rel_path, idx, line, "核实敏感文件读取是否符合软件声明用途。"
                                ))
                            # exfiltration
                            if EXFILTRATION_HOST_REGEX.search(line):
                                findings.append(self._make_finding(
                                    scan_id, "js-exfiltration", FindingCategory.NETWORK_EXFILTRATION,
                                    "检测到可疑数据外传或 Webhook 接口", Severity.MEDIUM, 0.85,
                                    rel_path, idx, line, "检查该外部通信目标是否已在文档中明确声明。"
                                ))
                    except Exception:
                        continue

        return findings

    def _make_finding(self, scan_id, rule_id, category, title, severity, confidence, file_path, line_no, raw_snippet, remediation):
        redacted = redact_secrets(raw_snippet.strip())
        fp_str = f"{self.name}:{rule_id}:{file_path}:{line_no}:{redacted}"
        fingerprint = hashlib.sha256(fp_str.encode("utf-8")).hexdigest()

        evidence = Evidence(
            kind="code_snippet",
            source=f"{self.name}:{rule_id}",
            location=f"{file_path}:{line_no}",
            excerpt_redacted=redacted,
            sha256=hashlib.sha256(redacted.encode("utf-8")).hexdigest(),
        )

        return Finding(
            scan_id=scan_id,
            scanner_name=self.name,
            fingerprint=fingerprint,
            category=category,
            title=title,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_start=line_no,
            line_end=line_no,
            remediation=remediation,
            evidences=[evidence],
        )
