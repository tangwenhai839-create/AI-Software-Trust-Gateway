"""AI Software Trust Gateway - Python 依赖解析器 (Python Dependency Manifest Parser)
"""
import os
import re
from pathlib import Path
from typing import List

from backend.app.domain.enums import DependencyScope, Ecosystem
from backend.app.domain.models import Dependency

# 匹配 requirements.txt 中的依赖项 (支持 ==, >=, ~=, <=, 无版本)
REQ_LINE_REGEX = re.compile(
    r"^\s*([a-zA-Z0-9_\-\.]+)\s*(?:(==|>=|<=|~=|>|<|!=)\s*([a-zA-Z0-9_\-\.]+))?"
)


class PythonDependencyParser:
    """解析 Python 生态的依赖清单与 Lockfile"""

    @classmethod
    def parse_manifest(cls, file_path: str, repo_dir: str, artifact_id: str = "") -> List[Dependency]:
        deps: List[Dependency] = []
        filename = os.path.basename(file_path).lower()
        rel_path = os.path.relpath(file_path, repo_dir).replace("\\", "/")

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if filename == "requirements.txt" or filename.endswith(".txt"):
                deps.extend(cls._parse_requirements_txt(content, rel_path, artifact_id))
            elif filename == "pyproject.toml":
                deps.extend(cls._parse_pyproject_toml(content, rel_path, artifact_id))
        except Exception:
            pass

        return deps

    @classmethod
    def _parse_requirements_txt(cls, content: str, rel_path: str, artifact_id: str) -> List[Dependency]:
        deps: List[Dependency] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            match = REQ_LINE_REGEX.match(line)
            if match:
                pkg_name = match.group(1).lower()
                op = match.group(2)
                ver = match.group(3) if match.group(3) else ""

                scope = DependencyScope.DIRECT
                if not ver or op != "==":
                    # 未锁死确切版本的依赖
                    scope = DependencyScope.UNRESOLVED

                deps.append(
                    Dependency(
                        artifact_id=artifact_id,
                        ecosystem=Ecosystem.PYPI,
                        name=pkg_name,
                        version=ver if ver else "latest",
                        scope=scope,
                        manifest_path=rel_path,
                    )
                )
        return deps

    @classmethod
    def _parse_pyproject_toml(cls, content: str, rel_path: str, artifact_id: str) -> List[Dependency]:
        deps: List[Dependency] = []
        in_deps = False

        for line in content.splitlines():
            clean = line.strip()
            if clean.startswith("dependencies = [") or clean == "[project.dependencies]":
                in_deps = True
                continue
            if in_deps:
                if clean.startswith("]") or clean.startswith("["):
                    in_deps = False
                    continue
                # 解析 "requests>=2.25.0"
                match = re.search(r'["\']([a-zA-Z0-9_\-\.]+)(?:([=><~]+)([a-zA-Z0-9_\-\.]+))?["\']', clean)
                if match:
                    pkg_name = match.group(1).lower()
                    ver = match.group(3) or "unspecified"
                    deps.append(
                        Dependency(
                            artifact_id=artifact_id,
                            ecosystem=Ecosystem.PYPI,
                            name=pkg_name,
                            version=ver,
                            scope=DependencyScope.DIRECT if match.group(2) == "==" else DependencyScope.UNRESOLVED,
                            manifest_path=rel_path,
                        )
                    )
        return deps
