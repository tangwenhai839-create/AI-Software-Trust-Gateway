"""AI Software Trust Gateway - Node.js 依赖解析器 (Node.js Manifest & Lockfile Parser)
"""
import json
import os
from typing import List

from backend.app.domain.enums import DependencyScope, Ecosystem
from backend.app.domain.models import Dependency


class NodeDependencyParser:
    """解析 Node.js / npm 生态清单与 Lockfile"""

    @classmethod
    def parse_manifest(cls, file_path: str, repo_dir: str, artifact_id: str = "") -> List[Dependency]:
        deps: List[Dependency] = []
        filename = os.path.basename(file_path).lower()
        rel_path = os.path.relpath(file_path, repo_dir).replace("\\", "/")

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            if filename == "package.json":
                # dependencies & devDependencies
                prod_deps = data.get("dependencies", {})
                for name, ver in prod_deps.items():
                    clean_ver = ver.lstrip("^~>=< ")
                    scope = DependencyScope.DIRECT if (not ver.startswith(("^", "~", ">", "<"))) else DependencyScope.UNRESOLVED
                    deps.append(Dependency(
                        artifact_id=artifact_id,
                        ecosystem=Ecosystem.NPM,
                        name=name,
                        version=clean_ver or "latest",
                        scope=scope,
                        manifest_path=rel_path,
                    ))

            elif filename == "package-lock.json":
                # Lockfile: packages / dependencies
                packages = data.get("packages", {})
                if packages:
                    for pkg_key, pkg_info in packages.items():
                        if not pkg_key:  # 根目录
                            continue
                        name = pkg_key.replace("node_modules/", "")
                        ver = pkg_info.get("version", "")
                        if name and ver:
                            deps.append(Dependency(
                                artifact_id=artifact_id,
                                ecosystem=Ecosystem.NPM,
                                name=name,
                                version=ver,
                                scope=DependencyScope.INDIRECT if "node_modules/" in pkg_key and pkg_key.count("node_modules") > 1 else DependencyScope.DIRECT,
                                manifest_path=rel_path,
                            ))
        except Exception:
            pass

        return deps
