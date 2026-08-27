"""AI Software Trust Gateway - 依赖安全分析器 (Dependency Vulnerability Analyzer)
"""
import os
from typing import List, Tuple

from backend.app.dependencies.osv_client import OSVClient
from backend.app.dependencies.parsers.node_parser import NodeDependencyParser
from backend.app.dependencies.parsers.python_parser import PythonDependencyParser
from backend.app.domain.models import Dependency


class DependencyAnalyzer:
    """整合清单解析与 OSV 已知漏洞匹配"""

    def __init__(self, osv_client: OSVClient = None):
        self.osv_client = osv_client or OSVClient()

    async def analyze_dependencies(
        self,
        repo_dir: str,
        manifest_paths: List[str],
        artifact_id: str = "",
    ) -> Tuple[List[Dependency], bool]:
        """
        分析依赖清单并查询 OSV。
        返回 (dependencies_list, is_osv_available)
        """
        all_deps: List[Dependency] = []
        osv_success = True

        # 1. 解析所有发现的清单文件
        for rel_manifest in manifest_paths:
            full_path = os.path.join(repo_dir, rel_manifest)
            if not os.path.exists(full_path):
                continue

            fname = os.path.basename(rel_manifest).lower()
            if fname in ("requirements.txt", "pyproject.toml") or fname.endswith(".txt"):
                deps = PythonDependencyParser.parse_manifest(full_path, repo_dir, artifact_id)
                all_deps.extend(deps)
            elif fname in ("package.json", "package-lock.json"):
                deps = NodeDependencyParser.parse_manifest(full_path, repo_dir, artifact_id)
                all_deps.extend(deps)

        # 2. 构建 OSV 批量查询请求 (仅针对已明确版本的依赖)
        queries = []
        queryable_indices = []

        for idx, dep in enumerate(all_deps):
            if dep.version and dep.version not in ("latest", "unspecified"):
                queries.append({
                    "package": {
                        "name": dep.name,
                        "ecosystem": dep.ecosystem.value,
                    },
                    "version": dep.version,
                })
                queryable_indices.append(idx)

        # 3. 发送批量查询
        if queries:
            vuln_results, is_success = await self.osv_client.query_batch_vulnerabilities(queries)
            osv_success = is_success
            for i, vuln_list in enumerate(vuln_results):
                dep_idx = queryable_indices[i]
                all_deps[dep_idx].vulnerabilities = vuln_list

        return all_deps, osv_success
