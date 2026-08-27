"""AI Software Trust Gateway - 项目基础结构分析器 (语言识别、清单定位与入口点检测)
"""
import os
from pathlib import Path
from typing import Dict, List, Tuple

LANGUAGE_EXTENSIONS: Dict[str, List[str]] = {
    "python": [".py", ".pyw"],
    "javascript": [".js", ".mjs", ".cjs", ".jsx"],
    "typescript": [".ts", ".mts", ".cts", ".tsx"],
    "go": [".go"],
    "rust": [".rs"],
    "java": [".java"],
    "c_cpp": [".c", ".cpp", ".cc", ".h", ".hpp"],
}

MANIFEST_FILENAMES = {
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "poetry.lock",
    "setup.py",
    "setup.cfg",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
}

ENTRYPOINT_CANDIDATES = {
    "main.py",
    "app.py",
    "server.py",
    "cli.py",
    "__main__.py",
    "index.js",
    "server.js",
    "index.ts",
    "main.go",
    "main.rs",
    "setup.py",
}


class ProjectStructureAnalyzer:
    """分析仓库目录结构，识别主要编程语言、清单与入口点"""

    @classmethod
    def analyze(cls, repo_dir: str) -> Tuple[List[str], List[str], List[str]]:
        """
        分析仓库结构。
        返回: (detected_languages, manifest_relative_paths, entrypoints)
        """
        root_path = Path(repo_dir).resolve()
        lang_counts: Dict[str, int] = {lang: 0 for lang in LANGUAGE_EXTENSIONS}
        manifest_paths: List[str] = []
        entrypoints: List[str] = []

        ignore_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            rel_dir = os.path.relpath(root, root_path)

            for file in files:
                rel_file = file if rel_dir == "." else os.path.join(rel_dir, file)
                rel_file_norm = rel_file.replace("\\", "/")

                # 检查清单
                if file in MANIFEST_FILENAMES:
                    manifest_paths.append(rel_file_norm)

                # 检查入口点
                if file in ENTRYPOINT_CANDIDATES or (rel_dir == "." and file.endswith((".py", ".js", ".ts"))):
                    entrypoints.append(rel_file_norm)

                # 检查语言后缀
                ext = os.path.splitext(file)[1].lower()
                for lang, exts in LANGUAGE_EXTENSIONS.items():
                    if ext in exts:
                        lang_counts[lang] += 1

        # 排序并提取存在文件的语言
        sorted_langs = [
            lang for lang, count in sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)
            if count > 0
        ]
        if not sorted_langs:
            sorted_langs = ["unknown"]

        return sorted_langs, manifest_paths, entrypoints
