"""AI Software Trust Gateway - 安全仓库获取器 (GitHub Fetcher & Local Ingester)
"""
import hashlib
import os
import shutil
from pathlib import Path
from typing import Optional, Tuple
import httpx

from backend.app.core.config import settings
from backend.app.core.errors import IngestionError, ResourceLimitExceededError
from backend.app.core.logging import logger
from backend.app.core.resources import resource_path
from backend.app.core.security import normalize_and_validate_github_url
from backend.app.ingestion.archive_guard import SafeArchiveExtractor


class SafeRepoFetcher:
    """安全获取目标仓库，固定 Commit SHA，计算哈希，并在受控环境中解压"""

    def __init__(self, artifacts_base_dir: Optional[str] = None):
        self.base_dir = Path(artifacts_base_dir or settings.ASTG_ARTIFACTS_DIR).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    async def fetch_github_repository(
        self,
        url: str,
        ref: str = "main",
        scan_id: str = "temp",
    ) -> Tuple[str, str, str, int, int]:
        """
        获取 GitHub 仓库。
        返回: (local_repo_dir, resolved_commit_sha, archive_sha256, total_size_bytes, file_count)
        """
        canonical_url, owner, repo = normalize_and_validate_github_url(url)
        scan_dir = self.base_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        archive_path = scan_dir / "repo_archive.zip"
        extract_target = scan_dir / "repo"

        headers = {
            "User-Agent": "ASTG-Security-Scanner/1.0",
            "Accept": "application/vnd.github.v3+json",
        }
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

        # 1. 尝试固定 Commit SHA
        commit_sha = ref
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                commit_api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}"
                resp = await client.get(commit_api_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    commit_sha = data.get("sha", ref)
                    logger.info("已固定 GitHub Commit SHA", scan_id=scan_id, commit_sha=commit_sha)
            except Exception as e:
                logger.warning("获取远程 Commit SHA 异常，回退使用原始 ref", error=str(e))

            # 2. 下载仓库归档 Zipball
            zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{commit_sha}"
            try:
                max_bytes = settings.ASTG_MAX_REPO_SIZE_MB * 1024 * 1024
                hasher = hashlib.sha256()
                downloaded_size = 0

                async with client.stream("GET", zip_url, headers=headers) as response:
                    if response.status_code != 200:
                        # 降级尝试公开 archive URL
                        fallback_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{ref}.zip"
                        async with client.stream("GET", fallback_url) as fb_resp:
                            if fb_resp.status_code != 200:
                                raise IngestionError(
                                    f"下载 GitHub 仓库归档失败 (HTTP {response.status_code} / {fb_resp.status_code})"
                                )
                            with open(archive_path, "wb") as f:
                                async for chunk in fb_resp.aiter_bytes():
                                    downloaded_size += len(chunk)
                                    if downloaded_size > max_bytes:
                                        raise ResourceLimitExceededError("下载仓库大小超出配置限制")
                                    hasher.update(chunk)
                                    f.write(chunk)
                    else:
                        with open(archive_path, "wb") as f:
                            async for chunk in response.aiter_bytes():
                                downloaded_size += len(chunk)
                                if downloaded_size > max_bytes:
                                    raise ResourceLimitExceededError("下载仓库大小超出配置限制")
                                hasher.update(chunk)
                                f.write(chunk)

                archive_sha256 = hasher.hexdigest()
            except Exception as e:
                if isinstance(e, (IngestionError, ResourceLimitExceededError)):
                    raise
                raise IngestionError(f"下载 GitHub 仓库归档发生错误: {str(e)}")

        # 3. 安全解压
        raw_extract = scan_dir / "raw"
        raw_extract.mkdir(parents=True, exist_ok=True)
        size_bytes, file_count, _ = SafeArchiveExtractor.extract_zip(str(archive_path), str(raw_extract))

        # 处理 GitHub zipball 解压后的单层根目录包装 (e.g. owner-repo-sha/)
        entries = list(raw_extract.iterdir())
        if len(entries) == 1 and entries[0].is_dir():
            if extract_target.exists():
                shutil.rmtree(extract_target)
            shutil.move(str(entries[0]), str(extract_target))
            shutil.rmtree(raw_extract, ignore_errors=True)
        else:
            if extract_target.exists():
                shutil.rmtree(extract_target)
            shutil.move(str(raw_extract), str(extract_target))

        return str(extract_target), commit_sha, archive_sha256, size_bytes, file_count

    def ingest_local_directory(
        self,
        local_dir: str,
        scan_id: str = "temp",
    ) -> Tuple[str, str, str, int, int]:
        """
        用于本地测试、Fixture 或测试目录的安全导入。
        """
        requested_path = Path(local_dir).expanduser()
        if requested_path.is_absolute():
            source_path = requested_path.resolve()
        else:
            bundled_path = resource_path(local_dir)
            source_path = bundled_path if bundled_path.exists() else requested_path.resolve()
        if not source_path.exists() or not source_path.is_dir():
            raise IngestionError(f"本地测试目录不存在: {local_dir}")

        scan_dir = self.base_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        extract_target = scan_dir / "repo"
        if extract_target.exists():
            shutil.rmtree(extract_target)

        # 复制到工作区并计算指标
        shutil.copytree(str(source_path), str(extract_target))

        hasher = hashlib.sha256()
        total_size = 0
        file_count = 0

        for root, _, files in os.walk(extract_target):
            for file in files:
                file_count += 1
                fp = os.path.join(root, file)
                sz = os.path.getsize(fp)
                total_size += sz
                with open(fp, "rb") as f:
                    while chunk := f.read(65536):
                        hasher.update(chunk)

        content_sha256 = hasher.hexdigest()
        commit_sha = f"local-{content_sha256[:12]}"
        return str(extract_target), commit_sha, content_sha256, total_size, file_count
