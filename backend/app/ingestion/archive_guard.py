"""AI Software Trust Gateway - 解压安全守卫 (防止路径穿越、符号链接逃逸与压缩炸弹)
"""
import os
import tarfile
import zipfile
from pathlib import Path
from typing import List, Tuple

from backend.app.core.config import settings
from backend.app.core.errors import ArchiveSafetyError, ResourceLimitExceededError


class SafeArchiveExtractor:
    """安全解压工具，防范恶意归档文件"""

    @classmethod
    def extract_zip(
        cls,
        zip_path: str,
        extract_to: str,
        strip_single_root: bool = False,
    ) -> Tuple[int, int, List[str]]:
        """
        安全解压 ZIP 文件。
        返回 (total_size_bytes, total_files_count, extracted_files_list)
        """
        target_dir = Path(extract_to).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        max_size_bytes = settings.ASTG_MAX_REPO_SIZE_MB * 1024 * 1024
        max_single_file_bytes = settings.ASTG_MAX_SINGLE_FILE_MB * 1024 * 1024
        max_files = settings.ASTG_MAX_REPO_FILES

        total_size = 0
        total_files = 0
        extracted_paths: List[str] = []

        with zipfile.ZipFile(zip_path, 'r') as zf:
            infolist = zf.infolist()
            if len(infolist) > max_files:
                raise ResourceLimitExceededError(
                    f"归档内文件数 ({len(infolist)}) 超出上限 {max_files}"
                )

            # GitHub zipballs wrap every item in owner-repo-commit/. Removing
            # that redundant layer before writing avoids wasting dozens of
            # characters from Windows' legacy MAX_PATH budget.
            root_prefix = ""
            if strip_single_root:
                safe_names = [item.filename.replace("\\", "/").lstrip("/") for item in infolist]
                top_levels = {name.split("/", 1)[0] for name in safe_names if name}
                if len(top_levels) == 1:
                    root_prefix = next(iter(top_levels)) + "/"

            for member in infolist:
                # 检查单文件大小
                if member.file_size > max_single_file_bytes:
                    raise ResourceLimitExceededError(
                        f"文件 {member.filename} 大小 ({member.file_size} 字节) 超出单文件上限 {max_single_file_bytes}"
                    )

                total_size += member.file_size
                if total_size > max_size_bytes:
                    raise ResourceLimitExceededError(
                        f"归档解压总大小超出上限 {max_size_bytes} 字节 (疑似压缩炸弹)"
                    )

                # 检查路径穿越
                original_name = member.filename.replace("\\", "/")
                original_norm = os.path.normpath(original_name)
                if original_norm.startswith("..") or os.path.isabs(original_norm) or "/../" in original_name:
                    raise ArchiveSafetyError(f"检测到路径穿越攻击特征: {member.filename}")

                member_name = original_name
                if root_prefix and member_name.startswith(root_prefix):
                    member_name = member_name[len(root_prefix):]
                if not member_name:
                    continue
                norm_name = os.path.normpath(member_name)
                if norm_name.startswith("..") or os.path.isabs(norm_name) or "/../" in member_name:
                    raise ArchiveSafetyError(f"检测到路径穿越攻击特征: {member.filename}")

                dest_path = (target_dir / norm_name).resolve()
                if not str(dest_path).startswith(str(target_dir)):
                    raise ArchiveSafetyError(f"解压目标超出工作目录范围: {dest_path}")

                # 提取
                if member.is_dir():
                    dest_path.mkdir(parents=True, exist_ok=True)
                else:
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as source, open(dest_path, "wb") as target:
                        chunk = source.read(65536)
                        while chunk:
                            target.write(chunk)
                            chunk = source.read(65536)
                    total_files += 1
                    extracted_paths.append(str(dest_path))

        return total_size, total_files, extracted_paths

    @classmethod
    def extract_tar(cls, tar_path: str, extract_to: str) -> Tuple[int, int, List[str]]:
        """
        安全解压 TAR / TAR.GZ 文件。
        """
        target_dir = Path(extract_to).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        max_size_bytes = settings.ASTG_MAX_REPO_SIZE_MB * 1024 * 1024
        max_single_file_bytes = settings.ASTG_MAX_SINGLE_FILE_MB * 1024 * 1024
        max_files = settings.ASTG_MAX_REPO_FILES

        total_size = 0
        total_files = 0
        extracted_paths: List[str] = []

        with tarfile.open(tar_path, 'r:*') as tf:
            for member in tf.getmembers():
                if total_files > max_files:
                    raise ResourceLimitExceededError(f"文件数超出限制: {max_files}")

                if member.size > max_single_file_bytes:
                    raise ResourceLimitExceededError(
                        f"文件 {member.name} 超出单文件上限 {max_single_file_bytes}"
                    )

                total_size += member.size
                if total_size > max_size_bytes:
                    raise ResourceLimitExceededError("解压总大小超出上限 (疑似压缩炸弹)")

                norm_name = os.path.normpath(member.name)
                if norm_name.startswith("..") or os.path.isabs(norm_name):
                    raise ArchiveSafetyError(f"检测到路径穿越攻击特征: {member.name}")

                dest_path = (target_dir / norm_name).resolve()
                if not str(dest_path).startswith(str(target_dir)):
                    raise ArchiveSafetyError(f"解压目标超出工作目录范围: {dest_path}")

                # 拦截恶意的外部符号链接
                if member.issym() or member.islnk():
                    link_target = (dest_path.parent / member.linkname).resolve()
                    if not str(link_target).startswith(str(target_dir)):
                        raise ArchiveSafetyError(f"拦截跨目录恶意符号链接: {member.name} -> {member.linkname}")

                if member.isdir():
                    dest_path.mkdir(parents=True, exist_ok=True)
                elif member.isreg():
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    extracted_file = tf.extractfile(member)
                    if extracted_file:
                        with open(dest_path, "wb") as f:
                            f.write(extracted_file.read())
                        total_files += 1
                        extracted_paths.append(str(dest_path))

        return total_size, total_files, extracted_paths
