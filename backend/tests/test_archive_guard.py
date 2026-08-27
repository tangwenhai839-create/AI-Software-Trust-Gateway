"""归档安全与路径穿越防御测试
"""
import io
import os
import tempfile
import zipfile
import pytest
from backend.app.core.errors import ArchiveSafetyError, ResourceLimitExceededError
from backend.app.ingestion.archive_guard import SafeArchiveExtractor


def test_safe_zip_extraction():
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = os.path.join(tmp_dir, "safe.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("clean_dir/file.txt", "hello world")

        extract_target = os.path.join(tmp_dir, "extracted")
        sz, count, paths = SafeArchiveExtractor.extract_zip(zip_path, extract_target)
        assert count == 1
        assert sz == len("hello world")
        assert os.path.exists(os.path.join(extract_target, "clean_dir", "file.txt"))


def test_path_traversal_zip_blocking():
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = os.path.join(tmp_dir, "traversal.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../escape.txt", "malicious payload")

        extract_target = os.path.join(tmp_dir, "extracted")
        with pytest.raises(ArchiveSafetyError):
            SafeArchiveExtractor.extract_zip(zip_path, extract_target)


def test_single_archive_root_can_be_stripped_for_short_windows_paths():
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = os.path.join(tmp_dir, "github.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("owner-repo-abcdef/deep/file.txt", "content")

        extract_target = os.path.join(tmp_dir, "extracted")
        SafeArchiveExtractor.extract_zip(zip_path, extract_target, strip_single_root=True)
        assert os.path.exists(os.path.join(extract_target, "deep", "file.txt"))
        assert not os.path.exists(os.path.join(extract_target, "owner-repo-abcdef"))
