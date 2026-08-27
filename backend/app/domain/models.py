"""AI Software Trust Gateway - 领域数据实体 (Domain Entities)
不依赖外部 Web 框架，便于纯净测试与序列化。
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from backend.app.domain.enums import (
    Ecosystem,
    DependencyScope,
    FindingCategory,
    RiskLevel,
    ScanStage,
    ScanStatus,
    Severity,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_id() -> str:
    return str(uuid.uuid4())


@dataclass
class Project:
    id: str = field(default_factory=generate_id)
    source_type: str = "github"
    canonical_url: str = ""
    owner: str = ""
    name: str = ""
    default_branch: str = "main"
    created_at: datetime = field(default_factory=utc_now)


@dataclass
class Artifact:
    id: str = field(default_factory=generate_id)
    project_id: str = ""
    commit_sha: str = ""
    sha256: str = ""
    local_path: str = ""
    size_bytes: int = 0
    file_count: int = 0
    languages: List[str] = field(default_factory=list)
    manifest_paths: List[str] = field(default_factory=list)
    entrypoints: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)


@dataclass
class Evidence:
    id: str = field(default_factory=generate_id)
    finding_id: str = ""
    kind: str = "code_snippet"  # code_snippet, ast_node, network_endpoint, cve_ref
    source: str = ""           # scanner name or rule id
    location: str = ""         # file:line
    excerpt_redacted: str = "" # 脱敏后的代码/内容摘录
    sha256: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str = field(default_factory=generate_id)
    scan_id: str = ""
    scanner_name: str = ""
    fingerprint: str = ""
    category: FindingCategory = FindingCategory.SUSPICIOUS_PATTERN
    title: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.8
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    remediation: str = ""
    evidences: List[Evidence] = field(default_factory=list)
    ai_assessment: Optional[Dict[str, Any]] = None
    status: str = "active"  # active, confirmed, false_positive


@dataclass
class Vulnerability:
    id: str = field(default_factory=generate_id)
    advisory_id: str = ""      # e.g., GHSA-xxxx-xxxx-xxxx or CVE-2023-xxxx
    aliases: List[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    cvss_score: Optional[float] = None
    severity: Severity = Severity.MEDIUM
    fixed_versions: List[str] = field(default_factory=list)
    source_url: str = ""


@dataclass
class Dependency:
    id: str = field(default_factory=generate_id)
    artifact_id: str = ""
    ecosystem: Ecosystem = Ecosystem.UNKNOWN
    name: str = ""
    version: str = ""
    scope: DependencyScope = DependencyScope.DIRECT
    manifest_path: str = ""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class PurposeProfile:
    id: str = field(default_factory=generate_id)
    scan_id: str = ""
    summary: str = ""
    declared_capabilities: List[str] = field(default_factory=list)
    expected_behaviors: List[str] = field(default_factory=list)
    expected_external_services: List[str] = field(default_factory=list)
    model_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Score:
    id: str = field(default_factory=generate_id)
    scan_id: str = ""
    scoring_version: str = "mvp-static-v1"
    safety_score: int = 100
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    confidence: float = 1.0
    coverage: float = 1.0
    components: Dict[str, Any] = field(default_factory=dict)
    caps_applied: List[str] = field(default_factory=list)


@dataclass
class Scan:
    id: str = field(default_factory=generate_id)
    project_id: str = ""
    artifact_id: str = ""
    target_url: str = ""
    target_ref: str = "main"
    resolved_commit_sha: str = ""
    profile: str = "mvp-static-v1"
    status: ScanStatus = ScanStatus.QUEUED
    stage: ScanStage = ScanStage.INIT
    progress_pct: int = 0
    error_summary: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    requested_at: datetime = field(default_factory=utc_now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    ai_config: Dict[str, Any] = field(default_factory=dict)
