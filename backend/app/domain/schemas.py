"""AI Software Trust Gateway - API Pydantic 数据契约 (Pydantic Schemas)
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl

from backend.app.domain.enums import (
    DependencyScope,
    Ecosystem,
    FindingCategory,
    RiskLevel,
    ScanStage,
    ScanStatus,
    Severity,
)


class ScanSourceInput(BaseModel):
    type: str = Field(default="github", description="源类型: github, archive, local")
    url: str = Field(..., description="目标仓库 URL (例如 https://github.com/owner/repo)")
    ref: str = Field(default="main", description="分支、标签或 Commit SHA")


class AIConfigInput(BaseModel):
    enabled: bool = Field(default=False, description="是否启用 AI 综合推理")
    provider: str = Field(default="disabled", description="提供者: disabled, openai_compatible（含本地兼容服务）")
    model: Optional[str] = Field(default="gpt-4o-mini", description="模型名称")


class CreateScanRequest(BaseModel):
    source: ScanSourceInput
    profile: str = Field(default="mvp-static-v1", description="评分配置版本")
    ai: Optional[AIConfigInput] = Field(default_factory=AIConfigInput)


class CreateScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    stage: ScanStage
    status_url: str
    created_at: datetime


class EvidenceSchema(BaseModel):
    id: str
    kind: str
    source: str
    location: str
    excerpt_redacted: str
    sha256: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class FindingSchema(BaseModel):
    id: str
    fingerprint: str
    scanner_name: str
    category: FindingCategory
    title: str
    severity: Severity
    confidence: float
    file_path: str
    line_start: int
    line_end: int
    remediation: str
    evidences: List[EvidenceSchema] = Field(default_factory=list)
    ai_assessment: Optional[Dict[str, Any]] = None
    status: str = "active"


class FindingPageResponse(BaseModel):
    items: List[FindingSchema]
    total: int
    page: int
    page_size: int


class VulnerabilitySchema(BaseModel):
    id: str
    advisory_id: str
    aliases: List[str] = Field(default_factory=list)
    summary: str
    cvss_score: Optional[float] = None
    severity: Severity
    fixed_versions: List[str] = Field(default_factory=list)
    source_url: str


class DependencySchema(BaseModel):
    id: str
    ecosystem: Ecosystem
    name: str
    version: str
    scope: DependencyScope
    manifest_path: str
    vulnerabilities: List[VulnerabilitySchema] = Field(default_factory=list)


class DependencyPageResponse(BaseModel):
    items: List[DependencySchema]
    total: int


class ScoreSchema(BaseModel):
    scoring_version: str
    safety_score: int
    risk_score: int
    risk_level: RiskLevel
    confidence: float
    coverage: float
    components: Dict[str, Any] = Field(default_factory=dict)
    caps_applied: List[str] = Field(default_factory=list)


class ScanSummaryResponse(BaseModel):
    scan_id: str
    target_url: str
    target_ref: str
    resolved_commit_sha: Optional[str] = None
    status: ScanStatus
    stage: ScanStage
    progress_pct: int
    error_summary: Optional[str] = None
    languages: List[str] = Field(default_factory=list)
    findings_count: int = 0
    dependencies_count: int = 0
    vulnerabilities_count: int = 0
    score: Optional[ScoreSchema] = None
    ai_enabled: bool = False
    requested_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanListResponse(BaseModel):
    items: List[ScanSummaryResponse]
    total: int


class AnalysisResponse(BaseModel):
    scan_id: str
    purpose_profile: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    ai_analysis: Dict[str, Any] = Field(default_factory=dict)
    scanner_runs: List[Dict[str, Any]] = Field(default_factory=list)
    coverage: Dict[str, float] = Field(default_factory=dict)
    dynamic_analysis: Dict[str, Any] = Field(default_factory=dict)


class ReportResponse(BaseModel):
    scan_id: str
    schema_version: str = "1.0"
    html_url: str
    json_url: str
    generated_at: datetime


class CapabilityResponse(BaseModel):
    version: str = "1.0.0"
    mode: str = "mvp-static-v1"
    platform: str = "windows"
    scanners: List[str] = Field(default_factory=lambda: ["astg_ast_python", "astg_js_pattern", "semgrep", "bandit", "osv"])
    scanner_status: Dict[str, str] = Field(default_factory=dict)
    ai_providers: List[str] = Field(default_factory=lambda: ["disabled", "openai_compatible"])
    supported_ecosystems: List[str] = Field(default_factory=lambda: ["PyPI", "npm"])
    dynamic_sandbox_available: bool = False
    sandbox_notice: str = "MVP 阶段仅执行安全静态分析与供应链审查，不执行目标代码。"
