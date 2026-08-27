"""AI Software Trust Gateway - SQLAlchemy ORM 表模型定义
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from backend.app.db.session import Base


def utc_now():
    return datetime.now(timezone.utc)


def gen_uuid():
    return str(uuid.uuid4())


class ProjectModel(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    source_type = Column(String(32), default="github", nullable=False)
    canonical_url = Column(String(512), unique=True, nullable=False, index=True)
    owner = Column(String(128), nullable=False, index=True)
    name = Column(String(128), nullable=False, index=True)
    default_branch = Column(String(64), default="main")
    created_at = Column(DateTime(timezone=True), default=utc_now)

    scans = relationship("ScanModel", back_populates="project", cascade="all, delete-orphan")


class ArtifactModel(Base):
    __tablename__ = "artifacts"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    project_id = Column(String(36), nullable=False, index=True)
    commit_sha = Column(String(64), nullable=False, index=True)
    sha256 = Column(String(64), nullable=False)
    local_path = Column(String(512), nullable=False)
    size_bytes = Column(Integer, default=0)
    file_count = Column(Integer, default=0)
    languages = Column(JSON, default=list)
    manifest_paths = Column(JSON, default=list)
    entrypoints = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=True, index=True)
    artifact_id = Column(String(36), nullable=True, index=True)
    target_url = Column(String(512), nullable=False)
    target_ref = Column(String(64), default="main")
    resolved_commit_sha = Column(String(64), nullable=True)
    profile = Column(String(64), default="mvp-static-v1")
    status = Column(String(32), default="queued", index=True)
    stage = Column(String(32), default="init")
    progress_pct = Column(Integer, default=0)
    error_summary = Column(Text, nullable=True)
    error_details = Column(JSON, nullable=True)
    ai_config = Column(JSON, default=dict)
    requested_at = Column(DateTime(timezone=True), default=utc_now)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    project = relationship("ProjectModel", back_populates="scans")
    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")
    score = relationship("ScoreModel", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    report = relationship("ReportModel", back_populates="scan", uselist=False, cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    scanner_name = Column(String(64), nullable=False)
    fingerprint = Column(String(64), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    confidence = Column(Float, default=0.8)
    file_path = Column(String(512), nullable=False)
    line_start = Column(Integer, default=0)
    line_end = Column(Integer, default=0)
    remediation = Column(Text, default="")
    ai_assessment = Column(JSON, nullable=True)
    status = Column(String(32), default="active")

    scan = relationship("ScanModel", back_populates="findings")
    evidences = relationship("EvidenceModel", back_populates="finding", cascade="all, delete-orphan")


class EvidenceModel(Base):
    __tablename__ = "evidences"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False, index=True)
    kind = Column(String(32), default="code_snippet")
    source = Column(String(64), default="")
    location = Column(String(512), default="")
    excerpt_redacted = Column(Text, default="")
    sha256 = Column(String(64), default="")
    attributes = Column(JSON, default=dict)

    finding = relationship("FindingModel", back_populates="evidences")


class DependencyModel(Base):
    __tablename__ = "dependencies"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    artifact_id = Column(String(36), nullable=False, index=True)
    ecosystem = Column(String(32), nullable=False)
    name = Column(String(128), nullable=False, index=True)
    version = Column(String(64), nullable=False)
    scope = Column(String(16), default="direct")
    manifest_path = Column(String(512), default="")
    vulnerabilities_json = Column(JSON, default=list)


class ScoreModel(Base):
    __tablename__ = "scores"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), unique=True, nullable=False, index=True)
    scoring_version = Column(String(64), default="mvp-static-v1")
    safety_score = Column(Integer, default=100)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(16), default="safe")
    confidence = Column(Float, default=1.0)
    coverage = Column(Float, default=1.0)
    components = Column(JSON, default=dict)
    caps_applied = Column(JSON, default=list)

    scan = relationship("ScanModel", back_populates="score")


class ReportModel(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), unique=True, nullable=False, index=True)
    schema_version = Column(String(16), default="1.0")
    json_path = Column(String(512), nullable=False)
    html_path = Column(String(512), nullable=False)
    json_sha256 = Column(String(64), nullable=False)
    html_sha256 = Column(String(64), nullable=False)
    generated_at = Column(DateTime(timezone=True), default=utc_now)

    scan = relationship("ScanModel", back_populates="report")
