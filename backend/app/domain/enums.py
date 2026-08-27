"""AI Software Trust Gateway - 核心领域枚举定义
"""
from enum import Enum


class ScanStatus(str, Enum):
    QUEUED = "queued"
    INGESTING = "ingesting"
    SCANNING = "scanning"
    REASONING = "reasoning"
    SCORING = "scoring"
    REPORTING = "reporting"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanStage(str, Enum):
    INIT = "init"
    INGESTION = "ingestion"
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    PROVENANCE_ANALYSIS = "provenance_analysis"
    AI_REASONING = "ai_reasoning"
    SCORING = "scoring"
    REPORT_GENERATION = "report_generation"
    FINISHED = "finished"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingCategory(str, Enum):
    SENSITIVE_FILE_ACCESS = "sensitive_file_access"
    NETWORK_EXFILTRATION = "network_exfiltration"
    DYNAMIC_EXECUTION = "dynamic_execution"
    COMMAND_EXECUTION = "command_execution"
    CODE_INJECTION = "code_injection"
    OBFUSCATION = "obfuscation"
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    INSECURE_CONFIGURATION = "insecure_configuration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PROVENANCE_RISK = "provenance_risk"
    SUSPICIOUS_PATTERN = "suspicious_pattern"


class Ecosystem(str, Enum):
    PYPI = "PyPI"
    NPM = "npm"
    MAVEN = "Maven"
    GO = "Go"
    CARGO = "crates.io"
    UNKNOWN = "unknown"


class DependencyScope(str, Enum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    UNRESOLVED = "unresolved"


class AIProviderType(str, Enum):
    DISABLED = "disabled"
    OPENAI_COMPATIBLE = "openai_compatible"
    LOCAL_LLM = "local_llm"


class PurposeAlignment(str, Enum):
    ALIGNED = "aligned"
    UNCLEAR = "unclear"
    MISALIGNED = "misaligned"
