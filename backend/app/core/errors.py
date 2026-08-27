"""AI Software Trust Gateway - 统一异常体系
"""
from typing import Any, Dict, Optional


class ASTGException(Exception):
    """ASTG 基础异常"""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class SSRFValidationError(ASTGException):
    """SSRF 或非法 URL 异常"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="SSRF_SECURITY_VIOLATION", details=details)


class ArchiveSafetyError(ASTGException):
    """解压安全、路径穿越或压缩炸弹异常"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="ARCHIVE_SAFETY_VIOLATION", details=details)


class ResourceLimitExceededError(ASTGException):
    """资源限制超出异常"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="RESOURCE_LIMIT_EXCEEDED", details=details)


class IngestionError(ASTGException):
    """获取与摄取失败"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="INGESTION_FAILED", details=details)


class ScanNotFoundError(ASTGException):
    """扫描任务未找到"""
    def __init__(self, scan_id: str):
        super().__init__(f"扫描任务未找到: {scan_id}", code="SCAN_NOT_FOUND", details={"scan_id": scan_id})


class AIValidationError(ASTGException):
    """AI 输出 Schema 校验或引用错误"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="AI_VALIDATION_ERROR", details=details)
