"""AI Software Trust Gateway - 扫描器适配器抽象基类 (ScannerAdapter Base Interface)
"""
from abc import ABC, abstractmethod
from typing import List, Optional

from backend.app.domain.models import Finding


class ScannerAdapter(ABC):
    """
    所有静态扫描器的标准化适配器接口。
    生命周期: detect (适用性) -> prepare (规则/配置准备) -> run (安全执行) -> normalize (产出标准化 Finding)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """扫描器标识名 (如 semgrep, bandit, astg_ast)"""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """扫描器版本"""
        pass

    @abstractmethod
    def is_applicable(self, languages: List[str], repo_dir: str) -> bool:
        """根据仓库语言和结构判断是否应该运行该扫描器"""
        pass

    @abstractmethod
    async def scan(self, repo_dir: str, scan_id: str) -> List[Finding]:
        """
        在受控环境中执行扫描，捕获异常并返回标准化 Finding 列表。
        禁止直接将第三方工具的原始格式泄漏至业务层。
        """
        pass
