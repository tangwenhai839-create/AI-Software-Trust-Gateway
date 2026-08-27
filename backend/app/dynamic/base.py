"""Contracts shared by dynamic sandbox providers."""
from abc import ABC, abstractmethod
from typing import Any, Dict


class DynamicAnalysisProvider(ABC):
    @property
    @abstractmethod
    def provider_type(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def analyze(self, repo_dir: str, scan_id: str) -> Dict[str, Any]:
        """Analyze a target inside an isolated environment and return evidence."""
        raise NotImplementedError
