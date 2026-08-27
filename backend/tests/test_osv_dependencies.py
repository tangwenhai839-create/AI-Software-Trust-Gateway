"""依赖解析与漏洞模型测试
"""
import pytest
from backend.app.dependencies.parsers.python_parser import PythonDependencyParser
from backend.app.dependencies.parsers.node_parser import NodeDependencyParser
from backend.app.domain.enums import DependencyScope, Ecosystem


def test_python_requirements_parser():
    content = "requests==2.28.1\nurllib3>=1.26.0\n# comment\npillow\n"
    deps = PythonDependencyParser._parse_requirements_txt(content, "requirements.txt", "art-1")
    assert len(deps) == 3
    assert deps[0].name == "requests"
    assert deps[0].version == "2.28.1"
    assert deps[0].scope == DependencyScope.DIRECT
    assert deps[1].scope == DependencyScope.UNRESOLVED


def test_node_package_json_parser(tmp_path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text('{"dependencies": {"express": "4.18.2", "lodash": "^4.17.21"}}', encoding="utf-8")

    deps = NodeDependencyParser.parse_manifest(str(pkg_json), str(tmp_path), "art-1")
    assert len(deps) == 2
    express_dep = next(d for d in deps if d.name == "express")
    assert express_dep.scope == DependencyScope.DIRECT
    lodash_dep = next(d for d in deps if d.name == "lodash")
    assert lodash_dep.scope == DependencyScope.UNRESOLVED
