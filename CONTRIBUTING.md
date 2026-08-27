# Contributing

感谢参与 AI Software Trust Gateway。

## 开发流程

1. Fork 仓库并从 `main` 创建功能分支。
2. 后端修改需运行 `python -m pytest backend/tests -q`。
3. 前端修改需在 `frontend` 中运行 `npm ci` 与 `npm run build`。
4. 提交 Pull Request，并说明修改目标、风险影响和验证结果。

## 安全要求

- 不得在静态扫描流程中执行目标项目代码、安装脚本或 Git Hooks。
- 新增外部请求必须经过 SSRF 与超时限制审查。
- 不要提交 API Key、Token、数据库、扫描报告或真实敏感样本。
- 动态执行功能必须在明确的隔离提供者中实现，不得回退到宿主机执行。

安全漏洞请遵循 [SECURITY.md](SECURITY.md)，不要公开披露可直接利用的细节。
