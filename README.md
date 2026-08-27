# AI Software Trust Gateway (ASTG)

> **本地开源 AI 软件可信安全网关** — 在下载、安装或运行第三方软件、GitHub 项目、AI 插件和 MCP 工具之前，给出客观可解释的风险评估与决策依据。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](pyproject.toml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](backend/)
[![Next.js](https://img.shields.io/badge/Next.js-14+-black.svg)](frontend/)

---

## 1. 项目愿景与定位

ASTG **不是传统杀毒软件**，不以“发现危险关键词 = 判定病毒”为逻辑。在 AI Agent 时代，`eval()`、`subprocess()`、网络外发等行为既可能合理，也可能被滥用。

ASTG 结合软件宣称用途、多源静态代码特征、供应链已知漏洞 (OSV) 及确定性评分算法，输出可解释、可追溯、防伪造的安全评分 (0-100) 与风险等级。

```
              用户 / CLI / AI Agent / Web 界面
                             │
                  FastAPI 控制平面 (/api/v1)
                             │
                安全获取与解压隔离 (SSRF/解压安全保护)
                             │
     ┌───────────────────────┼───────────────────────┐
     ▼                       ▼                       ▼
静态代码审查引擎         OSV 供应链依赖分析        项目溯源与声誉
(Python AST / JS /    (PyPI / npm 清单解析     (GitHub 社区关注 /
 Semgrep / Bandit)      已知 CVE/Advisory)       许可证 / 异常特征)
     │                       │                       │
     └───────────────────────┼───────────────────────┘
                             ▼
                    多源证据去重与融合
                             ▼
               受限 AI 语义推理 (可选 / 默认关闭)
                             ▼
            确定性评分引擎 (mvp-static-v1 & 严重度上限 Caps)
                             ▼
             独立 HTML 报告 / 版本化 JSON 报告
```

---

## 2. 核心特性

- **🛡 严格安全防护**：
  - **绝不执行不可信代码**：静态审查阶段不运行 setup.py、npm install 或 Git hooks。
  - **全链路 SSRF 防御**：解析拦截本地回环 (127.0.0.1)、私有子网 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) 及云元数据地址 (169.254.169.254)。
  - **解压与路径穿越防护**：自动拒绝 `../` 逃逸路径、恶意跨目录符号链接及压缩炸弹。
- **🔍 多维度静态分析**：
  - 原生 Python AST 与模式扫描器：零外部依赖分析动态代码执行、敏感凭据文件读取（SSH/AWS/Wallet/浏览器 Cookies）及可疑 Webhook/数据外传。
  - Semgrep 与 Bandit 适配器：支持外部工具无缝接入并标准化输出 `Finding` 与 `Evidence`。
- **📦 供应链依赖审查**：
  - 自动解析 `requirements.txt`、`pyproject.toml`、`package.json`、`package-lock.json`。
  - 批量查询 Google OSV 权威漏洞数据库，映射 CVE 编号、严重度、CVSS 分数及修复版本。
- **⚖ 确定性评分引擎 (`mvp-static-v1`)**：
  - 相同代码与配置产出 100% 确定可复现的结果。
  - **硬性安全分上限 (Score Caps)**：Critical 严重安全发现强制将安全分限制在 $\le 39$（高风险），High 发现限制在 $\le 69$（中风险），杜绝虚高评分。
- **🤖 受限 AI 综合推理**：
  - 结构化输入、严格提示注入 (Prompt Injection) 隔离与敏感信息自动脱敏。
  - 严格 JSON Schema 校验及证据引用真实性检查（禁止 AI 虚构不存在的发现项或证据 ID）。
- **📊 独立自包含报告**：
  - 导出符合 `report-v1.json` 规范的机器可读 JSON。
  - 导出单文件独立 HTML 报告（严格 CSP、上下文转义防范存储型 XSS、暗黑高级质感）。
- **💻 CLI + Web 双重界面**：
  - Python CLI (`astg`)：适合 CI/CD 自动化集成，提供退出码（0: 安全/低风险, 1: 扫描失败, 2: 高风险）。
  - Next.js Web 管理界面：仪表盘、实时阶段进度条、径向安全分环仪表、交互式证据折叠抽屉。

---

## 3. 快速开始

### 3.1 环境要求
- Python 3.10+
- Node.js 18+ (用于 Web 前端)
- Docker & Docker Compose (可选，用于生产部署)

ASTG 的默认形态是**安装在用户自己的 Windows / Linux / macOS 电脑上本地使用**。API 默认只监听 `127.0.0.1`，不需要云服务器；Docker/PostgreSQL/Redis/Celery 是多人或服务器部署时的可选方案。

本地模式的数据默认保存在当前用户可写的数据目录中。在 Windows 上为 `%LOCALAPPDATA%\AI Software Trust Gateway`，因此后续安装到 `Program Files` 后也不会因安装目录不可写而丢失数据库或报告。

### 3.2 安装依赖

```bash
# 克隆或进入项目根目录
cd AI-Software-Trust-Gateway

# 安装 Python 后端与 CLI
pip install -e .

# 安装前端依赖
cd frontend && npm install && cd ..
```

### 3.3 启动服务

#### 方式 A：本地极简开发模式 (推荐)
```bash
# 启动 FastAPI 控制平面 API (监听 127.0.0.1:8000)
python -m backend.app.main

# 在新终端启动 Next.js Web 界面 (http://localhost:3000)
cd frontend
npm run dev
```

默认不会启用开发热重载，避免 Windows 安装版重复启动子进程。如需源码开发时自动重载，可在 `.env` 中设置 `ASTG_RELOAD=true`。

#### 方式 B：Docker Compose 生产一键启动
```bash
# 启动 PostgreSQL 16, Redis 7, API, Celery Worker 及 Next.js 前端
docker compose up -d --build
```

---

## 4. CLI 命令行使用指南

```bash
# 1. 扫描目标 GitHub 仓库
astg scan https://github.com/psf/requests --ref main

# 2. 扫描本地测试目录
astg scan local://fixtures/suspicious_stealer

# 3. 启用 AI 语义推理 (需要配置 OPENAI_API_KEY)
astg scan https://github.com/owner/repo --ai

# 4. 输出 JSON 格式
astg scan local://fixtures/benign_image_tool --format json

# 5. 查询任务状态
astg status <scan_id>

# 6. 下载/导出 HTML 报告至文件
astg report <scan_id> --format html --save report.html
```

---

## 5. 评分与等级对照表

| 安全评分 | 等级 | 判定含义 | 建议动作 |
|---:|---|---|---|
| **90 – 100** | **SAFE (安全)** | 在当前覆盖范围内未发现高风险特征 | 可考虑运行，仍需注意静态分析局限 |
| **70 – 89** | **LOW (低风险)** | 存在少量轻微或符合用途的功能调用 | 建议在最小权限或容器环境中运行 |
| **40 – 69** | **MEDIUM (中风险)** | 存在中高危调用或依赖漏洞 | 需人工复核代码或沙箱隔离验证 |
| **0 – 39** | **HIGH (高风险)** | 存在已证实的严重风险或数据窃取特征 | 默认阻止运行，需要安全专家介入 |

---

## 6. 自动化测试套件

ASTG 包含完整的单元测试、安全防御测试与端到端流水线测试：

```bash
# 运行全部 21+ 项测试用例
python -m pytest backend/tests/ -v
```

## 7. 当前能力边界

- 已可用：GitHub/本地目录获取、Python/JavaScript 原生静态规则、可选 Semgrep/Bandit、PyPI/npm 依赖解析、OSV 漏洞查询、项目用途提取、可选 OpenAI 兼容 AI 推理、评分、数据库持久化、CLI、Web 和 HTML/JSON 报告。
- 动态行为分析：已建立严格的可插拔提供者边界，默认记录为 `not_run`，不会在宿主机直接执行被扫描程序。
- 尚未交付：Docker/Frida/Sysmon/eBPF 动态取证提供者、Java/Go/Rust 深度规则、CodeQL/YARA、安装程序二进制逆向、MCP/IDE 插件。
- 因动态沙箱默认未执行，完整扫描覆盖率上限为 70%；报告会明确显示该限制，不能把静态扫描结果冒充完整运行时安全结论。

## 8. Windows 一键安装包

项目已经提供可复现的 Windows 打包脚本。构建机需要 Python 3.11、PyInstaller、Node.js、npm 和 Inno Setup 6：

```powershell
.\packaging\windows\build.ps1
```

生成结果位于：

`dist\installer\AI-Software-Trust-Gateway-Setup-1.0.3.exe`

安装包内置后端、Web 前端、SQLite、规则、Schema 和 Node.js 运行时。默认安装到当前用户的 LocalAppData，不需要管理员权限；桌面控制窗口负责启动、打开和停止本地服务。

---

## 9. 许可证

本项目基于 [MIT License](LICENSE) 开源。
