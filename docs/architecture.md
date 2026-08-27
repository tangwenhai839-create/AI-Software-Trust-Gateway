# ASTG 系统架构设计 (Architecture Design)

## 1. 架构总览

ASTG 采用模块化单体 (Modular Monolith) 架构，保证本地开发轻量部署与生产环境分布式扩容的一致性。

```
+-------------------------------------------------------------+
|               Client Layer (CLI / Next.js / MCP)            |
+-------------------------------------------------------------+
                              │ REST API (/api/v1)
+─────────────────────────────▼───────────────────────────────+
|               FastAPI Control Plane (Port 8000)             |
|  - Rate Limiter & SSRF Filter                               |
|  - Request ID & Logging Middleware                          |
|  - In-process Async Queue / Celery Task Dispatcher          |
+─────────────────────────────┬───────────────────────────────+
                              │
+─────────────────────────────▼───────────────────────────────+
|                  Scan Workflow Orchestrator                 |
|                                                             |
|  1. Safe Ingestion & Isolation (ArchiveGuard / Git Fetch)    |
|  2. Static Security Scanners (Python AST, JS, Semgrep, Bandit)|
|  3. Dependency & OSV Analyzer (PyPI, npm manifests)         |
|  4. Provenance Collector (GitHub metadata & trust signals)  |
|  5. Purpose Profile Extractor (README & capability facts)   |
|  6. AI Reasoning Engine (Prompt-Injection Safe & Schematized)|
|  7. Deterministic Scoring Engine (mvp-static-v1 & Score Caps)|
|  8. Report Generator (JSON v1 & CSP XSS-Safe HTML)          |
+─────────────────────────────────────────────────────────────+
                              │
+─────────────────────────────▼───────────────────────────────+
|                  Storage & Artifacts Layer                  |
|  - SQLite (Local) / PostgreSQL 16 (Production)              |
|  - Local File Artifacts Storage (/artifacts/{scan_id}/)     |
+-------------------------------------------------------------+
```

## 2. 核心模块与职责

1. **`ingestion`**：解析验证目标 URL，阻断 SSRF，安全流式下载 ZIP 归档，并在受控环境中提取。
2. **`scanners`**：基于 `ScannerAdapter` 接口封装各语言与工具规则，统一输出标准化 `Finding` 与 `Evidence`。
3. **`dependencies`**：解析依赖清单，批量检索 OSV 漏洞库并映射严重度。
4. **`reasoning`**：受限脱敏提示组装，严格 JSON Schema 输出校验与证据 ID 真实性检验。
5. **`services/scoring`**：版本化评分引擎，加权计算并执行严重发现分值上限限制。
6. **`reports`**：生成双格式报告（JSON + HTML）。
