# ASTG REST API v1 规范

所有端点均以 `/api/v1` 为前缀。

## 1. 扫描任务管理

### `POST /api/v1/scans`
提交新的目标仓库进行可信审查。

- **请求体 (JSON)**:
```json
{
  "source": {
    "type": "github",
    "url": "https://github.com/owner/repo",
    "ref": "main"
  },
  "profile": "mvp-static-v1",
  "ai": {
    "enabled": false,
    "provider": "disabled"
  }
}
```
- **响应 (202 Accepted)**:
```json
{
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "queued",
  "stage": "init",
  "status_url": "/api/v1/scans/3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "created_at": "2026-08-27T12:00:00Z"
}
```

---

### `GET /api/v1/scans/{id}`
查询扫描进度与概要。

- **响应 (200 OK)**:
```json
{
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "target_url": "https://github.com/owner/repo",
  "target_ref": "main",
  "resolved_commit_sha": "a1b2c3d4e5f6...",
  "status": "completed",
  "stage": "finished",
  "progress_pct": 100,
  "findings_count": 2,
  "dependencies_count": 5,
  "vulnerabilities_count": 0,
  "score": {
    "safety_score": 92,
    "risk_score": 8,
    "risk_level": "safe",
    "confidence": 0.90,
    "coverage": 1.0
  }
}
```

---

### `GET /api/v1/scans/{id}/findings`
分页并过滤查看扫描发现项列表。

- **查询参数**:
  - `severity`: `critical | high | medium | low | info`
  - `category`: 类别过滤
  - `page`: 页码 (默认 1)
  - `page_size`: 每页条数 (默认 50)

---

### `GET /api/v1/scans/{id}/score`
获取详细评分构成、分项与上限规则。

---

### `GET /api/v1/scans/{id}/report.html`
下载或在浏览器中查看自包含的 HTML 评估报告。

---

### `GET /api/v1/scans/{id}/report.json`
下载符合 `report-v1.json` Schema 的结构化评估报告。

---

## 2. 健康检查与系统能力

- `GET /api/v1/health/live`
- `GET /api/v1/health/ready`
- `GET /api/v1/capabilities`
