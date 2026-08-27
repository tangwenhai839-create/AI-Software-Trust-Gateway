"""AI Software Trust Gateway - 报告生成器 (JSON Report & Standalone XSS-Safe HTML Report Generator)
"""
import hashlib
import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from backend.app.core.config import settings
from backend.app.domain.models import Artifact, Dependency, Finding, Project, PurposeProfile, Scan, Score


class ReportGenerator:
    """生成标准化 JSON 与安全单文件 HTML 报告"""

    def __init__(self, artifacts_base_dir: str = None):
        self.base_dir = Path(artifacts_base_dir or settings.ASTG_ARTIFACTS_DIR).resolve()

    def generate_reports(
        self,
        scan: Scan,
        project: Project,
        artifact: Artifact,
        score: Score,
        findings: List[Finding],
        dependencies: List[Dependency],
        provenance: Dict[str, Any],
        purpose: PurposeProfile,
        ai_analysis: Dict[str, Any],
        coverage: Dict[str, float],
        scanner_runs: List[Dict[str, Any]] = None,
        dynamic_analysis: Dict[str, Any] = None,
    ) -> Tuple[str, str, str, str]:
        """
        生成 JSON 与 HTML 报告。
        返回: (json_path, html_path, json_sha256, html_sha256)
        """
        scan_dir = self.base_dir / scan.id
        scan_dir.mkdir(parents=True, exist_ok=True)

        json_path = scan_dir / "report.json"
        html_path = scan_dir / "report.html"

        # 1. 结构化 JSON 报告
        top_risks = [f.title for f in findings if f.severity.value in ("critical", "high")][:3]
        if not top_risks:
            top_risks = ["在当前静态扫描覆盖范围内未发现严重风险"]

        recommended_action = "在最小权限环境中运行"
        if score.risk_level.value == "safe":
            recommended_action = "可考虑运行，仍需注意静态分析局限"
        elif score.risk_level.value == "high":
            recommended_action = "默认阻止运行，需要安全专家介入复核"
        elif score.risk_level.value == "medium":
            recommended_action = "建议人工复核或沙箱验证后运行"

        limitations = [
            "静态评估，不包含运行时验证",
            "依赖漏洞基于已知公开情报库",
        ]
        if scan.status.value == "partial":
            limitations.append("部分扫描器因缺少环境或执行超时未完成全部分析")

        report_dict: Dict[str, Any] = {
            "schema_version": "1.0",
            "scan_id": scan.id,
            "target": {
                "type": project.source_type or "github",
                "url": scan.target_url,
                "commit_sha": scan.resolved_commit_sha or artifact.commit_sha,
                "content_sha256": artifact.sha256,
                "languages": artifact.languages,
            },
            "status": scan.status.value,
            "score": {
                "safety_score": score.safety_score,
                "risk_score": score.risk_score,
                "risk_level": score.risk_level.value,
                "confidence": score.confidence,
                "coverage": score.coverage,
                "scoring_version": score.scoring_version,
                "components": score.components,
                "caps_applied": score.caps_applied,
            },
            "summary": {
                "conclusion": f"软件可信安全分 {score.safety_score}/100，判定为 [{score.risk_level.value.upper()}] 等级。",
                "top_risks": top_risks,
                "recommended_action": recommended_action,
                "limitations": limitations,
            },
            "findings": [
                {
                    "id": f.id,
                    "fingerprint": f.fingerprint,
                    "category": f.category.value,
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "file_path": f.file_path,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "remediation": f.remediation,
                    "evidences": [
                        {
                            "id": e.id,
                            "kind": e.kind,
                            "source": e.source,
                            "location": e.location,
                            "excerpt_redacted": e.excerpt_redacted,
                            "sha256": e.sha256,
                        }
                        for e in f.evidences
                    ],
                    "ai_assessment": f.ai_assessment,
                }
                for f in findings
            ],
            "dependencies": [
                {
                    "id": d.id,
                    "ecosystem": d.ecosystem.value,
                    "name": d.name,
                    "version": d.version,
                    "scope": d.scope.value,
                    "manifest_path": d.manifest_path,
                    "vulnerabilities": [
                        {
                            "id": v.id,
                            "advisory_id": v.advisory_id,
                            "aliases": v.aliases,
                            "summary": v.summary,
                            "details": v.details,
                            "cvss_score": v.cvss_score,
                            "severity": v.severity.value,
                            "fixed_versions": v.fixed_versions,
                            "source_url": v.source_url,
                        }
                        for v in d.vulnerabilities
                    ],
                }
                for d in dependencies
            ],
            "provenance": provenance,
            "purpose_profile": {
                "summary": purpose.summary,
                "declared_capabilities": purpose.declared_capabilities,
                "expected_external_services": purpose.expected_external_services,
            },
            "ai_analysis": ai_analysis,
            "coverage": coverage,
            "scanner_runs": scanner_runs or [],
            "dynamic_analysis": dynamic_analysis or {},
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # 写入 JSON
        json_bytes = json.dumps(report_dict, indent=2, ensure_ascii=False).encode("utf-8")
        with open(json_path, "wb") as f:
            f.write(json_bytes)
        json_sha256 = hashlib.sha256(json_bytes).hexdigest()

        # 2. 生成安全单文件 HTML
        html_content = self._render_html_report(report_dict)
        html_bytes = html_content.encode("utf-8")
        with open(html_path, "wb") as f:
            f.write(html_bytes)
        html_sha256 = hashlib.sha256(html_bytes).hexdigest()

        return str(json_path), str(html_path), json_sha256, html_sha256

    def _render_html_report(self, data: Dict[str, Any]) -> str:
        # 上下文严格转义，防范存储型 XSS
        e = html.escape
        score_val = data["score"]["safety_score"]
        risk_level = data["score"]["risk_level"]

        badge_color = "#10b981"  # green
        if score_val < 40:
            badge_color = "#ef4444"  # red
        elif score_val < 70:
            badge_color = "#f59e0b"  # amber
        elif score_val < 90:
            badge_color = "#3b82f6"  # blue

        findings_html = ""
        for idx, f in enumerate(data.get("findings", []), 1):
            sev = f.get("severity", "medium").upper()
            sev_color = "#ef4444" if sev in ("CRITICAL", "HIGH") else "#f59e0b" if sev == "MEDIUM" else "#3b82f6"

            ev_html = ""
            for ev in f.get("evidences", []):
                snippet = ev.get("excerpt_redacted", "")
                ev_html += f"""
                <div style="margin-top: 8px; background: #0f172a; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #94a3b8; overflow-x: auto; border: 1px solid #334155;">
                  <div style="color: #64748b; margin-bottom: 4px;">来源: {e(ev.get("source", ""))} | 位置: {e(ev.get("location", ""))}</div>
                  <pre style="margin: 0; color: #f1f5f9; white-space: pre-wrap;">{e(snippet)}</pre>
                </div>
                """

            findings_html += f"""
            <div style="background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 12px; border-left: 4px solid {sev_color};">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div style="font-weight: 600; font-size: 15px; color: #f8fafc;">#{idx} {e(f.get("title", ""))}</div>
                <span style="background: {sev_color}22; color: {sev_color}; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold;">{e(sev)}</span>
              </div>
              <div style="color: #94a3b8; font-size: 13px; margin-top: 6px;">
                类别: <code>{e(f.get("category", ""))}</code> | 文件: <code>{e(f.get("file_path", ""))}:{f.get("line_start", 0)}</code>
              </div>
              <div style="color: #cbd5e1; font-size: 13px; margin-top: 6px;">
                <strong>修复建议:</strong> {e(f.get("remediation", ""))}
              </div>
              {ev_html}
            </div>
            """

        if not findings_html:
            findings_html = '<div style="color: #10b981; padding: 20px; text-align: center; background: #1e293b; border-radius: 8px;">✓ 在当前静态分析规则下未发现可疑代码模式</div>'

        deps_html = ""
        for dep in data.get("dependencies", []):
            vulns = dep.get("vulnerabilities", [])
            vuln_tag = f'<span style="color: #ef4444; font-weight: bold;">{len(vulns)} 漏洞</span>' if vulns else '<span style="color: #10b981;">安全</span>'
            deps_html += f"""
            <tr style="border-bottom: 1px solid #334155;">
              <td style="padding: 10px; color: #f8fafc; font-family: monospace;">{e(dep.get("name", ""))}</td>
              <td style="padding: 10px; color: #94a3b8;">{e(dep.get("version", ""))}</td>
              <td style="padding: 10px; color: #94a3b8;">{e(dep.get("ecosystem", ""))}</td>
              <td style="padding: 10px; color: #94a3b8;">{e(dep.get("scope", ""))}</td>
              <td style="padding: 10px;">{vuln_tag}</td>
            </tr>
            """

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ASTG 安全评估报告 - {e(data["target"]["url"])}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #0b0f19; color: #f8fafc; margin: 0; padding: 24px; line-height: 1.5; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    .card {{ background: #131d2e; border: 1px solid #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3); }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 20px; }}
    .score-box {{ text-align: center; background: #1e293b; padding: 20px 30px; border-radius: 12px; border: 2px solid {badge_color}; }}
    .score-val {{ font-size: 48px; font-weight: 800; color: {badge_color}; }}
    .tag {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; background: #334155; color: #cbd5e1; margin-right: 6px; margin-bottom: 6px; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
    th {{ padding: 10px; background: #1e293b; color: #94a3b8; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <div>
          <div style="font-size: 13px; color: #38bdf8; font-weight: 600; letter-spacing: 1px; text-transform: uppercase;">AI Software Trust Gateway 评估报告</div>
          <h1 style="margin: 6px 0 0 0; font-size: 24px;">{e(data["target"]["url"])}</h1>
          <div style="color: #64748b; font-size: 13px; margin-top: 4px;">Commit: <code>{e(data["target"]["commit_sha"])}</code> | 扫描 ID: <code>{e(data["scan_id"])}</code></div>
        </div>
        <div class="score-box">
          <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">安全评分</div>
          <div class="score-val">{score_val}</div>
          <div style="font-size: 13px; color: {badge_color}; font-weight: bold; text-transform: uppercase;">{e(risk_level)} RISK</div>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 20px;">
        <div style="background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #1e293b;">
          <div style="color: #64748b; font-size: 12px;">建议动作</div>
          <div style="color: #f8fafc; font-weight: 600; font-size: 14px; margin-top: 4px;">{e(data["summary"]["recommended_action"])}</div>
        </div>
        <div style="background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #1e293b;">
          <div style="color: #64748b; font-size: 12px;">代码与依赖覆盖率</div>
          <div style="color: #f8fafc; font-weight: 600; font-size: 14px; margin-top: 4px;">{int(data["score"]["coverage"] * 100)}% (置信度: {int(data["score"]["confidence"] * 100)}%)</div>
        </div>
        <div style="background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #1e293b;">
          <div style="color: #64748b; font-size: 12px;">识别主要语言</div>
          <div style="color: #f8fafc; font-weight: 600; font-size: 14px; margin-top: 4px;">{e(", ".join(data["target"]["languages"]))}</div>
        </div>
      </div>

      <div>
        <div style="font-size: 14px; font-weight: 600; margin-bottom: 8px; color: #cbd5e1;">扫描限制与声明:</div>
        <div>
          {' '.join([f'<span class="tag">⚠ {e(l)}</span>' for l in data["summary"]["limitations"]])}
        </div>
      </div>
    </div>

    <!-- 发现项详情 -->
    <div class="card">
      <h2 style="font-size: 18px; margin-top: 0; margin-bottom: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 10px;">
        安全发现项与代码证据 ({len(data.get("findings", []))})
      </h2>
      {findings_html}
    </div>

    <!-- 依赖与已知漏洞 -->
    <div class="card">
      <h2 style="font-size: 18px; margin-top: 0; margin-bottom: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 10px;">
        依赖清单与已知漏洞 ({len(data.get("dependencies", []))})
      </h2>
      <table>
        <thead>
          <tr>
            <th>包名</th>
            <th>版本</th>
            <th>生态</th>
            <th>作用域</th>
            <th>状态</th>
          </tr>
        </thead>
        <tbody>
          {deps_html if deps_html else '<tr><td colspan="5" style="text-align: center; padding: 20px; color: #64748b;">未发现依赖清单</td></tr>'}
        </tbody>
      </table>
    </div>

    <!-- 声明用途与 AI 综合解释 -->
    <div class="card">
      <h2 style="font-size: 18px; margin-top: 0; margin-bottom: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 10px;">
        声明用途与 AI 安全解释
      </h2>
      <div style="background: #0f172a; padding: 14px; border-radius: 8px; margin-bottom: 14px; border: 1px solid #1e293b;">
        <div style="color: #64748b; font-size: 12px;">软件声明用途</div>
        <div style="color: #f8fafc; margin-top: 4px; font-size: 14px;">{e(data.get("purpose_profile", {}).get("summary", ""))}</div>
      </div>
      <div style="background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #1e293b;">
        <div style="color: #64748b; font-size: 12px;">AI / 规则综合判定</div>
        <div style="color: #cbd5e1; margin-top: 4px; font-size: 14px;">{e(data.get("ai_analysis", {}).get("overall_assessment", {}).get("summary", "AI 综合分析已完成。"))}</div>
      </div>
    </div>

    <div style="text-align: center; color: #475569; font-size: 12px; margin-top: 20px;">
      Generated by AI Software Trust Gateway (ASTG) v1.0 • 本地可信安全网关 • {e(data["generated_at"])}
    </div>
  </div>
</body>
</html>
"""
