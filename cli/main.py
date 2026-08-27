"""AI Software Trust Gateway - 命令行界面 (ASTG CLI)
"""
import json
import os
import sys
import time
import click

# 确保 Windows 终端支持 UTF-8 编码
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from cli.client import ASTGClient


@click.group()
@click.version_option(version="1.0.0", prog_name="astg")
def main():
    """AI Software Trust Gateway (ASTG) - 本地开源 AI 软件可信安全网关 CLI"""
    pass


@main.command()
@click.argument("target_url")
@click.option("--ref", default="main", help="Git 分支、标签或 Commit SHA (默认: main)")
@click.option("--profile", default="mvp-static-v1", help="评分配置版本 (默认: mvp-static-v1)")
@click.option("--ai", "ai_enabled", is_flag=True, default=False, help="启用 AI 综合语义推理 (默认关闭以保障隐私)")
@click.option("--api-url", default="http://127.0.0.1:8000", help="ASTG 服务 API 地址")
@click.option("--wait/--no-wait", default=True, help="是否阻塞等待扫描完成")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "html"]), default="text", help="输出格式")
def scan(target_url: str, ref: str, profile: str, ai_enabled: bool, api_url: str, wait: bool, output_format: str):
    """提交目标仓库并执行安全可信评估"""
    client = ASTGClient(base_url=api_url)
    click.echo(f"[*] 正在提交扫描任务: {target_url} (ref: {ref})...")

    try:
        res = client.create_scan(url=target_url, ref=ref, profile=profile, ai_enabled=ai_enabled)
    except Exception as e:
        click.secho(f"[!] 提交扫描失败: {str(e)}", fg="red", err=True)
        sys.exit(1)

    scan_id = res["scan_id"]
    click.secho(f"[✓] 任务已创建，Scan ID: {scan_id}", fg="green")

    if not wait:
        click.echo(f"使用 'astg status {scan_id}' 查询执行进度。")
        return

    click.echo("[*] 正在执行多维度安全静态审查与依赖扫描...")
    start_time = time.time()

    while True:
        try:
            status_data = client.get_scan(scan_id)
            curr_status = status_data.get("status")
            stage = status_data.get("stage")
            pct = status_data.get("progress_pct", 0)

            if curr_status in ("completed", "partial"):
                break
            elif curr_status in ("failed", "cancelled"):
                click.secho(f"\n[!] 扫描任务已中止: {curr_status} ({status_data.get('error_summary')})", fg="red")
                sys.exit(1)

            sys.stdout.write(f"\r[-] 阶段: {stage} ({pct}%) ...")
            sys.stdout.flush()
            time.sleep(1)

            if time.time() - start_time > 600:  # 10 分钟超时
                click.secho("\n[!] 等待扫描结果超时", fg="red")
                sys.exit(1)
        except KeyboardInterrupt:
            click.echo("\n[*] 用户取消等待")
            return
        except Exception as e:
            click.secho(f"\n[!] 查询状态异常: {str(e)}", fg="yellow")
            time.sleep(2)

    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()

    score_info = status_data.get("score", {})
    safety_score = score_info.get("safety_score", 0)
    risk_level = score_info.get("risk_level", "unknown").upper()
    findings_count = status_data.get("findings_count", 0)
    deps_count = status_data.get("dependencies_count", 0)
    vulns_count = status_data.get("vulnerabilities_count", 0)

    color = "green" if safety_score >= 90 else "blue" if safety_score >= 70 else "yellow" if safety_score >= 40 else "red"

    if output_format == "json":
        report_json = client.get_report_json(scan_id)
        click.echo(json.dumps(report_json, indent=2, ensure_ascii=False))
    elif output_format == "html":
        html_str = client.download_report_html(scan_id)
        click.echo(html_str)
    else:
        click.echo("=" * 60)
        click.secho(f" ASTG 软件可信安全评估报告", bold=True)
        click.echo("=" * 60)
        click.echo(f" 目标仓库  : {target_url}")
        click.echo(f" Commit    : {status_data.get('resolved_commit_sha', ref)}")
        click.echo(f" 发现项数  : {findings_count} 项代码特征")
        click.echo(f" 依赖审查  : {deps_count} 个依赖 (发现 {vulns_count} 个已知漏洞)")
        click.echo("-" * 60)
        click.secho(f" 安全评分  : {safety_score} / 100", fg=color, bold=True)
        click.secho(f" 风险等级  : {risk_level} RISK", fg=color, bold=True)
        click.echo("=" * 60)

        # 打印 Top Findings
        if findings_count > 0:
            findings_data = client.get_findings(scan_id)
            click.echo("\n[主要安全发现项]:")
            for f in findings_data.get("items", [])[:5]:
                f_sev = f.get("severity", "").upper()
                f_col = "red" if f_sev in ("CRITICAL", "HIGH") else "yellow" if f_sev == "MEDIUM" else "blue"
                click.secho(f" • [{f_sev}] {f.get('title')} ({f.get('file_path')}:{f.get('line_start')})", fg=f_col)

        click.echo(f"\n[HTML 完整报告]: {api_url}/api/v1/scans/{scan_id}/report.html")

    # CI Exit Code
    if safety_score < 40:
        sys.exit(2)  # 高风险退出码
    sys.exit(0)


@main.command()
@click.argument("scan_id")
@click.option("--api-url", default="http://127.0.0.1:8000", help="ASTG 服务 API 地址")
def status(scan_id: str, api_url: str):
    """查询指定扫描任务的详细状态"""
    client = ASTGClient(base_url=api_url)
    try:
        data = client.get_scan(scan_id)
        click.echo(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception as e:
        click.secho(f"[!] 查询失败: {str(e)}", fg="red")
        sys.exit(1)


@main.command()
@click.argument("scan_id")
@click.option("--format", "fmt", type=click.Choice(["json", "html"]), default="json")
@click.option("--save", "save_path", help="保存报告至本地文件路径")
@click.option("--api-url", default="http://127.0.0.1:8000", help="ASTG 服务 API 地址")
def report(scan_id: str, fmt: str, save_path: str, api_url: str):
    """下载并导出扫描报告"""
    client = ASTGClient(base_url=api_url)
    try:
        if fmt == "html":
            content = client.download_report_html(scan_id)
        else:
            data = client.get_report_json(scan_id)
            content = json.dumps(data, indent=2, ensure_ascii=False)

        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(content)
            click.secho(f"[✓] 报告已保存至: {save_path}", fg="green")
        else:
            click.echo(content)
    except Exception as e:
        click.secho(f"[!] 获取报告失败: {str(e)}", fg="red")
        sys.exit(1)


@main.command()
@click.option("--api-url", default="http://127.0.0.1:8000", help="ASTG 服务 API 地址")
def capabilities(api_url: str):
    """查询 ASTG 网关支持的能力与扫描器矩阵"""
    client = ASTGClient(base_url=api_url)
    try:
        caps = client.get_capabilities()
        click.echo(json.dumps(caps, indent=2, ensure_ascii=False))
    except Exception as e:
        click.secho(f"[!] 获取能力列表失败: {str(e)}", fg="red")
        sys.exit(1)


if __name__ == "__main__":
    main()
