import { CapabilityInfo, Dependency, Finding, ScanAnalysis, ScanSummary } from './types';

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000/api/v1';

export async function createScan(url: string, ref = 'main', aiEnabled = false): Promise<{ scan_id: string; status_url: string }> {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      source: {
        type: url.startsWith('local://') ? 'local' : 'github',
        url: url.trim(),
        ref: ref.trim() || 'main',
      },
      profile: 'mvp-static-v1',
      ai: {
        enabled: aiEnabled,
        provider: aiEnabled ? 'openai_compatible' : 'disabled',
      },
    }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ message: '提交失败' }));
    throw new Error(errorData.message || errorData.detail?.message || `请求失败 (${res.status})`);
  }

  return res.json();
}

export async function getScanSummary(scanId: string): Promise<ScanSummary> {
  const res = await fetch(`${API_BASE}/scans/${scanId}`, { cache: 'no-store' });
  if (!res.ok) {
    throw new Error('查询扫描信息失败');
  }
  return res.json();
}

export async function getRecentScans(limit = 10): Promise<{ items: ScanSummary[]; total: number }> {
  const res = await fetch(`${API_BASE}/scans?limit=${limit}`, { cache: 'no-store' });
  if (!res.ok) throw new Error('获取扫描历史失败');
  return res.json();
}

export async function getHealth(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/health/ready`, { cache: 'no-store' });
  if (!res.ok) throw new Error('服务未就绪');
  return res.json();
}

export async function getScanFindings(scanId: string, severity?: string): Promise<{ items: Finding[]; total: number }> {
  const url = new URL(`${API_BASE}/scans/${scanId}/findings`);
  if (severity) {
    url.searchParams.set('severity', severity);
  }
  const res = await fetch(url.toString(), { cache: 'no-store' });
  if (!res.ok) {
    throw new Error('获取发现项失败');
  }
  return res.json();
}

export async function getScanDependencies(scanId: string): Promise<{ items: Dependency[]; total: number }> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/dependencies`, { cache: 'no-store' });
  if (!res.ok) throw new Error('获取依赖失败');
  return res.json();
}

export async function getScanAnalysis(scanId: string): Promise<ScanAnalysis> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/analysis`, { cache: 'no-store' });
  if (!res.ok) throw new Error('获取分析详情失败');
  return res.json();
}

export async function getCapabilities(): Promise<CapabilityInfo> {
  const res = await fetch(`${API_BASE}/capabilities`, { cache: 'no-store' });
  if (!res.ok) {
    throw new Error('获取系统能力失败');
  }
  return res.json();
}
