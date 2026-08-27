'use client';

import React, { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft,
  Download,
  FileText,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Shield,
  Layers,
  Terminal,
  ExternalLink,
} from 'lucide-react';
import { API_BASE, getScanAnalysis, getScanDependencies, getScanFindings, getScanSummary } from '../../../lib/api';
import { Dependency, Finding, ScanAnalysis, ScanSummary, Severity } from '../../../lib/types';
import { DependencyTable } from '../../../components/DependencyTable';
import { FindingCard } from '../../../components/FindingCard';
import { ScanProgress } from '../../../components/ScanProgress';
import { ScoreGauge } from '../../../components/ScoreGauge';

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [dependencies, setDependencies] = useState<Dependency[]>([]);
  const [analysis, setAnalysis] = useState<ScanAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'findings' | 'dependencies' | 'ai' | 'provenance'>('findings');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const fetchScanData = async () => {
    try {
      const data = await getScanSummary(scanId);
      setSummary(data);

      if (data.status === 'completed' || data.status === 'partial') {
        const [fData, dData, aData] = await Promise.all([
          getScanFindings(scanId, severityFilter === 'all' ? undefined : severityFilter),
          getScanDependencies(scanId),
          getScanAnalysis(scanId),
        ]);
        setFindings(fData.items);
        setDependencies(dData.items);
        setAnalysis(aData);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanData();
    const interval = setInterval(() => {
      if (summary?.status !== 'completed' && summary?.status !== 'failed' && summary?.status !== 'cancelled') {
        fetchScanData();
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [scanId, summary?.status, severityFilter]);

  if (loading && !summary) {
    return (
      <div className="container" style={{ textAlign: 'center', paddingTop: '80px' }}>
        <RefreshCw size={32} className="pulsing" color="#38bdf8" />
        <div style={{ marginTop: '16px', color: '#94a3b8' }}>正在加载扫描数据...</div>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="container" style={{ textAlign: 'center', paddingTop: '80px' }}>
        <AlertTriangle size={36} color="#ef4444" />
        <div style={{ marginTop: '16px', fontSize: '18px', color: '#f8fafc' }}>未找到扫描任务</div>
        <button className="btn-secondary" style={{ marginTop: '20px' }} onClick={() => router.push('/')}>
          <ArrowLeft size={16} /> 返回控制台
        </button>
      </div>
    );
  }

  const isCompleted = summary.status === 'completed' || summary.status === 'partial';
  const analysisLimitations: string[] = analysis?.ai_analysis?.overall_assessment?.limitations || [];

  return (
    <div className="container" style={{ paddingTop: '24px', paddingBottom: '60px' }}>
      {/* 顶部导航与操作栏 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <button className="btn-secondary" onClick={() => router.push('/')}>
          <ArrowLeft size={16} /> 返回首页
        </button>

        {isCompleted && (
          <div style={{ display: 'flex', gap: '10px' }}>
            <a
              href={`${API_BASE}/scans/${scanId}/report.html`}
              target="_blank"
              rel="noreferrer"
              className="btn-primary"
              style={{ fontSize: '13px', padding: '8px 16px' }}
            >
              <FileText size={16} /> 查看独立 HTML 报告
            </a>
            <a
              href={`${API_BASE}/scans/${scanId}/report.json`}
              download
              className="btn-secondary"
              style={{ fontSize: '13px', padding: '8px 16px' }}
            >
              <Download size={16} /> 下载 JSON 报告
            </a>
          </div>
        )}
      </div>

      {/* 头部摘要信息 */}
      <div className="glass-panel" style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
          <div>
            <div style={{ fontSize: '12px', color: '#38bdf8', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '1px' }}>
              扫描目标详情
            </div>
            <h1 style={{ fontSize: '24px', fontWeight: 800, marginTop: '4px', wordBreak: 'break-all' }}>
              {summary.target_url}
            </h1>
            <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontSize: '13px', color: '#94a3b8', flexWrap: 'wrap' }}>
              <span>分支/Ref: <code>{summary.target_ref}</code></span>
              {summary.resolved_commit_sha && (
                <span>Commit: <code>{summary.resolved_commit_sha.slice(0, 12)}</code></span>
              )}
              <span>扫描 ID: <code>{summary.scan_id}</code></span>
            </div>
          </div>

          {summary.score && (
            <ScoreGauge
              score={summary.score.safety_score}
              riskLevel={summary.score.risk_level}
              confidence={summary.score.confidence}
              coverage={summary.score.coverage}
            />
          )}
        </div>

        {/* 阶段进度条 */}
        <div style={{ marginTop: '24px', borderTop: '1px solid #1e293b', paddingTop: '20px' }}>
          <ScanProgress status={summary.status} stage={summary.stage} progressPct={summary.progress_pct} />
        </div>

        {/* 触发的安全分上限警告 (Caps) */}
        {summary.score?.caps_applied && summary.score.caps_applied.length > 0 && (
          <div
            style={{
              marginTop: '18px',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '8px',
              padding: '12px 16px',
            }}
          >
            <div style={{ color: '#f87171', fontWeight: 600, fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <AlertTriangle size={16} /> 安全分上限触发提示 (Score Caps Applied):
            </div>
            <ul style={{ margin: '6px 0 0 20px', color: '#fca5a5', fontSize: '12px' }}>
              {summary.score.caps_applied.map((cap, idx) => (
                <li key={idx}>{cap}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Tab 导航与筛选 */}
      {isCompleted && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', marginBottom: '20px' }}>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                style={{
                  background: 'none',
                  border: 'none',
                  color: activeTab === 'findings' ? '#38bdf8' : '#94a3b8',
                  borderBottom: `2px solid ${activeTab === 'findings' ? '#38bdf8' : 'transparent'}`,
                  padding: '10px 16px',
                  fontWeight: 600,
                  fontSize: '14px',
                  cursor: 'pointer',
                }}
                onClick={() => setActiveTab('findings')}
              >
                代码安全发现 ({summary.findings_count})
              </button>
              <button
                style={{
                  background: 'none',
                  border: 'none',
                  color: activeTab === 'dependencies' ? '#38bdf8' : '#94a3b8',
                  borderBottom: `2px solid ${activeTab === 'dependencies' ? '#38bdf8' : 'transparent'}`,
                  padding: '10px 16px',
                  fontWeight: 600,
                  fontSize: '14px',
                  cursor: 'pointer',
                }}
                onClick={() => setActiveTab('dependencies')}
              >
                依赖与漏洞审查 ({summary.dependencies_count})
              </button>
              <button
                style={{ background: 'none', border: 'none', color: activeTab === 'ai' ? '#38bdf8' : '#94a3b8', borderBottom: `2px solid ${activeTab === 'ai' ? '#38bdf8' : 'transparent'}`, padding: '10px 16px', fontWeight: 600, fontSize: '14px', cursor: 'pointer' }}
                onClick={() => setActiveTab('ai')}
              >
                AI 与用途分析
              </button>
              <button
                style={{ background: 'none', border: 'none', color: activeTab === 'provenance' ? '#38bdf8' : '#94a3b8', borderBottom: `2px solid ${activeTab === 'provenance' ? '#38bdf8' : 'transparent'}`, padding: '10px 16px', fontWeight: 600, fontSize: '14px', cursor: 'pointer' }}
                onClick={() => setActiveTab('provenance')}
              >
                来源与扫描覆盖
              </button>
            </div>

            {activeTab === 'findings' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', paddingBottom: '8px' }}>
                <span style={{ fontSize: '12px', color: '#94a3b8' }}>严重度过滤:</span>
                <select
                  className="input-field"
                  style={{ padding: '4px 8px', fontSize: '12px', width: 'auto' }}
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <option value="all">全部严重度</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
            )}
          </div>

          {/* Tab 页面内容 */}
          {activeTab === 'findings' && (
            <div>
              {findings.length > 0 ? (
                findings.map((f, idx) => <FindingCard key={f.id} finding={f} index={idx + 1} />)
              ) : (
                <div className="glass-panel" style={{ textAlign: 'center', padding: '40px', color: '#34d399' }}>
                  <CheckCircle2 size={36} style={{ margin: '0 auto 12px auto' }} />
                  <div style={{ fontSize: '16px', fontWeight: 600 }}>在当前静态扫描规则下未发现风险特征</div>
                  <div style={{ fontSize: '13px', color: '#64748b', marginTop: '6px' }}>
                    仍建议在最小权限环境下运行未知第三方应用。
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'dependencies' && (
            <div className="glass-panel">
              <DependencyTable dependencies={dependencies} />
            </div>
          )}

          {activeTab === 'ai' && (
            <div className="glass-panel">
              <h3 style={{ marginTop: 0 }}>软件用途</h3>
              <p style={{ color: '#cbd5e1' }}>{analysis?.purpose_profile?.summary || '未提取到用途说明'}</p>
              <h3>AI / 离线规则结论</h3>
              <p style={{ color: '#cbd5e1' }}>{analysis?.ai_analysis?.overall_assessment?.summary || '没有可用的综合分析'}</p>
              {analysisLimitations.length > 0 && (
                <ul style={{ color: '#94a3b8' }}>{analysisLimitations.map((item: string, idx: number) => <li key={idx}>{item}</li>)}</ul>
              )}
            </div>
          )}

          {activeTab === 'provenance' && (
            <div className="glass-panel">
              <h3 style={{ marginTop: 0 }}>项目来源</h3>
              <pre style={{ whiteSpace: 'pre-wrap', color: '#cbd5e1' }}>{JSON.stringify(analysis?.provenance || {}, null, 2)}</pre>
              <h3>扫描器执行状态</h3>
              {(analysis?.scanner_runs || []).map((run, idx) => (
                <div key={idx} style={{ padding: '8px 0', borderBottom: '1px solid #1e293b', color: run.status === 'success' ? '#34d399' : '#f59e0b' }}>
                  {run.scanner}: {run.status}{run.error ? ` — ${run.error}` : ''}
                </div>
              ))}
              <h3>动态沙箱状态</h3>
              <pre style={{ whiteSpace: 'pre-wrap', color: '#cbd5e1' }}>{JSON.stringify(analysis?.dynamic_analysis || {}, null, 2)}</pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
