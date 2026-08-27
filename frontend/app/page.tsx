'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, Sparkles, AlertCircle, ArrowRight, Play, CheckCircle2, Lock, FileSearch } from 'lucide-react';
import { createScan, getCapabilities, getRecentScans } from '../lib/api';
import { CapabilityInfo, ScanSummary } from '../lib/types';

export default function HomePage() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [ref, setRef] = useState('main');
  const [aiEnabled, setAiEnabled] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [caps, setCaps] = useState<CapabilityInfo | null>(null);
  const [recentScans, setRecentScans] = useState<ScanSummary[]>([]);

  useEffect(() => {
    getCapabilities()
      .then(setCaps)
      .catch(() => {});
    getRecentScans(8)
      .then((data) => setRecentScans(data.items))
      .catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await createScan(url, ref, aiEnabled);
      router.push(`/scans/${res.scan_id}`);
    } catch (err: any) {
      setError(err.message || '提交扫描失败');
      setLoading(false);
    }
  };

  const handleQuickFill = (targetUrl: string, targetRef = 'main') => {
    setUrl(targetUrl);
    setRef(targetRef);
  };

  return (
    <div className="container" style={{ paddingTop: '40px', paddingBottom: '60px' }}>
      {/* 头部 Slogan */}
      <div style={{ textAlign: 'center', marginBottom: '40px' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(56, 189, 248, 0.1)',
            border: '1px solid rgba(56, 189, 248, 0.25)',
            padding: '6px 14px',
            borderRadius: '20px',
            fontSize: '13px',
            color: '#38bdf8',
            marginBottom: '16px',
          }}
        >
          <Sparkles size={14} /> 面向 AI Agent 与开发者的本地前置可信防线
        </div>
        <h1 style={{ fontSize: '38px', fontWeight: 800, letterSpacing: '-0.5px', marginBottom: '12px' }}>
          在运行第三方代码与 AI 插件之前，<br />
          <span style={{ background: 'linear-gradient(135deg, #38bdf8 0%, #3b82f6 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            先建立客观安全与可信判断
          </span>
        </h1>
        <p style={{ color: '#94a3b8', fontSize: '16px', maxWidth: '650px', margin: '0 auto' }}>
          ASTG 融合多源静态分析、依赖已知漏洞匹配与受限 AI 推理，
          提供可解释、不可伪造的确定性安全决策依据。
        </p>
      </div>

      {/* 提交扫描主卡片 */}
      <div className="glass-panel" style={{ maxWidth: '800px', margin: '0 auto 40px auto' }}>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontSize: '14px', fontWeight: 600, color: '#cbd5e1', marginBottom: '8px' }}>
              GitHub 仓库 URL / 本地测试路径
            </label>
            <input
              type="text"
              className="input-field"
              placeholder="例如: https://github.com/psf/requests 或 local://fixtures/suspicious_stealer"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '24px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', color: '#94a3b8', marginBottom: '6px' }}>
                分支 / Commit SHA
              </label>
              <input
                type="text"
                className="input-field"
                placeholder="main"
                value={ref}
                onChange={(e) => setRef(e.target.value)}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'flex-end' }}>
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: 'rgba(15, 23, 42, 0.8)',
                  border: '1px solid #334155',
                  padding: '12px 14px',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  fontSize: '13px',
                  color: '#f8fafc',
                }}
              >
                <input
                  type="checkbox"
                  checked={aiEnabled}
                  onChange={(e) => setAiEnabled(e.target.checked)}
                  style={{ width: '16px', height: '16px', accentColor: '#0284c7' }}
                />
                <span>启用 AI 语义推理 (默认关闭保障隐私)</span>
              </label>
            </div>
          </div>

          {error && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                padding: '12px 16px',
                borderRadius: '8px',
                color: '#f87171',
                fontSize: '14px',
                marginBottom: '20px',
              }}
            >
              <AlertCircle size={18} />
              <span>{error}</span>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', fontSize: '12px', color: '#64748b' }}>
              <Lock size={14} color="#34d399" />
              <span>零代码执行 • 绝不运行 Git Hooks • SSRF 安全拦截</span>
            </div>
            <button type="submit" className="btn-primary" disabled={loading || !url.trim()}>
              {loading ? (
                '正在创建扫描...'
              ) : (
                <>
                  <Play size={16} fill="#ffffff" />
                  开始可信安全审查
                </>
              )}
            </button>
          </div>
        </form>

        {/* 快速演示样本 */}
        <div style={{ marginTop: '24px', paddingTop: '16px', borderTop: '1px solid #1e293b' }}>
          <span style={{ fontSize: '12px', color: '#94a3b8', marginRight: '10px' }}>快速测试样本:</span>
          <button
            type="button"
            className="btn-secondary"
            style={{ fontSize: '12px', padding: '4px 10px', marginRight: '8px' }}
            onClick={() => handleQuickFill('local://fixtures/benign_image_tool')}
          >
            🛡 良性图像工具样本
          </button>
          <button
            type="button"
            className="btn-secondary"
            style={{ fontSize: '12px', padding: '4px 10px', marginRight: '8px' }}
            onClick={() => handleQuickFill('local://fixtures/suspicious_stealer')}
          >
            🚨 窃密与外传特征样本
          </button>
          <button
            type="button"
            className="btn-secondary"
            style={{ fontSize: '12px', padding: '4px 10px' }}
            onClick={() => handleQuickFill('https://github.com/psf/requests', 'main')}
          >
            🌐 PSF/requests
          </button>
        </div>
      </div>

      {/* 核心三层信任体系卡片 */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
        <div className="glass-panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <div style={{ background: 'rgba(56, 189, 248, 0.1)', padding: '8px', borderRadius: '8px' }}>
              <FileSearch size={20} color="#38bdf8" />
            </div>
            <h3 style={{ fontSize: '16px', fontWeight: 700 }}>1. 确定性规则发现</h3>
          </div>
          <p style={{ fontSize: '13px', color: '#94a3b8', lineHeight: 1.6 }}>
            集成 Semgrep、Bandit、Python AST 与模式识别，深度审查动态代码执行 (eval/exec)、敏感凭据读取及隐蔽网络通信。
          </p>
        </div>

        <div className="glass-panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <div style={{ background: 'rgba(16, 185, 129, 0.1)', padding: '8px', borderRadius: '8px' }}>
              <Shield size={20} color="#10b981" />
            </div>
            <h3 style={{ fontSize: '16px', fontWeight: 700 }}>2. 供应链与 OSV 漏洞</h3>
          </div>
          <p style={{ fontSize: '13px', color: '#94a3b8', lineHeight: 1.6 }}>
            自动解析 requirements.txt、pyproject.toml 与 package.json，基于权威 OSV 开源漏洞数据库匹配已知 CVE 并提供修复建议。
          </p>
        </div>

        <div className="glass-panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <div style={{ background: 'rgba(59, 130, 246, 0.1)', padding: '8px', borderRadius: '8px' }}>
              <Sparkles size={20} color="#3b82f6" />
            </div>
            <h3 style={{ fontSize: '16px', fontWeight: 700 }}>3. 确定性评分与硬性上限</h3>
          </div>
          <p style={{ fontSize: '13px', color: '#94a3b8', lineHeight: 1.6 }}>
            采用 <code>mvp-static-v1</code> 算法，严重安全发现自动触发安全分上限 (Score Cap)，杜绝仅凭 AI 单独判定安全的风险。
          </p>
        </div>
      </div>

      {recentScans.length > 0 && (
        <div className="glass-panel" style={{ marginTop: '24px' }}>
          <h2 style={{ fontSize: '18px', marginBottom: '14px' }}>最近扫描</h2>
          {recentScans.map((item) => (
            <button
              key={item.scan_id}
              type="button"
              onClick={() => router.push(`/scans/${item.scan_id}`)}
              style={{ width: '100%', display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '16px', textAlign: 'left', alignItems: 'center', background: 'transparent', border: 0, borderTop: '1px solid #1e293b', padding: '12px 0', color: '#f8fafc', cursor: 'pointer' }}
            >
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.target_url}</span>
              <span style={{ color: '#94a3b8', fontSize: '12px' }}>{item.status}</span>
              <span className={`badge badge-${item.score?.risk_level || 'low'}`}>{item.score ? `${item.score.safety_score} 分` : `${item.progress_pct}%`}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
