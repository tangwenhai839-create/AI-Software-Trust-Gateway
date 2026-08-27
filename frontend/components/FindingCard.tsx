'use client';

import React, { useState } from 'react';
import { Finding } from '../lib/types';
import { ChevronDown, ChevronUp, ShieldAlert, FileCode, CheckCircle } from 'lucide-react';

interface FindingCardProps {
  finding: Finding;
  index: number;
}

const riskExplanation: Record<string, string> = {
  network_exfiltration: '代码具备向外部地址发送数据的能力；如果传入敏感文件、令牌或用户数据，可能造成数据泄露。',
  dynamic_execution: '动态执行会把字符串当作代码运行；一旦内容可被外部输入控制，攻击者可能执行任意命令。',
  sensitive_file_access: '代码读取密钥、浏览器数据或凭据路径；这些内容泄露后可能导致账号、服务器或资产被接管。',
  privilege_escalation: '代码请求高权限或修改系统安全设置，可能扩大受攻击后的控制范围。',
  persistence: '代码可能建立启动项或持久化机制，使程序在用户不知情时持续运行。',
  network_communication: '代码会连接外部网络，需要确认目标域名、传输内容和软件声明用途是否一致。',
  suspicious_pattern: '该代码模式常见于高风险行为，需要结合调用参数、数据来源和软件用途进行人工复核。',
};

const explainRisk = (finding: Finding) =>
  riskExplanation[finding.category] ||
  '扫描器发现了可能影响机密性、完整性或可用性的行为，需要结合代码上下文确认是否合理。';

export const FindingCard: React.FC<FindingCardProps> = ({ finding, index }) => {
  const [expanded, setExpanded] = useState(false);

  const sev = finding.severity.toLowerCase();
  const badgeClass = `badge badge-${sev}`;
  const isHighRisk = sev === 'critical' || sev === 'high';
  const riskColor = isHighRisk ? '#f87171' : '#fbbf24';
  const riskBackground = isHighRisk ? 'rgba(239, 68, 68, 0.08)' : 'rgba(245, 158, 11, 0.08)';
  const riskBorder = isHighRisk ? 'rgba(239, 68, 68, 0.22)' : 'rgba(245, 158, 11, 0.24)';

  return (
    <div
      style={{
        background: 'rgba(18, 26, 43, 0.9)',
        border: '1px solid #1e293b',
        borderRadius: '10px',
        padding: '16px',
        marginBottom: '12px',
        transition: 'all 0.2s ease',
      }}
    >
      <div
        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', cursor: 'pointer' }}
        onClick={() => setExpanded(!expanded)}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className={badgeClass}>{finding.severity.toUpperCase()}</span>
          <div>
            <div style={{ fontWeight: 600, fontSize: '15px', color: '#f8fafc' }}>
              #{index} {finding.title}
            </div>
            <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px', display: 'flex', gap: '12px' }}>
              <span>类别: <code style={{ color: '#38bdf8' }}>{finding.category}</code></span>
              <span>位置: <code style={{ color: '#cbd5e1' }}>{finding.file_path}:{finding.line_start}</code></span>
              <span>扫描器: {finding.scanner_name}</span>
            </div>
            <div style={{ fontSize: '12px', color: riskColor, marginTop: '7px', lineHeight: 1.5 }}>
              为什么有风险：{explainRisk(finding)}
            </div>
          </div>
        </div>
        <button
          className="btn-secondary"
          style={{ padding: '4px 8px', fontSize: '12px', borderRadius: '4px' }}
          onClick={(e) => {
            e.stopPropagation();
            setExpanded(!expanded);
          }}
        >
          {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </button>
      </div>

      {/* 展开的详情与代码证据 */}
      {expanded && (
        <div style={{ marginTop: '16px', borderTop: '1px solid #1e293b', paddingTop: '14px' }}>
          <div style={{ marginBottom: '12px', background: riskBackground, border: `1px solid ${riskBorder}`, padding: '10px 14px', borderRadius: '6px', fontSize: '13px', lineHeight: 1.6 }}>
            <strong style={{ color: riskColor }}>{isHighRisk ? '高风险解释：' : '风险解释：'}</strong> {explainRisk(finding)}
            <div style={{ color: '#94a3b8', marginTop: '4px' }}>
              报告原因：扫描规则在 {finding.file_path}:{finding.line_start} 找到了对应调用或数据特征；这是一条需复核的安全发现，不等同于直接判定软件恶意。
            </div>
          </div>
          {finding.remediation && (
            <div style={{ marginBottom: '12px', background: 'rgba(15, 23, 42, 0.6)', padding: '10px 14px', borderRadius: '6px', fontSize: '13px' }}>
              <strong style={{ color: '#34d399' }}>💡 修复与审查建议:</strong> {finding.remediation}
            </div>
          )}

          <div style={{ fontSize: '13px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
            代码证据与调用特征 ({finding.evidences.length})
          </div>

          {finding.evidences.map((ev) => (
            <div
              key={ev.id}
              style={{
                background: '#0a0e17',
                border: '1px solid #1e293b',
                borderRadius: '6px',
                padding: '10px 14px',
                marginTop: '6px',
                fontFamily: 'monospace',
                fontSize: '12px',
              }}
            >
              <div style={{ color: '#64748b', fontSize: '11px', marginBottom: '4px' }}>
                规则: {ev.source} | 位置: {ev.location}
              </div>
              <pre style={{ color: '#f1f5f9', whiteSpace: 'pre-wrap', margin: 0 }}>
                {ev.excerpt_redacted}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
