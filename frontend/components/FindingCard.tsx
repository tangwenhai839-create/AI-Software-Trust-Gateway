'use client';

import React, { useState } from 'react';
import { Finding } from '../lib/types';
import { ChevronDown, ChevronUp, ShieldAlert, FileCode, CheckCircle } from 'lucide-react';

interface FindingCardProps {
  finding: Finding;
  index: number;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, index }) => {
  const [expanded, setExpanded] = useState(false);

  const sev = finding.severity.toLowerCase();
  const badgeClass = `badge badge-${sev}`;

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
