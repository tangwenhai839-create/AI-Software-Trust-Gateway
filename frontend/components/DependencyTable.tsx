'use client';

import React from 'react';
import { Dependency } from '../lib/types';
import { ShieldCheck, ShieldAlert, ExternalLink } from 'lucide-react';

interface DependencyTableProps {
  dependencies: Dependency[];
}

export const DependencyTable: React.FC<DependencyTableProps> = ({ dependencies }) => {
  if (!dependencies || dependencies.length === 0) {
    return (
      <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', background: 'rgba(15, 23, 42, 0.4)', borderRadius: '8px' }}>
        未检测到依赖清单文件 (或项目为零第三方依赖)。
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #1e293b', color: '#94a3b8' }}>
            <th style={{ padding: '10px' }}>依赖包名</th>
            <th style={{ padding: '10px' }}>声明版本</th>
            <th style={{ padding: '10px' }}>生态系统</th>
            <th style={{ padding: '10px' }}>作用域</th>
            <th style={{ padding: '10px' }}>已知漏洞 (OSV)</th>
          </tr>
        </thead>
        <tbody>
          {dependencies.map((dep) => {
            const hasVulns = dep.vulnerabilities && dep.vulnerabilities.length > 0;

            return (
              <tr key={dep.id} style={{ borderBottom: '1px solid #1e293b' }}>
                <td style={{ padding: '10px', color: '#f8fafc', fontWeight: 600, fontFamily: 'monospace' }}>
                  {dep.name}
                </td>
                <td style={{ padding: '10px', color: '#94a3b8', fontFamily: 'monospace' }}>
                  {dep.version}
                </td>
                <td style={{ padding: '10px', color: '#94a3b8' }}>
                  <span style={{ background: '#1e293b', padding: '2px 6px', borderRadius: '4px', fontSize: '11px' }}>
                    {dep.ecosystem}
                  </span>
                </td>
                <td style={{ padding: '10px', color: dep.scope === 'direct' ? '#38bdf8' : '#94a3b8' }}>
                  {dep.scope === 'direct' ? '直接依赖' : dep.scope === 'indirect' ? '间接依赖' : '未锁定'}
                </td>
                <td style={{ padding: '10px' }}>
                  {hasVulns ? (
                    <div>
                      {dep.vulnerabilities.map((v) => (
                        <div key={v.id} style={{ marginBottom: '4px' }}>
                          <a
                            href={v.source_url}
                            target="_blank"
                            rel="noreferrer"
                            style={{
                              color: '#ef4444',
                              fontWeight: 600,
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                            }}
                          >
                            <ShieldAlert size={14} />
                            {v.advisory_id}
                            <ExternalLink size={12} />
                          </a>
                          <div style={{ fontSize: '11px', color: '#94a3b8' }}>{v.summary}</div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span style={{ color: '#10b981', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <ShieldCheck size={14} /> 无已知漏洞
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
