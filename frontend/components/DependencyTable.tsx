'use client';

import React from 'react';
import { Dependency } from '../lib/types';
import { ShieldCheck, ShieldAlert, ExternalLink } from 'lucide-react';

interface DependencyTableProps {
  dependencies: Dependency[];
}

const severityText: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危/待确认',
};

const explainVulnerabilityImpact = (summary: string, details: string) => {
  const text = `${summary} ${details}`.toLowerCase();
  if (text.includes('buffer overflow') || text.includes('memory corruption')) return '可能造成程序崩溃、内存破坏，特定条件下可能被用于执行攻击代码。';
  if (text.includes('remote code execution') || text.includes('arbitrary code')) return '攻击者可能在运行该依赖的计算机上执行任意代码。';
  if (text.includes('path traversal')) return '攻击者可能越过预期目录，读取或写入不应访问的文件。';
  if (text.includes('denial of service') || text.includes('dos')) return '恶意输入可能让程序耗尽资源、崩溃或停止提供服务。';
  if (text.includes('cross-site scripting') || text.includes('xss')) return '攻击者可能在用户浏览器中执行脚本并窃取会话或篡改页面。';
  if (text.includes('sql injection')) return '攻击者可能操纵数据库查询，读取、篡改或删除数据。';
  if (text.includes('information disclosure') || text.includes('leak')) return '漏洞可能泄露程序内存、用户数据、凭据或其他敏感信息。';
  return 'OSV 确认当前声明版本处于该漏洞的受影响范围；实际风险取决于项目是否调用了对应的易受攻击功能。';
};

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
                <td style={{ padding: '10px', color: '#f8fafc', fontWeight: 600, fontFamily: 'monospace', verticalAlign: 'top' }}>
                  {dep.name}
                </td>
                <td style={{ padding: '10px', color: '#94a3b8', fontFamily: 'monospace', verticalAlign: 'top' }}>
                  {dep.version}
                </td>
                <td style={{ padding: '10px', color: '#94a3b8', verticalAlign: 'top' }}>
                  <span style={{ background: '#1e293b', padding: '2px 6px', borderRadius: '4px', fontSize: '11px' }}>
                    {dep.ecosystem}
                  </span>
                </td>
                <td style={{ padding: '10px', color: dep.scope === 'direct' ? '#38bdf8' : '#94a3b8', verticalAlign: 'top' }}>
                  {dep.scope === 'direct' ? '直接依赖' : dep.scope === 'indirect' ? '间接依赖' : '未锁定'}
                </td>
                <td style={{ padding: '10px', verticalAlign: 'top', minWidth: '420px' }}>
                  {hasVulns ? (
                    <div>
                      <div style={{ color: '#fca5a5', fontSize: '12px', marginBottom: '8px' }}>
                        检测到 {dep.vulnerabilities.length} 个去重后的已知漏洞，点击每项查看风险原因和修复版本。
                      </div>
                      {dep.vulnerabilities.map((v) => (
                        <details key={v.id} style={{ marginBottom: '8px', background: 'rgba(239, 68, 68, 0.06)', border: '1px solid rgba(239, 68, 68, 0.18)', borderRadius: '6px', padding: '8px 10px' }}>
                          <summary style={{ color: '#f87171', fontWeight: 600, cursor: 'pointer', lineHeight: 1.5 }}>
                            <ShieldAlert size={14} style={{ display: 'inline', marginRight: '5px', verticalAlign: '-2px' }} />
                            [{severityText[v.severity] || v.severity}] {v.advisory_id} — {v.summary || 'OSV 已确认该版本受影响'}
                          </summary>
                          <div style={{ marginTop: '8px', color: '#cbd5e1', fontSize: '12px', lineHeight: 1.65 }}>
                            <div><strong style={{ color: '#fca5a5' }}>为什么报出：</strong>项目声明使用 {dep.name} {dep.version}，OSV 将该版本列入此漏洞的受影响版本。</div>
                            <div><strong style={{ color: '#fca5a5' }}>为什么有风险：</strong>{explainVulnerabilityImpact(v.summary || '', v.details || '')}</div>
                            {v.details && <div><strong>漏洞说明：</strong>{v.details}</div>}
                            <div><strong>严重度：</strong>{severityText[v.severity] || v.severity}{v.cvss_score != null ? `（CVSS ${v.cvss_score}/10）` : '（OSV 未提供可计算的 CVSS 分数）'}</div>
                            <div><strong>修复建议：</strong>{v.fixed_versions?.length ? `升级到 ${Array.from(new Set(v.fixed_versions)).join('、')} 或更高安全版本。` : '打开官方公告确认已修复版本，并优先升级到当前维护分支的最新版。'}</div>
                            {v.aliases?.length > 0 && <div><strong>关联编号：</strong>{v.aliases.join('、')}</div>}
                            <a href={v.source_url} target="_blank" rel="noreferrer" style={{ color: '#38bdf8', display: 'inline-flex', alignItems: 'center', gap: '4px', marginTop: '4px' }}>
                              查看官方漏洞公告 <ExternalLink size={12} />
                            </a>
                          </div>
                        </details>
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
