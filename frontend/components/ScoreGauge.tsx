'use client';

import React from 'react';
import { RiskLevel } from '../lib/types';

interface ScoreGaugeProps {
  score: number;
  riskLevel: RiskLevel;
  confidence?: number;
  coverage?: number;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, riskLevel, confidence, coverage }) => {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let strokeColor = '#10b981'; // safe
  let glowColor = 'rgba(16, 185, 129, 0.3)';
  let label = '安全 (低观测风险)';

  if (score < 40) {
    strokeColor = '#ef4444';
    glowColor = 'rgba(239, 68, 68, 0.4)';
    label = '高风险 (默认阻止)';
  } else if (score < 70) {
    strokeColor = '#f59e0b';
    glowColor = 'rgba(245, 158, 11, 0.4)';
    label = '中风险 (需人工复核)';
  } else if (score < 90) {
    strokeColor = '#3b82f6';
    glowColor = 'rgba(59, 130, 246, 0.4)';
    label = '低风险 (受限环境)';
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
      <div style={{ position: 'relative', width: '150px', height: '150px' }}>
        <svg width="150" height="150" viewBox="0 0 140 140" style={{ transform: 'rotate(-90deg)' }}>
          {/* 背景圆环 */}
          <circle
            cx="70"
            cy="70"
            r={radius}
            stroke="#1e293b"
            strokeWidth="10"
            fill="transparent"
          />
          {/* 进度圆环 */}
          <circle
            cx="70"
            cy="70"
            r={radius}
            stroke={strokeColor}
            strokeWidth="10"
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 1s ease-out, stroke 0.5s ease',
              filter: `drop-shadow(0 0 8px ${glowColor})`,
            }}
          />
        </svg>
        <div
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
          }}
        >
          <span style={{ fontSize: '36px', fontWeight: 800, color: strokeColor, lineHeight: 1 }}>{score}</span>
          <span style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', marginTop: '4px', letterSpacing: '1px' }}>
            SAFETY SCORE
          </span>
        </div>
      </div>
      <div style={{ marginTop: '12px', fontWeight: 700, fontSize: '16px', color: strokeColor }}>
        {label}
      </div>
      {(confidence !== undefined || coverage !== undefined) && (
        <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontSize: '12px', color: '#64748b' }}>
          {confidence !== undefined && <span>置信度: {Math.round(confidence * 100)}%</span>}
          {coverage !== undefined && <span>覆盖率: {Math.round(coverage * 100)}%</span>}
        </div>
      )}
    </div>
  );
};
