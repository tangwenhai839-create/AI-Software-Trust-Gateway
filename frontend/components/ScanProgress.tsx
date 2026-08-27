'use client';

import React from 'react';
import { ScanStage, ScanStatus } from '../lib/types';
import { CheckCircle2, CircleDashed, AlertTriangle, XCircle } from 'lucide-react';

interface ScanProgressProps {
  status: ScanStatus;
  stage: ScanStage;
  progressPct: number;
}

const STAGES: { id: ScanStage; label: string }[] = [
  { id: 'ingestion', label: '1. 安全获取' },
  { id: 'static_analysis', label: '2. 静态分析' },
  { id: 'dependency_analysis', label: '3. 依赖与漏洞' },
  { id: 'ai_reasoning', label: '4. 用途与 AI 推理' },
  { id: 'scoring', label: '5. 确定性评分' },
  { id: 'report_generation', label: '6. 报告生成' },
];

export const ScanProgress: React.FC<ScanProgressProps> = ({ status, stage, progressPct }) => {
  const currentStageIndex = STAGES.findIndex((s) => s.id === stage);

  return (
    <div style={{ width: '100%' }}>
      {/* 进度条 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <span style={{ fontSize: '13px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          任务进度: {status.toUpperCase()}
        </span>
        <span style={{ fontSize: '14px', fontWeight: 700, color: '#38bdf8' }}>{progressPct}%</span>
      </div>
      <div style={{ width: '100%', height: '6px', background: '#1e293b', borderRadius: '3px', overflow: 'hidden', marginBottom: '18px' }}>
        <div
          style={{
            width: `${progressPct}%`,
            height: '100%',
            background: 'linear-gradient(90deg, #0284c7 0%, #38bdf8 100%)',
            transition: 'width 0.4s ease',
          }}
        />
      </div>

      {/* 阶段步骤指示器 */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '8px' }}>
        {STAGES.map((st, idx) => {
          let isDone = status === 'completed' || idx < currentStageIndex;
          let isCurrent = idx === currentStageIndex && status !== 'completed' && status !== 'failed';
          let isFailed = status === 'failed' && idx === currentStageIndex;

          return (
            <div
              key={st.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 10px',
                borderRadius: '6px',
                background: isCurrent ? 'rgba(56, 189, 248, 0.1)' : 'rgba(15, 23, 42, 0.6)',
                border: `1px solid ${isCurrent ? '#0284c7' : isDone ? '#1e293b' : '#1e293b'}`,
                fontSize: '12px',
                color: isDone ? '#10b981' : isCurrent ? '#38bdf8' : isFailed ? '#ef4444' : '#64748b',
                fontWeight: isCurrent ? 600 : 400,
              }}
            >
              {isDone && <CheckCircle2 size={14} color="#10b981" />}
              {isCurrent && <CircleDashed size={14} className="pulsing" color="#38bdf8" />}
              {isFailed && <XCircle size={14} color="#ef4444" />}
              {!isDone && !isCurrent && !isFailed && <CircleDashed size={14} color="#475569" />}
              <span>{st.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
