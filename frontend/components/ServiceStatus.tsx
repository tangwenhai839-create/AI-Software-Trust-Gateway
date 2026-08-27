'use client';

import React, { useEffect, useState } from 'react';
import { getHealth } from '../lib/api';

export function ServiceStatus() {
  const [ready, setReady] = useState<boolean | null>(null);

  useEffect(() => {
    let active = true;
    const check = () => getHealth().then(() => active && setReady(true)).catch(() => active && setReady(false));
    check();
    const timer = setInterval(check, 10000);
    return () => { active = false; clearInterval(timer); };
  }, []);

  const color = ready === true ? '#34d399' : ready === false ? '#f87171' : '#94a3b8';
  const background = ready === true ? 'rgba(16, 185, 129, 0.1)' : ready === false ? 'rgba(239, 68, 68, 0.1)' : 'rgba(100, 116, 139, 0.1)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color, background, padding: '4px 10px', borderRadius: '20px', border: `1px solid ${color}44` }}>
      <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: color }} />
      <span>{ready === true ? '本地服务已就绪' : ready === false ? '本地服务未连接' : '正在检查本地服务'}</span>
    </div>
  );
}
