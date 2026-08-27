import './globals.css';
import React from 'react';
import { Shield, Terminal, Cpu } from 'lucide-react';
import { ServiceStatus } from '../components/ServiceStatus';

export const metadata = {
  title: 'AI Software Trust Gateway (ASTG)',
  description: '本地开源 AI 软件可信安全网关 - 面向代码与 AI 插件的前置可信安全审查',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-CN">
      <body>
        {/* 顶部导航栏 */}
        <header
          style={{
            borderBottom: '1px solid rgba(56, 189, 248, 0.15)',
            background: 'rgba(10, 14, 23, 0.8)',
            backdropFilter: 'blur(10px)',
            position: 'sticky',
            top: 0,
            zIndex: 50,
          }}
        >
          <div
            className="container"
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              paddingTop: '16px',
              paddingBottom: '16px',
            }}
          >
            <a href="/" style={{ display: 'flex', alignItems: 'center', gap: '12px', color: '#f8fafc' }}>
              <div
                style={{
                  background: 'linear-gradient(135deg, #0284c7 0%, #2563eb 100%)',
                  padding: '8px',
                  borderRadius: '10px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 12px rgba(56, 189, 248, 0.4)',
                }}
              >
                <Shield size={22} color="#ffffff" />
              </div>
              <div>
                <div style={{ fontWeight: 800, fontSize: '18px', letterSpacing: '0.5px' }}>
                  AI Software Trust Gateway
                </div>
                <div style={{ fontSize: '11px', color: '#94a3b8' }}>本地开源 • AI 软件可信网关 v1.0</div>
              </div>
            </a>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <ServiceStatus />
            </div>
          </div>
        </header>

        {/* 页面主内容 */}
        <main>{children}</main>
      </body>
    </html>
  );
}
