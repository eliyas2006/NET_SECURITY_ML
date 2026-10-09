import React from 'react';
import { Shield, LayoutDashboard, UploadCloud, History, FileCode2 } from 'lucide-react';

export default function Navbar({ currentView, setCurrentView }) {
  return (
    <nav className="navbar">
      <div className="brand" onClick={() => setCurrentView('dashboard')} style={{ cursor: 'pointer' }}>
        <div className="brand-icon">
          <Shield size={20} color="#fff" />
        </div>
        <div>
          <span>NETSEC AUDITOR</span>
          <span style={{ fontSize: '0.7rem', display: 'block', color: 'var(--cyan-accent)', fontWeight: 600 }}>
            AI Multi-Vendor Compliance
          </span>
        </div>
      </div>

      <div className="nav-links">
        <button
          className={`nav-btn ${currentView === 'dashboard' ? 'active' : ''}`}
          onClick={() => setCurrentView('dashboard')}
        >
          <LayoutDashboard size={17} />
          Dashboard
        </button>

        <button
          className={`nav-btn ${currentView === 'upload' ? 'active' : ''}`}
          onClick={() => setCurrentView('upload')}
        >
          <UploadCloud size={17} />
          Upload & Audit
        </button>

        <button
          className={`nav-btn ${currentView === 'history' ? 'active' : ''}`}
          onClick={() => setCurrentView('history')}
        >
          <History size={17} />
          Audit History
        </button>

        <a
          href="/docs"
          target="_blank"
          rel="noreferrer"
          className="nav-btn"
          style={{ textDecoration: 'none', marginLeft: '8px' }}
        >
          <FileCode2 size={17} />
          API Docs
        </a>
      </div>
    </nav>
  );
}
