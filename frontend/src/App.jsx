import React, { useState } from 'react';
import Navbar from './components/Navbar';
import DashboardView from './components/DashboardView';
import UploadAuditView from './components/UploadAuditView';
import AuditDetailView from './components/AuditDetailView';
import HistoryView from './components/HistoryView';

export default function App() {
  const [currentView, setCurrentView] = useState('dashboard'); // 'dashboard', 'upload', 'detail', 'history'
  const [selectedAuditId, setSelectedAuditId] = useState(null);

  const handleSelectAudit = (id) => {
    setSelectedAuditId(id);
    setCurrentView('detail');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleAuditCompleted = (newAuditId) => {
    setSelectedAuditId(newAuditId);
    setCurrentView('detail');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="app-container">
      <Navbar currentView={currentView} setCurrentView={setCurrentView} />

      <main className="content-area">
        {currentView === 'dashboard' && (
          <DashboardView
            onSelectAudit={handleSelectAudit}
            onStartAudit={() => setCurrentView('upload')}
          />
        )}

        {currentView === 'upload' && (
          <UploadAuditView onAuditCompleted={handleAuditCompleted} />
        )}

        {currentView === 'detail' && (
          <AuditDetailView
            auditId={selectedAuditId}
            onBack={() => setCurrentView('dashboard')}
          />
        )}

        {currentView === 'history' && (
          <HistoryView onSelectAudit={handleSelectAudit} />
        )}
      </main>

      <footer style={{ borderTop: '1px solid var(--border-subtle)', padding: '20px 24px', textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-dim)', background: '#090d16' }}>
        AI-Driven Multi-Vendor Network Security Compliance Auditor &copy; 2026 &bull; Cisco IOS &bull; Fortinet FortiOS &bull; Palo Alto PAN-OS &bull; CIS Controls &bull; NIST 800-53
      </footer>
    </div>
  );
}
