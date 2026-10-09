import React, { useEffect, useState } from 'react';
import { fetchDashboardSummary } from '../services/api';
import {
  ShieldAlert,
  ShieldCheck,
  Server,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  ExternalLink
} from 'lucide-react';

export default function DashboardView({ onSelectAudit, onStartAudit }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadSummary = async () => {
    setLoading(true);
    setError(null);
    try {
      const summary = await fetchDashboardSummary();
      setData(summary);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSummary();
  }, []);

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '80px 20px' }}>
        <RefreshCw size={36} className="animate-spin" color="var(--cyan-accent)" style={{ margin: '0 auto 16px' }} />
        <h3 style={{ fontWeight: 600 }}>Loading Security Posture Intelligence...</h3>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card" style={{ borderColor: 'var(--rose-fail)', textAlign: 'center', padding: '40px' }}>
        <AlertTriangle size={40} color="var(--rose-fail)" style={{ margin: '0 auto 16px' }} />
        <h3>Error Connecting to Backend</h3>
        <p style={{ color: 'var(--text-muted)', margin: '8px 0 20px' }}>{error}</p>
        <button className="btn" onClick={loadSummary}>
          <RefreshCw size={16} /> Retry
        </button>
      </div>
    );
  }

  const {
    total_audits = 0,
    compliant_devices = 0,
    non_compliant_devices = 0,
    high_risk_devices = 0,
    critical_findings = 0,
    risk_distribution = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    vendor_distribution = {},
    recent_audits = []
  } = data || {};

  const complianceRate = total_audits > 0 ? Math.round((compliant_devices / total_audits) * 100) : 0;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '1.8rem', fontWeight: 800 }}>Fleet Compliance & Risk Overview</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem' }}>
            Continuous multi-vendor network device auditing via deterministic CIS controls and ML risk models.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button className="btn btn-secondary" onClick={loadSummary}>
            <RefreshCw size={16} /> Refresh
          </button>
          <button className="btn" onClick={onStartAudit}>
            New Device Audit <ArrowRight size={16} />
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid-kpi">
        <div className="kpi-box">
          <div className="kpi-title">
            <span>Total Devices Audited</span>
            <Server size={18} color="var(--cyan-accent)" />
          </div>
          <div className="kpi-number">{total_audits}</div>
          <div className="kpi-subtext">Cisco, Fortinet & Palo Alto</div>
        </div>

        <div className="kpi-box">
          <div className="kpi-title">
            <span>Compliant Fleet Ratio</span>
            <ShieldCheck size={18} color="var(--emerald-pass)" />
          </div>
          <div className="kpi-number" style={{ color: complianceRate >= 70 ? 'var(--emerald-pass)' : 'var(--amber-warn)' }}>
            {complianceRate}%
          </div>
          <div className="kpi-subtext">{compliant_devices} Compliant / {non_compliant_devices} Non-Compliant</div>
        </div>

        <div className="kpi-box">
          <div className="kpi-title">
            <span>High / Critical Risk Nodes</span>
            <ShieldAlert size={18} color="var(--rose-fail)" />
          </div>
          <div className="kpi-number" style={{ color: high_risk_devices > 0 ? 'var(--rose-fail)' : 'var(--emerald-pass)' }}>
            {high_risk_devices}
          </div>
          <div className="kpi-subtext">Requires immediate remediation</div>
        </div>

        <div className="kpi-box">
          <div className="kpi-title">
            <span>Critical CIS Violations</span>
            <AlertTriangle size={18} color="#f87171" />
          </div>
          <div className="kpi-number" style={{ color: critical_findings > 0 ? '#f87171' : 'var(--emerald-pass)' }}>
            {critical_findings}
          </div>
          <div className="kpi-subtext">Active perimeter/management exposures</div>
        </div>
      </div>

      {/* Breakdown Row: Risk Distribution & Vendor Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px', marginBottom: '28px' }}>
        <div className="card">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '16px' }}>Risk Tier Distribution</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((tier) => {
              const count = risk_distribution[tier] || 0;
              const pct = total_audits > 0 ? Math.round((count / total_audits) * 100) : 0;
              const colors = {
                CRITICAL: 'var(--rose-fail)',
                HIGH: '#fb923c',
                MEDIUM: 'var(--amber-warn)',
                LOW: 'var(--emerald-pass)'
              };

              return (
                <div key={tier}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '4px' }}>
                    <span className={`badge badge-${tier}`}>{tier}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{count} nodes ({pct}%)</span>
                  </div>
                  <div style={{ background: 'rgba(255, 255, 255, 0.06)', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, background: colors[tier], height: '100%', borderRadius: '4px', transition: 'width 0.5s ease' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '16px' }}>Supported Vendor Footprint</h3>
          {Object.keys(vendor_distribution).length === 0 ? (
            <p style={{ color: 'var(--text-dim)', fontSize: '0.9rem' }}>No configurations audited yet.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {Object.entries(vendor_distribution).map(([v, count]) => {
                const pct = total_audits > 0 ? Math.round((count / total_audits) * 100) : 0;
                return (
                  <div key={v}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem', marginBottom: '4px' }}>
                      <strong style={{ color: 'var(--text-main)' }}>{v}</strong>
                      <span style={{ color: 'var(--text-muted)' }}>{count} devices ({pct}%)</span>
                    </div>
                    <div style={{ background: 'rgba(255, 255, 255, 0.06)', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, background: 'var(--cyan-accent)', height: '100%', borderRadius: '4px' }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Recent Audits Table */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Recent Audits</h3>
          {recent_audits.length > 0 && (
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Showing latest {recent_audits.length} audits</span>
          )}
        </div>

        {recent_audits.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
            <Server size={32} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
            <p>No audits conducted yet. Upload your first configuration file to generate findings.</p>
            <button className="btn" style={{ marginTop: '16px' }} onClick={onStartAudit}>
              Upload Configuration
            </button>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Audit ID</th>
                  <th>Device / Hostname</th>
                  <th>Vendor</th>
                  <th>Compliance Score</th>
                  <th>Risk Tier</th>
                  <th>Critical Violations</th>
                  <th>Timestamp</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recent_audits.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <code style={{ color: 'var(--cyan-accent)', fontSize: '0.85rem' }}>{a.id}</code>
                    </td>
                    <td>
                      <strong>{a.hostname}</strong>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>{a.filename}</div>
                    </td>
                    <td>
                      <span style={{ fontWeight: 600 }}>{a.vendor}</span>
                    </td>
                    <td>
                      <strong style={{ color: a.compliance_score >= 80 ? 'var(--emerald-pass)' : a.compliance_score >= 50 ? 'var(--amber-warn)' : 'var(--rose-fail)' }}>
                        {a.compliance_score}%
                      </strong>
                    </td>
                    <td>
                      <span className={`badge badge-${a.final_risk_level}`}>
                        {a.final_risk_level} ({a.composite_risk_score})
                      </span>
                    </td>
                    <td>
                      {a.critical_violations > 0 ? (
                        <span style={{ color: 'var(--rose-fail)', fontWeight: 700 }}>{a.critical_violations} Critical</span>
                      ) : (
                        <span style={{ color: 'var(--emerald-pass)' }}>0</span>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                        onClick={() => onSelectAudit(a.id)}
                      >
                        Inspect <ExternalLink size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
