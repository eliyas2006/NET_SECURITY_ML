import React, { useEffect, useState } from 'react';
import { fetchAuditsList, deleteAuditRecord } from '../services/api';
import {
  History,
  Trash2,
  ExternalLink,
  Search,
  Printer,
  RefreshCw,
  AlertTriangle
} from 'lucide-react';

export default function HistoryView({ onSelectAudit }) {
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');

  const loadAudits = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAuditsList(100);
      setAudits(data);
    } catch (err) {
      setError(err.message || 'Failed to fetch audit history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAudits();
  }, []);

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm(`Are you sure you want to delete audit record ${id}?`)) return;

    try {
      await deleteAuditRecord(id);
      setAudits((prev) => prev.filter((a) => a.id !== id));
    } catch (err) {
      alert(`Error deleting audit: ${err.message}`);
    }
  };

  const filtered = audits.filter((a) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      a.id.toLowerCase().includes(q) ||
      a.hostname.toLowerCase().includes(q) ||
      a.filename.toLowerCase().includes(q) ||
      a.vendor.toLowerCase().includes(q)
    );
  });

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '1.8rem', fontWeight: 800 }}>Audit History & Archive</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem' }}>
            Historical record of all evaluated network configurations, risk trends, and compliance scores.
          </p>
        </div>
        <button className="btn btn-secondary" onClick={loadAudits}>
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      <div className="card">
        {/* Search Bar */}
        <div style={{ position: 'relative', marginBottom: '20px' }}>
          <Search size={16} color="var(--text-dim)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
          <input
            type="text"
            placeholder="Search audit archive by ID, hostname, vendor, or filename..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: '100%',
              background: '#090e1a',
              color: 'var(--text-main)',
              border: '1px solid var(--border-strong)',
              borderRadius: '6px',
              padding: '10px 12px 10px 36px',
              fontSize: '0.85rem',
              outline: 'none',
            }}
          />
        </div>

        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px' }}>
            <RefreshCw size={28} className="animate-spin" color="var(--cyan-accent)" style={{ margin: '0 auto 12px' }} />
            <p>Loading historical records...</p>
          </div>
        ) : error ? (
          <div style={{ textAlign: 'center', padding: '30px', color: 'var(--rose-fail)' }}>
            <AlertTriangle size={32} style={{ margin: '0 auto 8px' }} />
            <p>{error}</p>
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
            <History size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
            <p>No audit records found.</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Audit Reference</th>
                  <th>Device Hostname</th>
                  <th>Vendor</th>
                  <th>Compliance</th>
                  <th>Risk Tier</th>
                  <th>Critical / High</th>
                  <th>Timestamp</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => (
                  <tr key={a.id} style={{ cursor: 'pointer' }} onClick={() => onSelectAudit(a.id)}>
                    <td>
                      <code style={{ color: 'var(--cyan-accent)' }}>{a.id}</code>
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
                      <span style={{ color: a.critical_violations > 0 ? 'var(--rose-fail)' : 'inherit', fontWeight: a.critical_violations > 0 ? 700 : 400 }}>
                        {a.critical_violations} C / {a.high_violations} H
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '8px' }} onClick={(e) => e.stopPropagation()}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                          title="Inspect Audit"
                          onClick={() => onSelectAudit(a.id)}
                        >
                          <ExternalLink size={14} />
                        </button>
                        <a
                          href={`/api/audits/${a.id}/report`}
                          target="_blank"
                          rel="noreferrer"
                          className="btn btn-secondary"
                          style={{ padding: '4px 8px', fontSize: '0.75rem', textDecoration: 'none' }}
                          title="Print Executive Report"
                        >
                          <Printer size={14} />
                        </a>
                        <button
                          className="btn btn-danger"
                          style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                          title="Delete Audit"
                          onClick={(e) => handleDelete(a.id, e)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
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
