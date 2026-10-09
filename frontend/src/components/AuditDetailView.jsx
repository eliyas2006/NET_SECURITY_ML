import React, { useEffect, useState, useMemo } from 'react';
import { fetchAuditDetail, fetchAuditRemediation, getRemediationDownloadUrl } from '../services/api';
import {
  ShieldCheck,
  AlertTriangle,
  AlertCircle,
  Printer,
  ArrowLeft,
  Copy,
  Check,
  Search,
  Info,
  Activity,
  Cpu,
  RefreshCw,
  Download,
  Terminal,
  FileCode,
  ChevronDown,
  ChevronUp,
  X
} from 'lucide-react';

export default function AuditDetailView({ auditId, onBack }) {
  const [audit, setAudit] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Remediation Plan State
  const [remediationPlan, setRemediationPlan] = useState(null);
  const [loadingRemediation, setLoadingRemediation] = useState(false);
  const [showScriptModal, setShowScriptModal] = useState(false);
  const [expandedRemediations, setExpandedRemediations] = useState({});

  // Findings Filters
  const [statusFilter, setStatusFilter] = useState('ALL'); // ALL, FAIL, WARN, PASS
  const [severityFilter, setSeverityFilter] = useState('ALL'); // ALL, CRITICAL, HIGH, MEDIUM, LOW
  const [searchQuery, setSearchQuery] = useState('');

  const [copiedCliId, setCopiedCliId] = useState(null);
  const [copiedFullScript, setCopiedFullScript] = useState(false);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchAuditDetail(auditId);
        setAudit(data);

        // Fetch remediation plan concurrently
        setLoadingRemediation(true);
        try {
          const plan = await fetchAuditRemediation(auditId);
          setRemediationPlan(plan);
        } catch (rErr) {
          console.warn('Remediation plan fetch error:', rErr);
        } finally {
          setLoadingRemediation(false);
        }
      } catch (err) {
        setError(err.message || 'Failed to load audit record.');
      } finally {
        setLoading(false);
      }
    }
    if (auditId) {
      loadData();
    }
  }, [auditId]);

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedCliId(id);
    setTimeout(() => setCopiedCliId(null), 2000);
  };

  const copyFullScriptToClipboard = () => {
    if (remediationPlan?.full_script) {
      navigator.clipboard.writeText(remediationPlan.full_script);
      setCopiedFullScript(true);
      setTimeout(() => setCopiedFullScript(false), 2000);
    }
  };

  const toggleRemediationExpand = (controlId) => {
    setExpandedRemediations((prev) => ({
      ...prev,
      [controlId]: !prev[controlId]
    }));
  };

  // Map remediation actions by control_id for rapid O(1) lookup
  const remediationMap = useMemo(() => {
    if (!remediationPlan?.actions) return {};
    const map = {};
    for (const act of remediationPlan.actions) {
      map[act.control_id] = act;
    }
    return map;
  }, [remediationPlan]);

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '80px 20px' }}>
        <RefreshCw size={36} className="animate-spin" color="var(--cyan-accent)" style={{ margin: '0 auto 16px' }} />
        <h3>Retrieving Audit Findings & Intelligence...</h3>
      </div>
    );
  }

  if (error || !audit) {
    return (
      <div className="card" style={{ borderColor: 'var(--rose-fail)', textAlign: 'center', padding: '40px' }}>
        <AlertTriangle size={40} color="var(--rose-fail)" style={{ margin: '0 auto 16px' }} />
        <h3>Audit Not Found</h3>
        <p style={{ color: 'var(--text-muted)', margin: '8px 0 20px' }}>{error || 'Unable to locate requested audit record.'}</p>
        <button className="btn" onClick={onBack}>
          <ArrowLeft size={16} /> Return to Audits
        </button>
      </div>
    );
  }

  const {
    id,
    filename,
    vendor,
    vendor_confidence,
    device_type,
    hostname,
    raw_lines_count,
    compliance_score,
    final_risk_level,
    composite_risk_score,
    created_at,
    compliance_summary,
    risk_assessment,
    ml_result,
    findings = []
  } = audit;

  // Filter findings
  const filteredFindings = findings.filter((f) => {
    if (statusFilter !== 'ALL' && f.status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = f.control_id.toLowerCase().includes(q);
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchEvidence = f.evidence.toLowerCase().includes(q);
      if (!matchId && !matchTitle && !matchEvidence) return false;
    }
    return true;
  });

  const getSafetyBadgeStyle = (safety) => {
    switch (safety) {
      case 'SAFE_AUTOMATIC':
        return { background: 'rgba(16, 185, 129, 0.15)', color: 'var(--emerald-pass)', border: '1px solid rgba(16, 185, 129, 0.3)' };
      case 'REVIEW_REQUIRED':
        return { background: 'rgba(245, 158, 11, 0.15)', color: 'var(--amber-warn)', border: '1px solid rgba(245, 158, 11, 0.3)' };
      case 'MANUAL_ONLY':
        return { background: 'rgba(239, 68, 68, 0.15)', color: 'var(--rose-fail)', border: '1px solid rgba(239, 68, 68, 0.3)' };
      default:
        return { background: 'rgba(148, 163, 184, 0.15)', color: 'var(--text-muted)', border: '1px solid var(--border-subtle)' };
    }
  };

  return (
    <div>
      {/* Top Navigation & Action Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '12px' }}>
        <button className="btn btn-secondary" onClick={onBack}>
          <ArrowLeft size={16} /> Back to Dashboard
        </button>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          {remediationPlan && remediationPlan.remediated_controls_count > 0 && (
            <>
              <button
                className="btn btn-secondary"
                onClick={() => setShowScriptModal(true)}
                disabled={loadingRemediation}
                style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                <Terminal size={16} color="var(--cyan-accent)" />
                View Full Remediation Script
              </button>
              <a
                href={getRemediationDownloadUrl(id)}
                download
                className="btn"
                style={{
                  textDecoration: 'none',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: 'linear-gradient(135deg, var(--cyan-accent), var(--blue-accent))',
                  color: '#fff',
                  fontWeight: 600
                }}
              >
                <Download size={16} />
                Download Remediation ({remediationPlan.file_extension})
              </a>
            </>
          )}
          <a
            href={`/api/audits/${id}/report`}
            target="_blank"
            rel="noreferrer"
            className="btn btn-secondary"
            style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '8px' }}
          >
            <Printer size={16} /> View / Download HTML Report
          </a>
        </div>
      </div>

      {/* Header Banner */}
      <div className="card" style={{ marginBottom: '24px', background: 'linear-gradient(180deg, #111a2e 0%, var(--bg-card) 100%)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
              <h1 style={{ fontSize: '1.8rem', fontWeight: 800 }}>{hostname}</h1>
              <span className={`badge badge-${final_risk_level}`} style={{ fontSize: '0.85rem', padding: '6px 14px' }}>
                {final_risk_level} RISK ({composite_risk_score}/100)
              </span>
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
              Vendor: <strong style={{ color: '#fff' }}>{vendor}</strong> ({device_type}, {(vendor_confidence * 100).toFixed(0)}% detection confidence) | File: <strong style={{ color: '#fff' }}>{filename}</strong> ({raw_lines_count} lines)
              <br />
              Audit Reference ID: <code>{id}</code> | Timestamp: {new Date(created_at).toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      {/* Remediation Overview Banner (Stage 3A) */}
      {remediationPlan && remediationPlan.remediated_controls_count > 0 && (
        <div
          className="card"
          style={{
            marginBottom: '24px',
            background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.08) 0%, rgba(59, 130, 246, 0.04) 100%)',
            border: '1px solid rgba(6, 182, 212, 0.3)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
            <div style={{ flex: 1, minWidth: '280px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                <Terminal size={20} color="var(--cyan-accent)" />
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#fff' }}>
                  Automated Remediation Engine Ready ({remediationPlan.vendor} CLI)
                </h3>
              </div>
              <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', marginBottom: '12px', lineHeight: 1.5 }}>
                The engine has synthesized deterministic remediation actions for {remediationPlan.remediated_controls_count} security control(s).
                All commands are tailored for {remediationPlan.vendor} syntax and ready for export as <code>{remediationPlan.file_extension}</code>.
              </p>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <span className="badge" style={getSafetyBadgeStyle('SAFE_AUTOMATIC')}>
                  {remediationPlan.safe_automatic_count} Safe Automatic
                </span>
                <span className="badge" style={getSafetyBadgeStyle('REVIEW_REQUIRED')}>
                  {remediationPlan.review_required_count} Review Required
                </span>
                <span className="badge" style={getSafetyBadgeStyle('MANUAL_ONLY')}>
                  {remediationPlan.manual_only_count} Manual Only
                </span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <button
                className="btn btn-secondary"
                onClick={() => setShowScriptModal(true)}
                style={{ fontSize: '0.85rem' }}
              >
                <FileCode size={16} /> Inspect Script
              </button>
              <a
                href={getRemediationDownloadUrl(id)}
                download
                className="btn"
                style={{
                  textDecoration: 'none',
                  fontSize: '0.85rem',
                  background: 'var(--cyan-accent)',
                  color: '#090d16',
                  fontWeight: 700
                }}
              >
                <Download size={16} /> Download {remediationPlan.file_extension}
              </a>
            </div>
          </div>
          {/* Mandatory Operator Disclaimer */}
          <div
            style={{
              marginTop: '16px',
              padding: '10px 14px',
              borderRadius: '6px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.25)',
              color: 'var(--amber-warn)',
              fontSize: '0.8rem',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}
          >
            <AlertCircle size={18} style={{ flexShrink: 0 }} />
            <span>
              <strong>Operator Safety Protocol:</strong> {remediationPlan.deployment_warning}
            </span>
          </div>
        </div>
      )}

      {/* 4 Core Posture KPI Cards */}
      <div className="grid-kpi">
        <div className="kpi-box">
          <div className="kpi-title">
            <span>Deterministic Compliance</span>
            <ShieldCheck size={18} color="var(--emerald-pass)" />
          </div>
          <div className="kpi-number" style={{ color: compliance_score >= 80 ? 'var(--emerald-pass)' : compliance_score >= 50 ? 'var(--amber-warn)' : 'var(--rose-fail)' }}>
            {compliance_score}%
          </div>
          <div className="kpi-subtext">
            {compliance_summary.passed_count} Passed / {compliance_summary.failed_count} Failed / {compliance_summary.warn_count} Warn
          </div>
        </div>

        <div className="kpi-box">
          <div className="kpi-title">
            <span>Composite Risk Score</span>
            <Activity size={18} color="var(--cyan-accent)" />
          </div>
          <div className="kpi-number" style={{ color: composite_risk_score <= 25 ? 'var(--emerald-pass)' : composite_risk_score <= 50 ? 'var(--amber-warn)' : 'var(--rose-fail)' }}>
            {composite_risk_score} <span style={{ fontSize: '1rem', color: 'var(--text-dim)' }}>/ 100</span>
          </div>
          <div className="kpi-subtext">55% Rules + 45% ML + Anomaly Penalty</div>
        </div>

        <div className="kpi-box">
          <div className="kpi-title">
            <span>ML Model Risk Prediction</span>
            <Cpu size={18} color="var(--purple-accent)" />
          </div>
          <div className="kpi-number" style={{ color: 'var(--purple-accent)' }}>
            {ml_result.predicted_risk_class}
          </div>
          <div className="kpi-subtext">
            {ml_result.model_version} ({(ml_result.confidence * 100).toFixed(1)}% Confidence)
          </div>
        </div>

        <div className="kpi-box">
          <div className="kpi-title">
            <span>Anomaly Scoring</span>
            <AlertTriangle size={18} color={ml_result.is_anomaly ? 'var(--rose-fail)' : 'var(--emerald-pass)'} />
          </div>
          <div className="kpi-number" style={{ color: ml_result.is_anomaly ? 'var(--rose-fail)' : 'var(--emerald-pass)' }}>
            {ml_result.is_anomaly ? 'ANOMALOUS' : 'TYPICAL'}
          </div>
          <div className="kpi-subtext">Isolation Score: {ml_result.anomaly_score}</div>
        </div>
      </div>

      {/* Risk Aggregation Lineage & ML Explainability Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '24px', marginBottom: '28px' }}>
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Info size={18} color="var(--cyan-accent)" />
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Risk Formula & Key Drivers</h3>
          </div>
          <div style={{ background: '#090e1a', padding: '12px 14px', borderRadius: '6px', fontSize: '0.85rem', color: '#38bdf8', marginBottom: '14px', border: '1px solid var(--border-subtle)' }}>
            {risk_assessment.calculation_breakdown}
          </div>
          <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px' }}>
            PRIMARY RISK DRIVERS:
          </div>
          <ul style={{ paddingLeft: '20px', fontSize: '0.88rem', color: 'var(--text-main)', lineHeight: 1.8 }}>
            {risk_assessment.key_drivers.map((kd, idx) => (
              <li key={idx}>{kd}</li>
            ))}
          </ul>
        </div>

        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Cpu size={18} color="var(--purple-accent)" />
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>ML Model Explainability (Top Factors)</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {ml_result.top_contributing_factors.map((factor, idx) => (
              <div key={idx} style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '4px' }}>
                  <strong style={{ color: 'var(--text-main)' }}>{factor.description}</strong>
                  <span style={{ color: 'var(--cyan-accent)', fontWeight: 700 }}>+{factor.contribution_score}% impact</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                  <span>Feature: <code>{factor.feature_name}</code> (Value: {factor.feature_value})</span>
                  <span>Gini Weight: {factor.importance_weight}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Itemized Findings Section */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px', marginBottom: '20px' }}>
          <div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800 }}>Deterministic Compliance Findings</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              Showing {filteredFindings.length} of {findings.length} evaluated security controls
            </p>
          </div>

          {/* Status Filter Tabs */}
          <div style={{ display: 'flex', gap: '6px' }}>
            {['ALL', 'FAIL', 'WARN', 'PASS'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`btn btn-secondary ${statusFilter === st ? 'active' : ''}`}
                style={{
                  padding: '6px 12px',
                  fontSize: '0.8rem',
                  background: statusFilter === st ? 'var(--blue-accent)' : undefined,
                  color: statusFilter === st ? '#fff' : undefined,
                }}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        {/* Search & Severity Filter Bar */}
        <div style={{ display: 'flex', gap: '12px', marginBottom: '20px', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '240px', position: 'relative' }}>
            <Search size={16} color="var(--text-dim)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
            <input
              type="text"
              placeholder="Search by control ID, title, or evidence..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
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

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{
              background: '#090e1a',
              color: 'var(--text-main)',
              border: '1px solid var(--border-strong)',
              borderRadius: '6px',
              padding: '10px 14px',
              fontSize: '0.85rem',
              outline: 'none',
            }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Severity</option>
            <option value="HIGH">High Severity</option>
            <option value="MEDIUM">Medium Severity</option>
            <option value="LOW">Low Severity</option>
          </select>
        </div>

        {/* Findings List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {filteredFindings.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
              No findings match your current filter criteria.
            </div>
          ) : (
            filteredFindings.map((f, idx) => {
              const borderColors = {
                PASS: 'var(--emerald-pass)',
                WARN: 'var(--amber-warn)',
                FAIL: 'var(--rose-fail)',
              };

              const action = remediationMap[f.control_id];
              const isExpanded = !!expandedRemediations[f.control_id];

              return (
                <div
                  key={idx}
                  style={{
                    background: '#0a1020',
                    border: '1px solid var(--border-subtle)',
                    borderLeft: `5px solid ${borderColors[f.status] || 'var(--border-subtle)'}`,
                    borderRadius: '8px',
                    padding: '16px 20px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                      <span className={`badge badge-${f.status}`}>{f.status}</span>
                      <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                      <strong style={{ fontSize: '1rem', color: '#fff' }}>
                        {f.control_id}: {f.title}
                      </strong>
                    </div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      {action && (
                        <span className="badge" style={getSafetyBadgeStyle(action.safety_classification)}>
                          {action.safety_classification.replace('_', ' ')}
                        </span>
                      )}
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', background: 'rgba(255, 255, 255, 0.04)', padding: '3px 8px', borderRadius: '4px' }}>
                        {f.standard}
                      </span>
                    </div>
                  </div>

                  <div style={{ fontSize: '0.88rem', color: 'var(--text-main)', marginTop: '8px' }}>
                    <strong style={{ color: 'var(--cyan-accent)' }}>Evidence: </strong>
                    <span>{f.evidence}</span>
                  </div>

                  <div style={{ fontSize: '0.88rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                    <strong style={{ color: 'var(--text-main)' }}>Recommendation: </strong>
                    <span>{f.recommendation}</span>
                  </div>

                  {/* Remediation Action Section (Stage 3A Expandable Drawer) */}
                  {action && f.status !== 'PASS' && (
                    <div style={{ marginTop: '14px', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <button
                          className="btn btn-secondary"
                          onClick={() => toggleRemediationExpand(f.control_id)}
                          style={{
                            padding: '6px 12px',
                            fontSize: '0.8rem',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px'
                          }}
                        >
                          <Terminal size={14} color="var(--cyan-accent)" />
                          {isExpanded ? 'Hide Remediation Plan' : 'View Remediation Plan & CLI'}
                          {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                        </button>

                        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                          Component: <strong style={{ color: 'var(--text-main)' }}>{action.affected_component}</strong>
                        </div>
                      </div>

                      {/* Expanded Remediation Drawer */}
                      {isExpanded && (
                        <div
                          style={{
                            marginTop: '12px',
                            background: '#060911',
                            borderRadius: '8px',
                            border: '1px solid var(--border-strong)',
                            padding: '16px'
                          }}
                        >
                          {/* Rationale & Problem Description */}
                          <div style={{ marginBottom: '14px' }}>
                            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--cyan-accent)', marginBottom: '4px' }}>
                              TECHNICAL RATIONALE & REMEDIATION OBJECTIVE:
                            </div>
                            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                              {action.remediation_description}
                            </div>
                          </div>

                          {/* Placeholders Banner */}
                          {action.placeholders && action.placeholders.length > 0 && (
                            <div
                              style={{
                                background: 'rgba(245, 158, 11, 0.12)',
                                border: '1px solid rgba(245, 158, 11, 0.3)',
                                borderRadius: '6px',
                                padding: '8px 12px',
                                marginBottom: '14px',
                                fontSize: '0.8rem',
                                color: 'var(--amber-warn)'
                              }}
                            >
                              <strong>Requires Operator Configuration:</strong> Populate parameter(s):{' '}
                              <code>{action.placeholders.join(', ')}</code> with your enterprise environment addresses or keys.
                            </div>
                          )}

                          {/* Warning Banner */}
                          {action.warning && (
                            <div
                              style={{
                                background: 'rgba(239, 68, 68, 0.1)',
                                border: '1px solid rgba(239, 68, 68, 0.3)',
                                borderRadius: '6px',
                                padding: '8px 12px',
                                marginBottom: '14px',
                                fontSize: '0.8rem',
                                color: 'var(--rose-fail)'
                              }}
                            >
                              <strong>Operational Warning:</strong> {action.warning}
                            </div>
                          )}

                          {/* Commands (AFTER) */}
                          <div style={{ marginBottom: '14px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                              <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                                Recommended CLI Commands ({vendor}):
                              </span>
                              <button
                                className="copy-btn"
                                style={{ position: 'static' }}
                                onClick={() => copyToClipboard(action.commands.join('\n'), f.control_id + '_cmds')}
                              >
                                {copiedCliId === f.control_id + '_cmds' ? (
                                  <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                    <Check size={12} color="var(--emerald-pass)" /> Copied
                                  </span>
                                ) : (
                                  <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                    <Copy size={12} /> Copy Commands
                                  </span>
                                )}
                              </button>
                            </div>
                            <div className="code-container" style={{ margin: 0 }}>
                              <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                                {action.commands.join('\n')}
                              </pre>
                            </div>
                          </div>

                          {/* Validation Commands */}
                          {action.validation_commands && action.validation_commands.length > 0 && (
                            <div style={{ marginBottom: '14px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                                  Post-Change Validation Commands:
                                </span>
                                <button
                                  className="copy-btn"
                                  style={{ position: 'static' }}
                                  onClick={() => copyToClipboard(action.validation_commands.join('\n'), f.control_id + '_val')}
                                >
                                  {copiedCliId === f.control_id + '_val' ? (
                                    <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                      <Check size={12} color="var(--emerald-pass)" /> Copied
                                    </span>
                                  ) : (
                                    <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                      <Copy size={12} /> Copy Validation
                                    </span>
                                  )}
                                </button>
                              </div>
                              <div className="code-container" style={{ margin: 0, color: 'var(--emerald-pass)' }}>
                                <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                                  {action.validation_commands.join('\n')}
                                </pre>
                              </div>
                            </div>
                          )}

                          {/* Rollback Commands */}
                          {action.rollback_commands && action.rollback_commands.length > 0 && (
                            <div>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                                  Emergency Rollback Commands:
                                </span>
                                <button
                                  className="copy-btn"
                                  style={{ position: 'static' }}
                                  onClick={() => copyToClipboard(action.rollback_commands.join('\n'), f.control_id + '_roll')}
                                >
                                  {copiedCliId === f.control_id + '_roll' ? (
                                    <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                      <Check size={12} color="var(--emerald-pass)" /> Copied
                                    </span>
                                  ) : (
                                    <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                      <Copy size={12} /> Copy Rollback
                                    </span>
                                  )}
                                </button>
                              </div>
                              <div className="code-container" style={{ margin: 0, color: 'var(--text-muted)' }}>
                                <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                                  {action.rollback_commands.join('\n')}
                                </pre>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Full Remediation Script Modal */}
      {showScriptModal && remediationPlan && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.85)',
            backdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '24px'
          }}
        >
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: '960px',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              background: '#090d16',
              border: '1px solid var(--border-strong)',
              boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7)',
              padding: '24px'
            }}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Terminal size={22} color="var(--cyan-accent)" />
                  <h2 style={{ fontSize: '1.3rem', fontWeight: 800 }}>
                    Vendor Remediation Script: {remediationPlan.vendor}
                  </h2>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Target Node: <code>{remediationPlan.hostname}</code> | Total Actions: {remediationPlan.remediated_controls_count} | Format: <code>{remediationPlan.file_extension}</code>
                </p>
              </div>
              <button
                className="btn btn-secondary"
                onClick={() => setShowScriptModal(false)}
                style={{ padding: '6px 10px' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Warning Banner */}
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.25)',
                color: 'var(--amber-warn)',
                fontSize: '0.8rem',
                marginBottom: '16px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              <AlertCircle size={16} style={{ flexShrink: 0 }} />
              <span>
                Verify all placeholder tags (e.g. <code>&lt;SYSLOG_SERVER_IP&gt;</code>) before executing on networking equipment.
              </span>
            </div>

            {/* Script Text Container */}
            <div
              className="code-container"
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '16px',
                background: '#04070e',
                border: '1px solid var(--border-subtle)',
                fontSize: '0.85rem',
                lineHeight: 1.5,
                color: '#38bdf8',
                maxHeight: '55vh'
              }}
            >
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontFamily: 'JetBrains Mono, monospace' }}>
                {remediationPlan.full_script}
              </pre>
            </div>

            {/* Modal Footer */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '18px' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                {remediationPlan.safe_automatic_count} Safe Automatic | {remediationPlan.review_required_count} Review Required | {remediationPlan.manual_only_count} Manual Only
              </div>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  className="btn btn-secondary"
                  onClick={copyFullScriptToClipboard}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  {copiedFullScript ? (
                    <>
                      <Check size={14} color="var(--emerald-pass)" /> Copied Script
                    </>
                  ) : (
                    <>
                      <Copy size={14} /> Copy Full Script
                    </>
                  )}
                </button>
                <a
                  href={getRemediationDownloadUrl(id)}
                  download
                  className="btn"
                  style={{
                    textDecoration: 'none',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: 'var(--cyan-accent)',
                    color: '#090d16',
                    fontWeight: 700
                  }}
                >
                  <Download size={14} /> Download File ({remediationPlan.file_extension})
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
