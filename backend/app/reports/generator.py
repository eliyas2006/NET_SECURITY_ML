"""
Audit Report Generator.
Renders a comprehensive, standalone HTML/Printable security compliance audit report.
"""

from jinja2 import Template
from backend.app.schemas.api import AuditDetailResponse

REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Compliance Audit Report - {{ audit.hostname }}</title>
    <style>
        :root {
            --primary: #0f172a;
            --accent: #2563eb;
            --danger: #dc2626;
            --warning: #d97706;
            --success: #16a34a;
            --bg: #f8fafc;
            --card: #ffffff;
            --border: #e2e8f0;
            --text: #1e293b;
            --muted: #64748b;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0 0 6px 0;
            font-size: 24px;
            color: var(--primary);
        }
        .header .meta {
            color: var(--muted);
            font-size: 14px;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 13px;
            text-transform: uppercase;
        }
        .badge-CRITICAL { background: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
        .badge-HIGH { background: #ffedd5; color: #9a3412; border: 1px solid #fb923c; }
        .badge-MEDIUM { background: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }
        .badge-LOW { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
        .badge-PASS { background: #dcfce7; color: #166534; }
        .badge-FAIL { background: #fee2e2; color: #991b1b; }
        .badge-WARN { background: #fef3c7; color: #92400e; }

        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 30px;
        }
        .kpi-card {
            background: #f1f5f9;
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }
        .kpi-value {
            font-size: 28px;
            font-weight: 800;
            margin: 4px 0;
        }
        .kpi-label {
            font-size: 12px;
            color: var(--muted);
            text-transform: uppercase;
            font-weight: 600;
        }
        .section {
            margin-bottom: 36px;
        }
        .section-title {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
            color: var(--primary);
        }
        .finding-card {
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 16px;
            background: #fff;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .finding-title {
            font-weight: 600;
            font-size: 15px;
        }
        .code-box {
            background: #0f172a;
            color: #f8fafc;
            padding: 10px 14px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
            margin: 8px 0;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        .drivers-list {
            margin: 0;
            padding-left: 20px;
        }
        .drivers-list li {
            margin-bottom: 6px;
        }
        @media print {
            body { padding: 0; background: #fff; }
            .container { border: none; box-shadow: none; padding: 0; width: 100%; max-width: none; }
            .no-print { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Network Security Compliance Audit Report</h1>
                <div class="meta">
                    Target Device: <strong>{{ audit.hostname }}</strong> | Vendor: <strong>{{ audit.vendor }}</strong> ({{ audit.device_type }})<br>
                    Audit Reference: <strong>{{ audit.id }}</strong> | Generated: <strong>{{ audit.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</strong>
                </div>
            </div>
            <div style="text-align: right;">
                <span class="badge badge-{{ audit.final_risk_level }}" style="font-size: 16px; padding: 6px 16px;">
                    Risk: {{ audit.final_risk_level }} ({{ audit.composite_risk_score }}/100)
                </span>
                <div style="margin-top: 10px;" class="no-print">
                    <button onclick="window.print()" style="padding: 6px 14px; background: #2563eb; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">Print / Save as PDF</button>
                </div>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Compliance Score</div>
                <div class="kpi-value" style="color: {% if audit.compliance_score >= 80 %}var(--success){% elif audit.compliance_score >= 50 %}var(--warning){% else %}var(--danger){% endif %};">
                    {{ audit.compliance_score }}%
                </div>
                <div class="meta">{{ audit.compliance_summary.passed_count }}/{{ audit.compliance_summary.total_controls }} Passed</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Composite Risk Score</div>
                <div class="kpi-value" style="color: {% if audit.composite_risk_score <= 25 %}var(--success){% elif audit.composite_risk_score <= 50 %}var(--warning){% else %}var(--danger){% endif %};">
                    {{ audit.composite_risk_score }}
                </div>
                <div class="meta">Scale 0 - 100</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Critical Violations</div>
                <div class="kpi-value" style="color: {% if audit.compliance_summary.critical_violations > 0 %}var(--danger){% else %}var(--success){% endif %};">
                    {{ audit.compliance_summary.critical_violations }}
                </div>
                <div class="meta">Immediate Action Required</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">ML Predicted Risk</div>
                <div class="kpi-value" style="color: var(--accent);">
                    {{ audit.ml_result.predicted_risk_class }}
                </div>
                <div class="meta">{{ (audit.ml_result.confidence * 100)|round(1) }}% Confidence</div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Executive Risk Assessment & ML Insights</div>
            <p><strong>Calculation Formula & Lineage:</strong> {{ audit.risk_assessment.calculation_breakdown }}</p>
            <p><strong>Key Risk Drivers:</strong></p>
            <ul class="drivers-list">
                {% for driver in audit.risk_assessment.key_drivers %}
                    <li>{{ driver }}</li>
                {% endfor %}
            </ul>
            {% if audit.ml_result.is_anomaly %}
                <div style="background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px; margin-top: 14px;">
                    <strong>Configuration Anomaly Detected (Score: {{ audit.ml_result.anomaly_score }}):</strong>
                    This device exhibits atypical setting combinations deviating from standard baseline clusters.
                </div>
            {% endif %}
        </div>

        <div class="section">
            <div class="section-title">Itemized Security Compliance Findings ({{ audit.findings|length }} Controls)</div>
            {% for f in audit.findings %}
                <div class="finding-card" style="border-left: 4px solid {% if f.status == 'PASS' %}var(--success){% elif f.status == 'WARN' %}var(--warning){% else %}var(--danger){% endif %};">
                    <div class="finding-header">
                        <div>
                            <span class="badge badge-{{ f.status }}">{{ f.status }}</span>
                            <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
                            <strong style="margin-left: 8px;">{{ f.control_id }}: {{ f.title }}</strong>
                        </div>
                        <div class="meta">{{ f.standard }}</div>
                    </div>
                    <div style="font-size: 14px; margin-top: 6px;">
                        <strong>Evidence:</strong> {{ f.evidence }}
                    </div>
                    <div style="font-size: 14px; margin-top: 4px; color: var(--muted);">
                        <strong>Recommendation:</strong> {{ f.recommendation }}
                    </div>
                    {% if f.remediation_cli and f.status != 'PASS' %}
                        <div style="margin-top: 8px;">
                            <strong style="font-size: 13px;">Remediation CLI Snippet:</strong>
                            <div class="code-box">{{ f.remediation_cli }}</div>
                        </div>
                    {% endif %}
                </div>
            {% endfor %}
        <div class="section" style="border-top: 2px solid var(--border); padding-top: 20px; margin-top: 30px;">
            <div class="section-title" style="color: var(--muted); font-size: 15px;">Operational Safety Disclaimers & Limitations</div>
            <div style="font-size: 13px; color: var(--muted); line-height: 1.6;">
                <p><strong>Remediation Safety:</strong> All CLI remediation snippets and configuration blocks generated in this report are for operator review and offline evaluation. Do not copy-paste or deploy generated configurations directly to live production devices without staging validation and change window approval. Replace all <code>&lt;PLACEHOLDER&gt;</code> tokens with authoritative environment parameters.</p>
                <p><strong>Static Analysis Scope:</strong> This compliance audit evaluates static configuration text. It does not inspect live interface runtime state, active BGP/OSPF sessions, dynamic MAC address tables, or underlying operating system kernel firmware vulnerabilities.</p>
                <p><strong>Machine Learning Methodology:</strong> ML risk classifications and anomaly indicators are trained on synthetic expert-modeled configuration postures. High confidence predictions reflect statistical alignment with hardened baseline clusters and do not constitute a guarantee against zero-day exploits or active external cyber attacks.</p>
            </div>
        </div>
    </div>
</body>
</html>
"""


def generate_html_report(audit: AuditDetailResponse) -> str:
    template = Template(REPORT_HTML_TEMPLATE)
    return template.render(audit=audit)
