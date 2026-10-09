/**
 * API Client for interacting with the FastAPI Backend.
 */

const API_BASE = '/api';

export async function fetchDashboardSummary() {
  const res = await fetch(`${API_BASE}/dashboard/summary`);
  if (!res.ok) {
    throw new Error(`Failed to fetch dashboard summary: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAuditsList(limit = 50) {
  const res = await fetch(`${API_BASE}/audits?limit=${limit}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch audit history: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAuditDetail(auditId) {
  const res = await fetch(`${API_BASE}/audits/${auditId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch audit details for ${auditId}: ${res.statusText}`);
  }
  return res.json();
}

export async function uploadConfigurationFile(file, vendorOverride = null) {
  const formData = new FormData();
  formData.append('file', file);
  if (vendorOverride && vendorOverride !== 'auto') {
    formData.append('vendor_override', vendorOverride);
  }

  const res = await fetch(`${API_BASE}/audits/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || 'Upload and audit failed.');
  }
  return res.json();
}

export async function analyzeConfigurationText(content, filename = 'pasted_config.txt', vendorOverride = null) {
  const res = await fetch(`${API_BASE}/audits/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      content,
      filename,
      vendor_override: vendorOverride && vendorOverride !== 'auto' ? vendorOverride : null,
    }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || 'Configuration analysis failed.');
  }
  return res.json();
}

export async function detectVendorSnippet(content) {
  const res = await fetch(`${API_BASE}/audits/detect-vendor`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ content }),
  });
  if (!res.ok) {
    throw new Error('Vendor detection request failed.');
  }
  return res.json();
}

export async function deleteAuditRecord(auditId) {
  const res = await fetch(`${API_BASE}/audits/${auditId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`Failed to delete audit: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAuditRemediation(auditId) {
  const res = await fetch(`${API_BASE}/audits/${auditId}/remediation`);
  if (!res.ok) {
    throw new Error(`Failed to fetch remediation plan for ${auditId}: ${res.statusText}`);
  }
  return res.json();
}

export function getRemediationDownloadUrl(auditId) {
  return `${API_BASE}/audits/${auditId}/remediation/download`;
}

