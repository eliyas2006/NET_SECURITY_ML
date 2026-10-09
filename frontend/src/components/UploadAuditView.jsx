import React, { useState, useRef } from 'react';
import { uploadConfigurationFile, analyzeConfigurationText } from '../services/api';
import { SAMPLE_CONFIGS } from '../data/samples';
import {
  UploadCloud,
  FileText,
  CheckCircle,
  AlertCircle,
  Loader2,
  Sparkles,
  ArrowRight
} from 'lucide-react';

const PIPELINE_STEPS = [
  'Ingesting Configuration',
  'Fingerprinting Vendor Syntax',
  'Parsing Vendor Tree (AST)',
  'Normalizing Common Schema',
  'Evaluating Deterministic CIS Rules',
  'Extracting 29 Security Features',
  'Running ML Risk & Anomaly Scoring',
  'Aggregating Composite Risk & Saving',
];

export default function UploadAuditView({ onAuditCompleted }) {
  const [activeTab, setActiveTab] = useState('upload'); // 'upload' or 'text'
  const [selectedFile, setSelectedFile] = useState(null);
  const [rawText, setRawText] = useState('');
  const [vendorOverride, setVendorOverride] = useState('auto');
  const [customFilename, setCustomFilename] = useState('configuration.txt');

  const [isProcessing, setIsProcessing] = useState(false);
  const [currentStepIdx, setCurrentStepIdx] = useState(0);
  const [errorMessage, setErrorMessage] = useState(null);

  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setErrorMessage(null);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
      setErrorMessage(null);
    }
  };

  const loadSample = (sampleKey) => {
    const s = SAMPLE_CONFIGS[sampleKey];
    if (s) {
      setRawText(s.text);
      setCustomFilename(s.filename);
      setVendorOverride(s.vendor);
      setActiveTab('text');
      setErrorMessage(null);
    }
  };

  const runAudit = async () => {
    setErrorMessage(null);
    setIsProcessing(true);
    setCurrentStepIdx(0);

    // Simulate animated step progression through the 8 stages
    const stepInterval = setInterval(() => {
      setCurrentStepIdx((prev) => {
        if (prev < PIPELINE_STEPS.length - 1) return prev + 1;
        return prev;
      });
    }, 280);

    try {
      let result;
      if (activeTab === 'upload') {
        if (!selectedFile) {
          throw new Error('Please select or drop a configuration file first.');
        }
        result = await uploadConfigurationFile(selectedFile, vendorOverride);
      } else {
        if (!rawText.trim()) {
          throw new Error('Configuration text cannot be empty.');
        }
        result = await analyzeConfigurationText(rawText, customFilename, vendorOverride);
      }

      clearInterval(stepInterval);
      setCurrentStepIdx(PIPELINE_STEPS.length - 1);

      // Brief delay to display complete state before redirecting
      setTimeout(() => {
        setIsProcessing(false);
        onAuditCompleted(result.id);
      }, 400);

    } catch (err) {
      clearInterval(stepInterval);
      setIsProcessing(false);
      setErrorMessage(err.message || 'Audit execution encountered a failure.');
    }
  };

  return (
    <div style={{ maxWidth: '960px', margin: '0 auto' }}>
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <h1 style={{ fontSize: '2rem', fontWeight: 800 }}>Audit Network Configuration</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '1rem', marginTop: '6px' }}>
          Upload router or firewall configuration to trigger multi-vendor parsing, deterministic compliance checks, and ML risk classification.
        </p>
      </div>

      {/* Preset Quick-Load Samples */}
      <div className="card" style={{ marginBottom: '24px', background: 'rgba(30, 41, 59, 0.4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
          <Sparkles size={18} color="var(--cyan-accent)" />
          <strong style={{ fontSize: '0.9rem' }}>Quick Test with Pre-built Baseline Samples:</strong>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
          <button className="btn btn-secondary" style={{ fontSize: '0.8rem', padding: '6px 12px' }} onClick={() => loadSample('cisco_hardened')}>
            Cisco Hardened Core (Low Risk)
          </button>
          <button className="btn btn-secondary" style={{ fontSize: '0.8rem', padding: '6px 12px' }} onClick={() => loadSample('cisco_vulnerable')}>
            Cisco Perimeter (Critical Risk)
          </button>
          <button className="btn btn-secondary" style={{ fontSize: '0.8rem', padding: '6px 12px' }} onClick={() => loadSample('fortinet_edge')}>
            Fortinet Edge Firewall (Secure)
          </button>
          <button className="btn btn-secondary" style={{ fontSize: '0.8rem', padding: '6px 12px' }} onClick={() => loadSample('palo_alto_secure')}>
            Palo Alto PAN-OS Gateway
          </button>
        </div>
      </div>

      {/* Main Audit Form */}
      <div className="card">
        {/* Tab Switcher */}
        <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '16px', marginBottom: '24px' }}>
          <button
            className={`btn ${activeTab === 'upload' ? '' : 'btn-secondary'}`}
            onClick={() => setActiveTab('upload')}
            disabled={isProcessing}
          >
            <UploadCloud size={16} /> File Upload (.cfg, .conf, .txt)
          </button>
          <button
            className={`btn ${activeTab === 'text' ? '' : 'btn-secondary'}`}
            onClick={() => setActiveTab('text')}
            disabled={isProcessing}
          >
            <FileText size={16} /> Direct Configuration Text
          </button>
        </div>

        {/* Vendor Selector & Options */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
              VENDOR SELECTION
            </label>
            <select
              value={vendorOverride}
              onChange={(e) => setVendorOverride(e.target.value)}
              disabled={isProcessing}
              style={{
                width: '100%',
                background: '#090e1a',
                color: 'var(--text-main)',
                border: '1px solid var(--border-strong)',
                borderRadius: '6px',
                padding: '10px 12px',
                fontSize: '0.9rem',
                outline: 'none',
              }}
            >
              <option value="auto">Automatic Vendor Fingerprinting (Recommended)</option>
              <option value="Cisco">Cisco Systems (IOS / IOS-XE)</option>
              <option value="Fortinet">Fortinet (FortiOS)</option>
              <option value="Palo Alto">Palo Alto Networks (PAN-OS)</option>
            </select>
          </div>

          {activeTab === 'text' && (
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                DEVICE FILENAME IDENTIFIER
              </label>
              <input
                type="text"
                value={customFilename}
                onChange={(e) => setCustomFilename(e.target.value)}
                disabled={isProcessing}
                style={{
                  width: '100%',
                  background: '#090e1a',
                  color: 'var(--text-main)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: '6px',
                  padding: '10px 12px',
                  fontSize: '0.9rem',
                  outline: 'none',
                }}
              />
            </div>
          )}
        </div>

        {/* Input Methods */}
        {activeTab === 'upload' ? (
          <div>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              style={{ display: 'none' }}
              accept=".txt,.cfg,.conf,.set,.text"
            />
            <div
              className={`dropzone ${selectedFile ? 'active' : ''}`}
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current && fileInputRef.current.click()}
            >
              <UploadCloud size={48} color={selectedFile ? 'var(--cyan-accent)' : 'var(--text-dim)'} style={{ margin: '0 auto 12px' }} />
              {selectedFile ? (
                <div>
                  <h4 style={{ color: 'var(--cyan-accent)', fontWeight: 700 }}>{selectedFile.name}</h4>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '4px' }}>
                    {(selectedFile.size / 1024).toFixed(1)} KB — Click or drop another file to replace
                  </p>
                </div>
              ) : (
                <div>
                  <h4 style={{ fontWeight: 700 }}>Drag & drop network configuration file here</h4>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '6px' }}>
                    Supports Cisco IOS (.cfg), Fortinet FortiOS (.conf), and Palo Alto PAN-OS (.txt)
                  </p>
                  <button type="button" className="btn btn-secondary" style={{ marginTop: '16px' }}>
                    Browse Local File
                  </button>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div>
            <textarea
              rows={14}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste raw running-config or device configuration stanzas here..."
              disabled={isProcessing}
              style={{
                width: '100%',
                background: '#060911',
                color: '#38bdf8',
                border: '1px solid var(--border-strong)',
                borderRadius: '8px',
                padding: '14px',
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '0.85rem',
                lineHeight: 1.5,
                outline: 'none',
                resize: 'vertical',
              }}
            />
          </div>
        )}

        {/* Error message */}
        {errorMessage && (
          <div style={{ marginTop: '20px', padding: '12px 16px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid var(--rose-fail)', borderRadius: '6px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertCircle size={20} color="var(--rose-fail)" />
            <span style={{ color: '#fca5a5', fontSize: '0.9rem' }}>{errorMessage}</span>
          </div>
        )}

        {/* Processing State: Live Animated Pipeline Visualizer */}
        {isProcessing && (
          <div style={{ marginTop: '28px', padding: '24px', background: 'rgba(15, 23, 42, 0.9)', border: '1px solid var(--cyan-accent)', borderRadius: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <Loader2 size={24} className="animate-spin" color="var(--cyan-accent)" />
              <div>
                <strong style={{ fontSize: '1rem', color: '#fff' }}>Executing Audit Pipeline...</strong>
                <div style={{ fontSize: '0.85rem', color: 'var(--cyan-accent)' }}>
                  Current Phase: {PIPELINE_STEPS[currentStepIdx]}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {PIPELINE_STEPS.map((step, idx) => {
                const isDone = idx < currentStepIdx;
                const isCurrent = idx === currentStepIdx;

                return (
                  <div
                    key={step}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      fontSize: '0.85rem',
                      color: isDone ? 'var(--emerald-pass)' : isCurrent ? 'var(--cyan-accent)' : 'var(--text-dim)',
                      fontWeight: isCurrent ? 700 : 500,
                    }}
                  >
                    {isDone ? (
                      <CheckCircle size={16} color="var(--emerald-pass)" />
                    ) : isCurrent ? (
                      <Loader2 size={16} className="animate-spin" color="var(--cyan-accent)" />
                    ) : (
                      <div style={{ width: 16, height: 16, borderRadius: '50%', border: '1px solid var(--text-dim)' }} />
                    )}
                    <span>{step}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Action Button */}
        {!isProcessing && (
          <div style={{ marginTop: '24px', display: 'flex', justifyContent: 'flex-end' }}>
            <button
              className="btn"
              onClick={runAudit}
              disabled={activeTab === 'upload' ? !selectedFile : !rawText.trim()}
              style={{ padding: '12px 28px', fontSize: '1rem' }}
            >
              Start Intelligent Audit <ArrowRight size={18} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
