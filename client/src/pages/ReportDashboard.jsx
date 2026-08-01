import { useState, useEffect } from 'react';
import { getSecurityReport, downloadReportJsonUrl, downloadReportMarkdownUrl } from '../services/api';
import './ReportDashboard.css';

export default function ReportDashboard({ analysisId, onBack }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [reportData, setReportData] = useState(null);

  // Filter & Search states
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSev, setSelectedSev] = useState('ALL');
  const [expandedIds, setExpandedIds] = useState(new Set());

  useEffect(() => {
    if (!analysisId) return;

    let isMounted = true;

    async function fetchReport() {
      try {
        setLoading(true);
        const res = await getSecurityReport(analysisId);
        if (isMounted) {
          if (res.reportReady && res.report) {
            setReportData(res.report);
            setError(null);
          } else {
            setError('Security Report is still being generated. Please wait...');
          }
        }
      } catch (err) {
        if (isMounted) {
          console.error('Failed to fetch security report:', err);
          setError(err.message || 'Failed to load Security Report.');
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    fetchReport();

    return () => { isMounted = false; };
  }, [analysisId]);

  if (loading) {
    return (
      <div className="report-container">
        <div className="report-section" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div className="spinner" style={{ width: '32px', height: '32px', border3em: '3px solid #2563eb', borderTopColor: 'transparent', margin: '0 auto 16px' }}></div>
          <h3>Loading SentinelAI Security Report...</h3>
          <p style={{ color: '#64748b' }}>Analyzing findings, calculating risk scores, and rendering report dashboard.</p>
        </div>
      </div>
    );
  }

  if (error || !reportData) {
    return (
      <div className="report-container">
        <div className="report-section" style={{ textAlign: 'center', padding: '40px 20px' }}>
          <h2 style={{ color: '#ef4444' }}>⚠️ Notice</h2>
          <p>{error || 'Report not found.'}</p>
          {onBack && (
            <button className="export-btn" onClick={onBack} style={{ marginTop: '16px' }}>
              ← Return to Dashboard
            </button>
          )}
        </div>
      </div>
    );
  }

  const { analysis, summary, statistics, executive_summary, findings = [] } = reportData;

  const score = summary?.overallSecurityScore ?? 100;
  const grade = summary?.grade || 'A+';

  const toggleExpand = (id) => {
    const next = new Set(expandedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpandedIds(next);
  };

  const expandAll = () => {
    const all = new Set(findings.map((f) => f.finding_id));
    setExpandedIds(all);
  };

  const collapseAll = () => {
    setExpandedIds(new Set());
  };

  const filteredFindings = findings.filter((f) => {
    const matchesSev = selectedSev === 'ALL' || (f.severity || '').toUpperCase() === selectedSev;
    const matchesSearch =
      !searchTerm ||
      (f.title || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.category || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.affected_files?.[0] || '').toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSev && matchesSearch;
  });

  return (
    <div className="report-container">
      {/* Header */}
      <div className="report-header">
        <div className="report-header-top">
          <div className="report-title-section">
            <h1>
              🛡️ SentinelAI Security Assessment
            </h1>
            <div className="report-meta-sub">
              Repository: <strong>{analysis?.repoFullName || 'Codebase'}</strong> | Analysis ID: <code>{analysisId}</code>
            </div>
          </div>

          <div className="header-actions">
            {onBack && (
              <button className="export-btn" onClick={onBack}>
                ← Back
              </button>
            )}
            <a
              href={downloadReportJsonUrl(analysisId)}
              className="export-btn"
              download
              target="_blank"
              rel="noreferrer"
            >
              📥 Download JSON
            </a>
            <a
              href={downloadReportMarkdownUrl(analysisId)}
              className="export-btn primary"
              download
              target="_blank"
              rel="noreferrer"
            >
              📄 Download Markdown
            </a>
            <button className="export-btn" onClick={() => window.print()}>
              🖨️ Print / PDF
            </button>
          </div>
        </div>
      </div>

      {/* Summary Score Dial & Statistics */}
      <div className="summary-grid">
        <div className="score-card">
          <div className={`score-badge-circle grade-${grade.charAt(0)}`}>
            {score}
          </div>
          <div className="score-label">Overall Security Score (Grade {grade})</div>
        </div>

        <div className="stats-grid">
          <div className="stat-box">
            <div className="stat-val">{statistics?.filesScanned || 0}</div>
            <div className="stat-lbl">Files Scanned</div>
          </div>
          <div className="stat-box">
            <div className="stat-val">{statistics?.chunksProcessed || 0}</div>
            <div className="stat-lbl">AST Chunks</div>
          </div>
          <div className="stat-box">
            <div className="stat-val">{statistics?.artifactsExtracted || 0}</div>
            <div className="stat-lbl">Evidence Nodes</div>
          </div>
          <div className="stat-box">
            <div className="stat-val">{statistics?.relationshipsBuilt || 0}</div>
            <div className="stat-lbl">Relationships</div>
          </div>
          <div className="stat-box">
            <div className="stat-val">{statistics?.findingsGenerated || 0}</div>
            <div className="stat-lbl">Total Findings</div>
          </div>
        </div>
      </div>

      {/* Severity Counters Row */}
      <div className="severity-cards-row">
        <div className="sev-count-card critical">
          <div className="count">{summary?.critical || 0}</div>
          <div className="label">Critical</div>
        </div>
        <div className="sev-count-card high">
          <div className="count">{summary?.high || 0}</div>
          <div className="label">High</div>
        </div>
        <div className="sev-count-card medium">
          <div className="count">{summary?.medium || 0}</div>
          <div className="label">Medium</div>
        </div>
        <div className="sev-count-card low">
          <div className="count">{summary?.low || 0}</div>
          <div className="label">Low</div>
        </div>
        <div className="sev-count-card info">
          <div className="count">{summary?.info || 0}</div>
          <div className="label">Info</div>
        </div>
      </div>

      {/* Executive Summary Section */}
      <div className="report-section">
        <h2>📊 Executive Summary</h2>
        <p style={{ lineHeight: '1.6', color: '#334155' }}>
          {executive_summary?.overview || 'Static security analysis completed.'}
        </p>
      </div>

      {/* Interactive Findings Table */}
      <div className="report-section">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <h2 style={{ margin: 0, border: 'none', padding: 0 }}>
            🛡️ Security Findings ({filteredFindings.length} of {findings.length})
          </h2>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="export-btn" onClick={expandAll} style={{ fontSize: '0.8rem', padding: '4px 10px' }}>
              Expand All
            </button>
            <button className="export-btn" onClick={collapseAll} style={{ fontSize: '0.8rem', padding: '4px 10px' }}>
              Collapse All
            </button>
          </div>
        </div>

        {/* Toolbar */}
        <div className="findings-toolbar">
          <input
            type="text"
            className="search-input"
            placeholder="Search findings by title, category, or file path..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />

          <select
            className="filter-select"
            value={selectedSev}
            onChange={(e) => setSelectedSev(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
            <option value="LOW">Low Only</option>
            <option value="INFO">Info Only</option>
          </select>
        </div>

        {filteredFindings.length === 0 ? (
          <p style={{ color: '#64748b', fontStyle: 'italic', padding: '20px 0' }}>
            No security findings match your filter criteria.
          </p>
        ) : (
          filteredFindings.map((finding) => {
            const isExpanded = expandedIds.has(finding.finding_id);
            const sev = (finding.severity || 'MEDIUM').toUpperCase();

            return (
              <div key={finding.finding_id} className="finding-card">
                <div className="finding-header" onClick={() => toggleExpand(finding.finding_id)}>
                  <div className="finding-title-group">
                    <span className={`sev-badge ${sev}`}>{sev}</span>
                    <span className="finding-title">{finding.title}</span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '0.85rem', color: '#64748b' }}>
                    <span>File: <code>{finding.affected_files?.[0] || 'N/A'}</code></span>
                    <span>Confidence: <strong>{((finding.confidence || 0.8) * 100).toFixed(0)}%</strong></span>
                    <span>{isExpanded ? '▲' : '▼'}</span>
                  </div>
                </div>

                {isExpanded && (
                  <div className="finding-body">
                    <div className="finding-sub-grid">
                      <div className="finding-block">
                        <h4>Executive Summary</h4>
                        <p style={{ fontSize: '0.9rem', color: '#334155', margin: 0 }}>
                          {finding.executive_summary || finding.description}
                        </p>
                      </div>

                      <div className="finding-block">
                        <h4>Technical Description & Root Cause</h4>
                        <p style={{ fontSize: '0.9rem', color: '#334155', margin: 0 }}>
                          {finding.technical_description || finding.reasoning}
                        </p>
                      </div>
                    </div>

                    <div className="finding-sub-grid">
                      <div className="finding-block">
                        <h4>Business Impact</h4>
                        <p style={{ fontSize: '0.9rem', color: '#334155', margin: 0 }}>
                          {finding.business_impact}
                        </p>
                      </div>

                      <div className="finding-block">
                        <h4>Technical Impact</h4>
                        <div>
                          {Array.isArray(finding.technical_impact) &&
                            finding.technical_impact.map((tag, tIdx) => (
                              <span key={tIdx} className="badge-tag">{tag}</span>
                            ))}
                        </div>
                      </div>
                    </div>

                    {/* Evidence Chain */}
                    {Array.isArray(finding.evidence_chain) && finding.evidence_chain.length > 0 && (
                      <div className="finding-block" style={{ marginBottom: '16px' }}>
                        <h4>Evidence Chain</h4>
                        <div className="evidence-chain">
                          {finding.evidence_chain.map((step, sIdx) => (
                            <span key={sIdx} style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                              <span className="chain-step">{step}</span>
                              {sIdx < finding.evidence_chain.length - 1 && <span className="chain-arrow">→</span>}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Vulnerable Code Snippet */}
                    {finding.exact_location?.code_snippet && (
                      <div className="finding-block" style={{ marginBottom: '16px' }}>
                        <h4>Vulnerable Code ({finding.exact_location.file_path} : L{finding.exact_location.start_line})</h4>
                        <pre className="code-box">{finding.exact_location.code_snippet}</pre>
                      </div>
                    )}

                    {/* Secure Code Replacement */}
                    {finding.secure_code_fix && (
                      <div className="finding-block" style={{ marginBottom: '16px' }}>
                        <h4>Recommended Secure Replacement Code</h4>
                        <pre className="code-box fix">{finding.secure_code_fix}</pre>
                        {finding.fix_explanation && (
                          <p style={{ fontSize: '0.85rem', color: '#047857', marginTop: '6px' }}>
                            <strong>Why Secure:</strong> {finding.fix_explanation}
                          </p>
                        )}
                      </div>
                    )}

                    {/* Standards Mapping */}
                    {finding.standards_mapping && Object.keys(finding.standards_mapping).length > 0 && (
                      <div className="finding-block" style={{ marginBottom: '12px' }}>
                        <h4>Standards & Framework Mapping</h4>
                        <div>
                          {Object.entries(finding.standards_mapping).map(([k, v]) => (
                            <span key={k} className="badge-tag">
                              <strong>{k.toUpperCase()}:</strong> {v}
                            </span>
                          ))}
                        </div>
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
  );
}
