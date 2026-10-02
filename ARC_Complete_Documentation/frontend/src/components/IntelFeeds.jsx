import React, { useState } from 'react';
import { 
  Crosshair, Users, Search, Copy, Check, 
  Bug, AlertCircle
} from 'lucide-react';
import { lookupIoc } from '../services/tauriIpc';

const IntelFeeds = ({ feeds = { iocs: [], cves: [], threat_actors: [] } }) => {
  const [activeTab, setActiveTab] = useState('iocs');
  const [searchQuery, setSearchQuery] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [isSearching, setIsSearching] = useState(false);
  const [copiedValue, setCopiedValue] = useState(null);

  const iocs = feeds?.iocs || [];
  const cves = feeds?.cves || [];
  const threatActors = feeds?.threat_actors || [];

  // Copy to clipboard helper
  const handleCopy = (val) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(val);
      setCopiedValue(val);
      setTimeout(() => setCopiedValue(null), 2000);
    }
  };

  // Perform IOC search & lookup via Tauri IPC
  const handleSearchSubmit = async (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    setIsSearching(true);
    try {
      const res = await lookupIoc(searchQuery.trim());
      setLookupResult(res);
    } catch (err) {
      console.error('IOC lookup failed:', err);
    } finally {
      setIsSearching(false);
    }
  };

  return (
    <div 
      id="intel-feeds-panel"
      className="intel-feeds-panel card"
      data-testid="intel-feeds"
      style={{
        display: 'flex',
        flexDirection: 'column',
        padding: 0,
        overflow: 'hidden',
        border: '1px solid var(--border-color)',
        borderRadius: '8px',
        background: 'var(--bg-card)'
      }}
    >
      {/* Panel Tabs Header */}
      <div 
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 16px',
          borderBottom: '1px solid var(--border-color)',
          background: 'var(--bg-main)'
        }}
      >
        <div style={{ display: 'flex', gap: '16px' }}>
          <button
            onClick={() => setActiveTab('iocs')}
            style={{
              background: 'none',
              border: 'none',
              color: activeTab === 'iocs' ? 'var(--text-primary)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'iocs' ? '2px solid var(--accent-blue)' : '2px solid transparent',
              paddingBottom: '6px',
              fontWeight: activeTab === 'iocs' ? 600 : 400,
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer'
            }}
          >
            <Crosshair size={14} color="var(--accent-blue)" />
            Indicators of Compromise ({iocs.length})
          </button>

          <button
            onClick={() => setActiveTab('cves')}
            style={{
              background: 'none',
              border: 'none',
              color: activeTab === 'cves' ? 'var(--text-primary)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'cves' ? '2px solid var(--accent-blue)' : '2px solid transparent',
              paddingBottom: '6px',
              fontWeight: activeTab === 'cves' ? 600 : 400,
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer'
            }}
          >
            <Bug size={14} color="var(--color-critical)" />
            CVE Vulnerabilities ({cves.length})
          </button>

          <button
            onClick={() => setActiveTab('actors')}
            style={{
              background: 'none',
              border: 'none',
              color: activeTab === 'actors' ? 'var(--text-primary)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'actors' ? '2px solid var(--accent-blue)' : '2px solid transparent',
              paddingBottom: '6px',
              fontWeight: activeTab === 'actors' ? 600 : 400,
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer'
            }}
          >
            <Users size={14} color="#a855f7" />
            Threat Actors ({threatActors.length})
          </button>
        </div>

        {/* IOC Lookup Form */}
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div style={{ position: 'relative' }}>
            <input 
              type="text"
              placeholder="Lookup IP, hash, or domain..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border-color)',
                borderRadius: '4px',
                color: 'var(--text-primary)',
                padding: '4px 8px 4px 24px',
                fontSize: '0.75rem',
                width: '210px',
                outline: 'none'
              }}
            />
            <Search size={12} color="var(--text-secondary)" style={{ position: 'absolute', left: '7px', top: '8px' }} />
          </div>
          <button 
            type="submit" 
            className="secondary-btn" 
            style={{ padding: '4px 8px', fontSize: '0.75rem' }}
            disabled={isSearching}
          >
            {isSearching ? 'Querying...' : 'Query'}
          </button>
        </form>
      </div>

      {/* Lookup Result Banner */}
      {lookupResult && (
        <div 
          style={{
            padding: '10px 16px',
            background: lookupResult.matched ? 'rgba(239, 68, 68, 0.12)' : 'rgba(59, 130, 246, 0.1)',
            borderBottom: '1px solid var(--border-color)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '0.75rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertCircle size={16} color={lookupResult.matched ? 'var(--color-critical)' : 'var(--accent-blue)'} />
            <span>
              Reputation for <strong>{lookupResult.indicator}</strong>: 
              <span className={`severity-badge ${lookupResult.reputation === 'MALICIOUS' ? 'critical' : lookupResult.reputation === 'SUSPICIOUS' ? 'high' : 'low'}`} style={{ margin: '0 6px' }}>
                {lookupResult.reputation}
              </span>
              (Confidence: {lookupResult.confidence}%) — {lookupResult.description}
            </span>
          </div>
          <button 
            onClick={() => setLookupResult(null)} 
            style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '0.8rem' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* TAB 1: Indicators of Compromise (IOCs) */}
      {activeTab === 'iocs' && (
        <div style={{ overflowX: 'auto', maxHeight: '320px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-main)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '8px 12px' }}>Type</th>
                <th style={{ padding: '8px 12px' }}>Indicator Value</th>
                <th style={{ padding: '8px 12px' }}>Threat Category</th>
                <th style={{ padding: '8px 12px' }}>Severity</th>
                <th style={{ padding: '8px 12px' }}>Confidence</th>
                <th style={{ padding: '8px 12px' }}>Tags</th>
                <th style={{ padding: '8px 12px', textAlign: 'center' }}>Copy</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc) => (
                <tr key={ioc?.id || Math.random()} className="hover-row">
                  <td style={{ padding: '8px 12px', fontWeight: 600 }}>{ioc?.ioc_type}</td>
                  <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                    {ioc?.value}
                  </td>
                  <td style={{ padding: '8px 12px', color: 'var(--text-secondary)' }}>{ioc?.threat_type}</td>
                  <td style={{ padding: '8px 12px' }}>
                    <span className={`severity-badge ${ioc?.severity || 'low'}`}>
                      {ioc?.severity}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px' }}>{ioc?.confidence}%</td>
                  <td style={{ padding: '8px 12px' }}>
                    <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                      {(ioc?.tags || []).map((tag) => (
                        <span key={tag} className="tech-badge" style={{ fontSize: '0.65rem' }}>
                          {tag}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td style={{ padding: '8px 12px', textAlign: 'center' }}>
                    <button
                      onClick={() => handleCopy(ioc?.value)}
                      className="page-btn"
                      style={{ margin: '0 auto' }}
                      title="Copy Indicator"
                    >
                      {copiedValue === ioc?.value ? <Check size={12} color="var(--color-success)" /> : <Copy size={12} />}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 2: CVE Vulnerabilities */}
      {activeTab === 'cves' && (
        <div style={{ overflowX: 'auto', maxHeight: '320px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-main)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '8px 12px' }}>CVE ID</th>
                <th style={{ padding: '8px 12px' }}>CVSS Score</th>
                <th style={{ padding: '8px 12px' }}>Severity</th>
                <th style={{ padding: '8px 12px' }}>Affected Infrastructure</th>
                <th style={{ padding: '8px 12px' }}>Vulnerability Description</th>
                <th style={{ padding: '8px 12px' }}>Published</th>
              </tr>
            </thead>
            <tbody>
              {cves.map((cve) => (
                <tr key={cve?.id || Math.random()} className="hover-row">
                  <td style={{ padding: '8px 12px', fontWeight: 700, color: 'var(--accent-blue)', whiteSpace: 'nowrap' }}>
                    {cve?.cve_id}
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span 
                      style={{ 
                        fontWeight: 700, 
                        color: cve?.cvss_score >= 9.0 ? 'var(--color-critical)' : 'var(--color-high)',
                        background: 'rgba(239, 68, 68, 0.1)',
                        padding: '2px 6px',
                        borderRadius: '4px'
                      }}
                    >
                      {cve?.cvss_score?.toFixed(1) || '0.0'}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <span className={`severity-badge ${cve?.severity || 'critical'}`}>
                      {cve?.severity}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px' }}>
                    <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                      {(cve?.affected_systems || []).map((sys) => (
                        <span key={sys} className="tech-badge" style={{ fontSize: '0.65rem' }}>
                          {sys}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', maxWidth: '380px' }}>
                    {cve?.description}
                  </td>
                  <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {cve?.published_date}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 3: Threat Actors (Zero Geographical Elements) */}
      {activeTab === 'actors' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px', padding: '16px', maxHeight: '320px', overflowY: 'auto' }}>
          {threatActors.map((actor) => (
            <div 
              key={actor?.id || Math.random()} 
              style={{
                background: 'var(--bg-main)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.85rem' }}>{actor?.name}</span>
                <span className="status-badge" style={{ fontSize: '0.6rem', color: '#a855f7', borderColor: '#a855f7' }}>
                  {actor?.origin}
                </span>
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                <strong>Aliases:</strong> {(actor?.aliases || []).join(', ')}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                <strong>Targeted Sectors:</strong> {(actor?.targeted_sectors || []).join(', ')}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                <strong>Motivation:</strong> {actor?.motivation}
              </div>
              <p style={{ margin: '4px 0 0 0', fontSize: '0.7rem', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                {actor?.description}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default IntelFeeds;
