import React, { useState, useEffect } from 'react';
import { AlertTriangle, ChevronDown, MoreHorizontal, Filter } from 'lucide-react';

const Alerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/v1/alerts');
        if (!response.ok) {
          throw new Error('Failed to fetch alerts');
        }
        const data = await response.json();
        setAlerts(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    fetchAlerts();
  }, []);

  return (
    <div style={{padding: '24px', display: 'flex', flexDirection: 'column', height: '100%'}}>
      <div className="page-header" style={{marginBottom: '16px'}}>
        <div className="page-title">
          <h2>Alerts</h2>
          <p>Monitor, triage and investigate security alerts</p>
        </div>
        <div className="header-controls">
          <button className="primary-btn">+ Create Case</button>
        </div>
      </div>

      <div className="filters-bar" style={{display: 'flex', gap: '12px', marginBottom: '16px'}}>
        {['Severity', 'Status', 'Source', 'Host', 'MITRE Technique'].map(f => (
          <div key={f} className="dropdown-btn" style={{backgroundColor: 'transparent'}}>
            {f} <ChevronDown size={14}/>
          </div>
        ))}
        <div className="dropdown-btn" style={{marginLeft: 'auto'}}>Last 24 hours <ChevronDown size={14}/></div>
      </div>

      <div className="card" style={{flexGrow: 1, padding: 0, overflow: 'hidden'}}>
        <div className="table-container" style={{height: '100%', overflowY: 'auto'}}>
          <table style={{width: '100%'}}>
            <thead style={{position: 'sticky', top: 0, backgroundColor: 'var(--bg-card)', zIndex: 1}}>
              <tr>
                <th style={{width:'40px'}}><input type="checkbox" /></th>
                <th>Time</th>
                <th>Severity</th>
                <th>Title</th>
                <th>Source</th>
                <th>Host</th>
                <th>Technique</th>
                <th>Status</th>
                <th>Risk</th>
                <th style={{width:'40px'}}></th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan="10" style={{textAlign: 'center', padding: '24px', color: 'var(--text-secondary)'}}>Loading alerts...</td></tr>}
              {!loading && error && <tr><td colSpan="10" style={{textAlign: 'center', padding: '24px', color: 'var(--color-critical)'}}>Unable to load alerts: {error}</td></tr>}
              {!loading && !error && alerts.length === 0 && <tr><td colSpan="10" style={{textAlign: 'center', padding: '24px', color: 'var(--text-secondary)'}}>No alert data available. Waiting for telemetry.</td></tr>}
              
              {!loading && !error && alerts.map((a, i) => (
                <tr key={a.id || i} className="hover-row">
                  <td><input type="checkbox" /></td>
                  <td style={{color: '#9ca3af', whiteSpace: 'nowrap'}}>{new Date(a.created_at).toLocaleTimeString()}</td>
                  <td><span className={`severity-badge ${a.severity.toLowerCase()}`}>{a.severity}</span></td>
                  <td style={{fontWeight: '500', color: 'var(--text-primary)'}}>{a.title}</td>
                  <td style={{color: '#9ca3af'}}>{a.source || 'N/A'}</td>
                  <td style={{color: '#9ca3af'}}>{a.host || 'N/A'}</td>
                  <td><span className="tech-badge">{a.mitre_technique || 'None'}</span></td>
                  <td><span className={`status-badge ${a.status.toLowerCase()}`}>{a.status}</span></td>
                  <td>
                     <div style={{
                       backgroundColor: a.risk_score > 80 ? 'var(--color-critical)' : (a.risk_score > 60 ? 'var(--color-high)' : (a.risk_score > 40 ? 'var(--color-medium)' : 'var(--color-low)')),
                       color: 'white', padding: '2px 6px', borderRadius: '4px', textAlign: 'center', width: '30px', fontSize: '0.75rem', fontWeight: 'bold'
                     }}>
                       {a.risk_score}
                     </div>
                  </td>
                  <td><MoreHorizontal size={16} color="#9ca3af" style={{cursor: 'pointer'}}/></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="pagination-bar" style={{padding: '12px 16px', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: '#9ca3af'}}>
          <div>Showing {alerts.length} alerts</div>
        </div>
      </div>
    </div>
  );
};

export default Alerts;
