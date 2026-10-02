import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, Pause, Zap, Filter, CheckCircle2, 
  Radio, ArrowRight
} from 'lucide-react';
import { listen, acknowledgeAlert, simulateAlertEvent } from '../services/tauriIpc';

const MAX_ALERTS = 100; // Ring-buffer limit to safeguard memory (TC-T2-F5-01)

const LiveAlertStream = ({ 
  initialAlerts = [], 
  onSelectAlert = () => {}, 
  selectedAlertId = null,
  isTauriConnected = false 
}) => {
  const [alerts, setAlerts] = useState(initialAlerts || []);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [isStreaming, setIsStreaming] = useState(true);
  const [streamFrequencyMs, setStreamFrequencyMs] = useState(4000);
  const [lastAckId, setLastAckId] = useState(null);
  const simulatorTimerRef = useRef(null);

  // Sync initial alerts
  useEffect(() => {
    if (initialAlerts && initialAlerts.length > 0) {
      setAlerts(initialAlerts.slice(0, MAX_ALERTS));
    }
  }, [initialAlerts]);

  // Handle incoming live alerts (with defensive access and buffer limiting)
  const handleIncomingAlert = (newAlert) => {
    if (!newAlert) return;
    setAlerts((prevAlerts) => {
      // Deduplicate by ID
      const filtered = prevAlerts.filter((a) => a?.id !== newAlert.id);
      return [newAlert, ...filtered].slice(0, MAX_ALERTS);
    });
  };

  // Listen to Tauri native IPC Tokio background stream (TC-T1-F5-05, TC-T3-05)
  useEffect(() => {
    let unlistenFn = null;

    const setupListener = async () => {
      unlistenFn = await listen('threat_alert_stream', (event) => {
        if (isStreaming && event?.payload) {
          handleIncomingAlert(event.payload);
        }
      });
    };

    setupListener();

    return () => {
      if (typeof unlistenFn === 'function') {
        unlistenFn();
      }
    };
  }, [isStreaming]);

  // In-Client Streaming Simulator (for offline standalone & automated testing)
  useEffect(() => {
    if (!isStreaming) {
      if (simulatorTimerRef.current) clearInterval(simulatorTimerRef.current);
      return;
    }

    simulatorTimerRef.current = setInterval(async () => {
      try {
        const simulated = await simulateAlertEvent();
        if (simulated) {
          handleIncomingAlert(simulated);
        }
      } catch (err) {
        console.warn('Simulator error:', err);
      }
    }, streamFrequencyMs);

    return () => {
      if (simulatorTimerRef.current) clearInterval(simulatorTimerRef.current);
    };
  }, [isStreaming, streamFrequencyMs]);

  // Acknowledge Alert Handler
  const handleAcknowledge = async (e, alertId) => {
    e.stopPropagation();
    try {
      await acknowledgeAlert(alertId);
      setLastAckId(alertId);
      setAlerts((prev) => 
        prev.map((a) => a?.id === alertId ? { ...a, status: 'ACKNOWLEDGED' } : a)
      );
    } catch (err) {
      console.error('Ack failed:', err);
    }
  };

  // Manual Trigger Alert Injection
  const handleManualTrigger = async () => {
    const injected = await simulateAlertEvent();
    if (injected) {
      handleIncomingAlert(injected);
      onSelectAlert(injected);
    }
  };

  // Filter alerts by severity (TC-T2-F5-03)
  const filteredAlerts = alerts.filter((alert) => {
    if (!alert) return false;
    if (severityFilter === 'all') return true;
    const sev = (alert?.severity || '').toLowerCase();
    return sev === severityFilter.toLowerCase();
  });

  return (
    <div 
      id="live-alerts-panel"
      className="live-alerts-panel card"
      data-testid="live-alerts"
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        padding: 0,
        overflow: 'hidden',
        border: '1px solid var(--border-color)',
        borderRadius: '8px',
        background: 'var(--bg-card)'
      }}
    >
      {/* Panel Header & Controls */}
      <div 
        style={{
          padding: '12px 16px',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '8px'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Radio 
            size={18} 
            color={isStreaming ? 'var(--color-critical)' : 'var(--text-secondary)'} 
            style={{ animation: isStreaming ? 'pulse 2s infinite' : 'none' }}
          />
          <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Live Threat Alert Stream</span>
          <span 
            className="status-badge"
            style={{ 
              fontSize: '0.65rem',
              color: isTauriConnected ? 'var(--color-success)' : 'var(--color-medium)',
              borderColor: isTauriConnected ? 'var(--color-success)' : 'var(--color-medium)'
            }}
          >
            {isTauriConnected ? 'Tauri IPC Connected' : 'Offline / Standalone Simulator'}
          </span>
        </div>

        {/* Simulator Controls & Speed */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={() => setIsStreaming(!isStreaming)}
            className="secondary-btn"
            style={{ padding: '4px 10px', fontSize: '0.75rem', gap: '4px' }}
            title={isStreaming ? 'Pause Alert Stream' : 'Resume Alert Stream'}
          >
            {isStreaming ? <Pause size={12} /> : <Play size={12} />}
            {isStreaming ? 'Pause' : 'Resume'}
          </button>

          <select
            value={streamFrequencyMs}
            onChange={(e) => setStreamFrequencyMs(Number(e.target.value))}
            style={{
              background: 'var(--bg-main)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '4px',
              padding: '4px 6px',
              fontSize: '0.75rem',
              cursor: 'pointer'
            }}
            title="Stream Generation Interval"
          >
            <option value={1500}>1.5s Burst</option>
            <option value={3000}>3.0s Standard</option>
            <option value={5000}>5.0s Normal</option>
          </select>

          <button
            onClick={handleManualTrigger}
            className="primary-btn"
            style={{ padding: '4px 10px', fontSize: '0.75rem', gap: '4px' }}
            title="Inject Simulated Telemetry Event"
          >
            <Zap size={12} />
            Simulate
          </button>
        </div>
      </div>

      {/* Severity Filter Tabs */}
      <div 
        style={{
          display: 'flex',
          gap: '6px',
          padding: '8px 16px',
          background: 'rgba(0,0,0,0.2)',
          borderBottom: '1px solid var(--border-color)',
          fontSize: '0.75rem'
        }}
      >
        <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px', marginRight: '6px' }}>
          <Filter size={12} /> Filter:
        </span>
        {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            style={{
              background: severityFilter === sev ? 'var(--accent-blue)' : 'transparent',
              color: severityFilter === sev ? 'white' : 'var(--text-secondary)',
              border: '1px solid',
              borderColor: severityFilter === sev ? 'var(--accent-blue)' : 'var(--border-color)',
              borderRadius: '4px',
              padding: '2px 8px',
              fontSize: '0.7rem',
              textTransform: 'capitalize',
              cursor: 'pointer'
            }}
          >
            {sev}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', color: 'var(--text-secondary)', fontSize: '0.7rem' }}>
          Showing {filteredAlerts.length} of {alerts.length} (Max buffer {MAX_ALERTS})
        </span>
      </div>

      {/* Alert Stream List / Table Container */}
      <div style={{ flexGrow: 1, overflowY: 'auto', maxHeight: '430px' }}>
        {filteredAlerts.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
            No alerts matching current severity filter. Waiting for incoming telemetry events...
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-main)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '8px 12px' }}>Severity</th>
                <th style={{ padding: '8px 12px' }}>Incident Title</th>
                <th style={{ padding: '8px 12px' }}>Source → Target</th>
                <th style={{ padding: '8px 12px' }}>MITRE Technique</th>
                <th style={{ padding: '8px 12px' }}>Time</th>
                <th style={{ padding: '8px 12px', textAlign: 'center' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert) => {
                const isSelected = selectedAlertId === alert?.id;
                const severity = alert?.severity || 'low';
                const sourceIp = alert?.source_ip || alert?.ip_address || '-';
                const destIp = alert?.dest_ip || alert?.destination_ip || '-';
                const technique = alert?.mitre_technique || alert?.technique || '-';
                const isAcked = alert?.status === 'ACKNOWLEDGED' || lastAckId === alert?.id;

                return (
                  <tr
                    key={alert?.id || Math.random()}
                    onClick={() => onSelectAlert(alert)}
                    className="hover-row"
                    style={{
                      cursor: 'pointer',
                      background: isSelected ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                      borderLeft: isSelected ? '3px solid var(--accent-blue)' : '3px solid transparent',
                      transition: 'background 0.15s ease'
                    }}
                  >
                    <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                      <span className={`severity-badge ${severity}`}>
                        {severity}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', fontWeight: 600 }}>
                      <div style={{ color: 'var(--text-primary)' }}>{alert?.title || 'Unknown Alert'}</div>
                      <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>ID: {alert?.id}</div>
                    </td>
                    <td style={{ padding: '8px 12px', whiteSpace: 'nowrap', fontFamily: 'monospace' }}>
                      <span style={{ color: 'var(--text-primary)' }}>{sourceIp}</span>
                      <ArrowRight size={10} style={{ margin: '0 4px', color: 'var(--text-secondary)' }} />
                      <span style={{ color: severity === 'critical' ? 'var(--color-critical)' : 'var(--text-primary)' }}>{destIp}</span>
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      <span className="tech-badge" style={{ fontSize: '0.65rem' }}>
                        {technique}
                      </span>
                    </td>
                    <td style={{ padding: '8px 12px', color: 'var(--text-secondary)', whiteSpace: 'nowrap', fontSize: '0.7rem' }}>
                      {alert?.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '-'}
                    </td>
                    <td style={{ padding: '8px 12px', textAlign: 'center' }}>
                      {isAcked ? (
                        <span style={{ color: 'var(--color-success)', display: 'inline-flex', alignItems: 'center', gap: '2px', fontSize: '0.65rem' }}>
                          <CheckCircle2 size={12} /> Acked
                        </span>
                      ) : (
                        <button
                          onClick={(e) => handleAcknowledge(e, alert?.id)}
                          className="secondary-btn"
                          style={{ padding: '2px 6px', fontSize: '0.65rem' }}
                          title="Acknowledge Alert"
                        >
                          Ack
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default LiveAlertStream;
