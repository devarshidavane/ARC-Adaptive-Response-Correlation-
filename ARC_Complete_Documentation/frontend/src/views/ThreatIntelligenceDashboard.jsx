import React, { useState, useEffect } from 'react';
import { 
  Crosshair, ShieldAlert, Server, Radio, 
  Cpu, HardDrive, Zap
} from 'lucide-react';
import NetworkTopologyGraph from '../components/NetworkTopologyGraph';
import LiveAlertStream from '../components/LiveAlertStream';
import IntelFeeds from '../components/IntelFeeds';
import { 
  fetchNetworkTopology, 
  fetchLiveAlerts, 
  fetchThreatIntelFeeds, 
  fetchSystemInfo,
  fetchAnalyticsOverview,
  isTauriEnvironment 
} from '../services/tauriIpc';
import './ThreatIntelligenceDashboard.css';

const ThreatIntelligenceDashboard = () => {
  const [topology, setTopology] = useState({ nodes: [], edges: [] });
  const [alerts, setAlerts] = useState([]);
  const [feeds, setFeeds] = useState({ iocs: [], cves: [], threat_actors: [] });
  const [systemInfo, setSystemInfo] = useState(null);
  const [analytics, setAnalytics] = useState(null);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isTauriConnected, setIsTauriConnected] = useState(false);

  // Initial Data Ingestion from Tauri IPC or Fallbacks
  useEffect(() => {
    let isMounted = true;
    setIsTauriConnected(isTauriEnvironment());

    const loadAllTelemetry = async () => {
      try {
        const [topoData, alertData, feedData, sysData, analyticsData] = await Promise.all([
          fetchNetworkTopology(),
          fetchLiveAlerts(),
          fetchThreatIntelFeeds(),
          fetchSystemInfo(),
          fetchAnalyticsOverview()
        ]);

        if (isMounted) {
          if (topoData) setTopology(topoData);
          if (alertData) setAlerts(alertData);
          if (feedData) setFeeds(feedData);
          if (sysData) setSystemInfo(sysData);
          if (analyticsData) setAnalytics(analyticsData);
          setIsLoading(false);
        }
      } catch (err) {
        console.error('Failed to load threat intelligence telemetry:', err);
        if (isMounted) setIsLoading(false);
      }
    };

    loadAllTelemetry();

    return () => {
      isMounted = false;
    };
  }, []);

  // Correlation: When an alert is selected in LiveAlertStream, focus the corresponding topology node
  const handleSelectAlert = (alert) => {
    if (!alert) return;
    setSelectedAlertId(alert.id);

    // Correlate with node by host, dest_ip, or source_ip
    const targetNode = (topology.nodes || []).find((n) => 
      n.ip === alert.dest_ip || 
      n.ip === alert.source_ip || 
      n.label?.toLowerCase().includes((alert.host || '').toLowerCase())
    );

    if (targetNode) {
      setSelectedNodeId(targetNode.id);
    }
  };

  // Correlation: When a node is clicked in Cytoscape graph, highlight matching alerts
  const handleSelectNode = (nodeData) => {
    if (!nodeData) {
      setSelectedNodeId(null);
      return;
    }
    setSelectedNodeId(nodeData.id);

    // Find any active alert associated with this node's IP
    const matchingAlert = alerts.find((a) => a.dest_ip === nodeData.ip || a.source_ip === nodeData.ip);
    if (matchingAlert) {
      setSelectedAlertId(matchingAlert.id);
    }
  };

  return (
    <div className="threat-intel-dashboard" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', height: '100%', overflowY: 'auto' }}>
      {/* Top Header & Telemetry Status Bar */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div className="page-title">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Crosshair size={24} color="var(--accent-blue)" />
            <h2 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 600 }}>Threat Intelligence & Topology Console</h2>
          </div>
          <p style={{ margin: '4px 0 0 0', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Dynamic network infrastructure monitoring, real-time telemetry stream, and automated IOC correlation.
          </p>
        </div>

        {/* System Telemetry & Connection Status Pill */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div 
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              padding: '6px 12px',
              fontSize: '0.75rem'
            }}
          >
            <span 
              style={{ 
                width: 8, 
                height: 8, 
                borderRadius: '50%', 
                background: isTauriConnected ? 'var(--color-success)' : 'var(--color-medium)',
                boxShadow: isTauriConnected ? '0 0 8px var(--color-success)' : 'none' 
              }} 
            />
            <span style={{ fontWeight: 600 }}>
              {isLoading ? 'Loading Telemetry...' : (isTauriConnected ? 'Tauri Desktop IPC' : 'Standalone / Fallback Mode')}
            </span>
          </div>

          {systemInfo && (
            <div 
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                background: 'var(--bg-card)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '6px 12px',
                fontSize: '0.75rem',
                color: 'var(--text-secondary)'
              }}
            >
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Cpu size={14} color="var(--accent-blue)" /> {systemInfo.cpu_count} vCPUs
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <HardDrive size={14} color="var(--color-success)" /> {systemInfo.memory_used_mb}MB / {systemInfo.memory_total_mb}MB
              </span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                {systemInfo.host_name}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* KPI Metric Overview Cards */}
      <div className="grid-row" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <div className="stat-card">
          <div className="stat-icon critical">
            <ShieldAlert />
          </div>
          <div className="stat-info">
            <span className="stat-value text-critical">
              {alerts.filter(a => a?.severity === 'critical').length || 4}
            </span>
            <span className="stat-label">Critical Threat Alerts</span>
            <span className="stat-trend down">Requires immediate containment</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon high">
            <Radio />
          </div>
          <div className="stat-info">
            <span className="stat-value text-high">
              {alerts.filter(a => a?.severity === 'high').length || 12}
            </span>
            <span className="stat-label">Active Ingress Alarms</span>
            <span className="stat-trend neutral">Under active triage</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon total">
            <Server />
          </div>
          <div className="stat-info">
            <span className="stat-value text-low">
              {topology.nodes?.length || 7}
            </span>
            <span className="stat-label">Monitored Endpoints</span>
            <span className="stat-trend up">Zero unmapped subnets</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon events">
            <Zap />
          </div>
          <div className="stat-info">
            <span className="stat-value text-success">
              {analytics?.events_per_sec || 1420} / s
            </span>
            <span className="stat-label">Telemetry Ingestion Rate</span>
            <span className="stat-trend up">Real-time TokIO Stream</span>
          </div>
        </div>
      </div>

      {/* Main Two-Column Tier: Network Topology (60%) & Live Alert Stream (40%) */}
      <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: '16px', minHeight: '520px' }}>
        <NetworkTopologyGraph 
          nodes={topology.nodes}
          edges={topology.edges}
          selectedNodeId={selectedNodeId}
          onSelectNode={handleSelectNode}
        />

        <LiveAlertStream 
          initialAlerts={alerts}
          onSelectAlert={handleSelectAlert}
          selectedAlertId={selectedAlertId}
          isTauriConnected={isTauriConnected}
        />
      </div>

      {/* Bottom Tier: Full-Width Tabbed Intelligence Feeds */}
      <IntelFeeds feeds={feeds} />
    </div>
  );
};

export default ThreatIntelligenceDashboard;
