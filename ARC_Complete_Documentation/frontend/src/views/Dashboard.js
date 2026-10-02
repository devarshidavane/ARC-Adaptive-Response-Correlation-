import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, ShieldAlert, Shield, ActivitySquare, FolderOpen, Activity, ChevronDown 
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar
} from 'recharts';
import { fetchAnalyticsOverview } from '../services/tauriIpc';

const Dashboard = () => {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        // Use tauriIpc so offline/fallback data is available when the Python backend is down
        const data = await fetchAnalyticsOverview();
        if (!data) throw new Error('No dashboard telemetry returned');
        setMetrics(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    fetchMetrics();
  }, []);

  if (loading) {
    return <div style={{padding: '40px', textAlign: 'center', color: 'var(--text-secondary)'}}>Loading dashboard telemetry...</div>;
  }

  if (error) {
    return <div style={{padding: '40px', textAlign: 'center', color: 'var(--color-critical)'}}>Error loading dashboard: {error}</div>;
  }

  if (!metrics) {
    return <div style={{padding: '40px', textAlign: 'center', color: 'var(--text-secondary)'}}>No dashboard data available.</div>;
  }

  return (
    <div className="dashboard-scroll">
      <div className="page-header">
        <div className="page-title">
          <h2>Security Operations Dashboard</h2>
          <p>Live visibility across your environment</p>
        </div>
        <div className="header-controls">
          <div className="time-display">
            <div className="date">{new Date().toLocaleDateString()}</div>
            <div className="time">{new Date().toLocaleTimeString()}</div>
          </div>
          <div className="dropdown-btn">Last 24 hours <ChevronDown size={14} /></div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid-row">
        <div className="stat-card">
          <div className="stat-icon critical"><AlertTriangle /></div>
          <div className="stat-info">
            <span className="stat-value text-critical">{metrics.critical_alerts || 0}</span>
            <span className="stat-label">Critical Alerts</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon high"><ShieldAlert /></div>
          <div className="stat-info">
            <span className="stat-value text-high">{metrics.high_alerts || 0}</span>
            <span className="stat-label">High Alerts</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon total"><Shield /></div>
          <div className="stat-info">
            <span className="stat-value" style={{color:'#3b82f6'}}>{metrics.total_alerts || 0}</span>
            <span className="stat-label">Total Alerts</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon events"><ActivitySquare /></div>
          <div className="stat-info">
            <span className="stat-value">{metrics.events_per_sec || 0}</span>
            <span className="stat-label">Events / sec</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon cases"><FolderOpen /></div>
          <div className="stat-info">
            <span className="stat-value">{metrics.open_cases || 0}</span>
            <span className="stat-label">Open Cases</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon health"><Activity /></div>
          <div className="stat-info">
            <span className="stat-value">{metrics.system_health_pct || 100}%</span>
            <span className="stat-label">System Health</span>
          </div>
        </div>
      </div>

      <div className="grid-row" style={{height: '300px'}}>
        <div className="card flex-1" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)'}}>
          [Event Ingestion Chart - Awaiting Telemetry Stream]
        </div>

        <div className="card flex-1" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)'}}>
          [Detection Activity Chart - Awaiting Alert Aggregation]
        </div>
      </div>

      <div className="grid-row" style={{height: '280px'}}>
         <div className="card flex-1" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)'}}>
           [Top MITRE ATT&CK Techniques - Awaiting Data]
         </div>

         <div className="card flex-1" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)'}}>
           [Alert Sources - Awaiting Data]
         </div>

         <div className="card flex-1" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)'}}>
           [Top Targeted Hosts - Awaiting Data]
         </div>
      </div>
    </div>
  );
};

export default Dashboard;
