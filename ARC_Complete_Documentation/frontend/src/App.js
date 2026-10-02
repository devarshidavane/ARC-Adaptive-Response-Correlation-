import React, { useState } from 'react';
import { 
  Search, Sun, Bell, LayoutDashboard, AlertTriangle, 
  SearchCode, FolderOpen, ShieldAlert, Activity, 
  Crosshair, Shield, Server, Users, Zap, BarChart2, 
  FileText, Settings
} from 'lucide-react';
import './App.css';

import Dashboard from './views/Dashboard';
import Alerts from './views/Alerts';
import Investigations from './views/Investigations';
import Detections from './views/Detections';
import ThreatIntel from './views/ThreatIntel';
import Mitre from './views/Mitre';
import Login from './views/Login';
import Hosts from './views/Hosts';

const Sidebar = ({ activeTab, setActiveTab }) => {
  const navItems = [
    { name: 'Dashboard', icon: <LayoutDashboard size={18} /> },
    { name: 'Alerts', icon: <AlertTriangle size={18} />, badge: '12' },
    { name: 'Investigations', icon: <SearchCode size={18} /> },
    { name: 'Cases', icon: <FolderOpen size={18} /> },
    { name: 'Detections', icon: <ShieldAlert size={18} /> },
    { name: 'Correlation', icon: <Activity size={18} /> },
    { name: 'Threat Intelligence', icon: <Crosshair size={18} /> },
    { name: 'MITRE ATT&CK', icon: <Shield size={18} /> },
    { name: 'Hosts', icon: <Server size={18} /> },
    { name: 'Users', icon: <Users size={18} /> },
    { name: 'Response', icon: <Zap size={18} /> },
    { name: 'Analytics', icon: <BarChart2 size={18} /> },
    { name: 'Reports', icon: <FileText size={18} /> },
    { name: 'System', icon: <Settings size={18} /> }
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <div style={{display:'flex', alignItems:'center'}}>
           <Shield className="logo-icon" size={32} />
           <div style={{marginLeft: '12px'}}>
             <h1 style={{color: 'white', margin: 0}}>ARC</h1>
             <div className="subtitle">Adaptive Response & Correlation</div>
           </div>
        </div>
      </div>
      <div className="sidebar-nav">
        {navItems.map(item => (
          <div 
            key={item.name} 
            className={`nav-item ${activeTab === item.name ? 'active' : ''}`}
            onClick={() => setActiveTab(item.name)}
          >
            {item.icon} {item.name} 
            {item.badge && <span className="badge">{item.badge}</span>}
          </div>
        ))}
      </div>
      <div className="sidebar-footer">
        <div style={{display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px'}}>
           <div className="avatar" style={{width:'24px', height:'24px', fontSize:'0.7rem'}}>A</div>
           <div>
             <div style={{color:'var(--text-primary)', fontWeight:'bold'}}>analyst01</div>
             <div style={{fontSize:'0.65rem'}}>SOC Analyst</div>
           </div>
        </div>
      </div>
    </div>
  );
};

const Topbar = ({ onLogout }) => {
  const [profileOpen, setProfileOpen] = useState(false);
  
  return (
    <div className="topbar">
      <div className="search-bar">
        <Search size={16} color="#9ca3af" />
        <input type="text" placeholder="Search alerts, hosts, users, IOCs, cases..." />
        <span className="shortcut">Ctrl K</span>
      </div>
      <div className="topbar-actions">
        <Sun size={20} className="topbar-icon" />
        <div className="topbar-icon">
          <Bell size={20} />
          <span style={{position:'absolute', top:'-4px', right:'-4px', background:'#ef4444', color:'white', fontSize:'10px', padding:'2px 4px', borderRadius:'4px'}}>12</span>
        </div>
        <div className="profile-section" onClick={() => setProfileOpen(!profileOpen)} style={{ cursor: 'pointer', position: 'relative' }}>
          <div className="avatar">A</div>
          <div className="profile-info">
            <span className="profile-name">analyst01</span>
            <span className="profile-role">SOC Analyst</span>
          </div>
          {profileOpen && (
            <div className="profile-dropdown">
              <button onClick={onLogout} className="dropdown-item">Logout</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const App = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return localStorage.getItem('arc_auth') === 'true';
  });
  const [activeTab, setActiveTab] = useState('Dashboard');

  const handleLogin = (username) => {
    setIsAuthenticated(true);
    localStorage.setItem('arc_auth', 'true');
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    localStorage.removeItem('arc_auth');
  };

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />;
  }

  const renderContent = () => {
    switch (activeTab) {
      case 'Dashboard': return <Dashboard />;
      case 'Alerts': return <Alerts />;
      case 'Investigations': return <Investigations />;
      case 'Detections': return <Detections />;
      case 'Threat Intelligence': return <ThreatIntel />;
      case 'MITRE ATT&CK': return <Mitre />;
      case 'Hosts': return <Hosts />;
      default: return (
        <div style={{padding: '40px', textAlign: 'center', color: '#9ca3af', marginTop: '10vh'}}>
          <h2 style={{color: 'white', marginBottom: '10px'}}>{activeTab}</h2>
          <p>This module is under construction.</p>
        </div>
      );
    }
  };

  return (
    <div className="dashboard-layout">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <div className="main-content">
        <Topbar onLogout={handleLogout} />
        {renderContent()}
      </div>
    </div>
  );
};

export default App;
