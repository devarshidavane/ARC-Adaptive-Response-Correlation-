import React, { useState } from 'react';
import { Server, Plus, Trash2 } from 'lucide-react';

const Hosts = () => {
  const [hosts, setHosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [newHostName, setNewHostName] = useState('');
  const [newHostIp, setNewHostIp] = useState('');
  const [newHostType, setNewHostType] = useState('Windows');

  React.useEffect(() => {
    const fetchHosts = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/v1/hosts');
        if (!response.ok) throw new Error('Hosts unavailable');
        const data = await response.json();
        setHosts(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchHosts();
  }, []);

  const handleAddHost = (e) => {
    e.preventDefault();
    // TODO: implement API post
  };

  const handleRemoveHost = (id) => {
    // TODO: implement API delete
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Server size={24} /> Monitored Hosts & Devices
        </h2>
        <p style={{ color: 'var(--text-secondary)' }}>
          Manage systems that send telemetry to ARC.
        </p>
      </div>

      <div style={{ display: 'flex', gap: '20px', marginTop: '20px' }}>
        <div className="card" style={{ flex: '1' }}>
          <h3 style={{ marginBottom: '15px' }}>Current Devices</h3>
          <table className="hosts-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left' }}>
                <th style={{ padding: '10px' }}>Name</th>
                <th style={{ padding: '10px' }}>IP Address</th>
                <th style={{ padding: '10px' }}>Type</th>
                <th style={{ padding: '10px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map(host => (
                <tr key={host.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '10px' }}>{host.name}</td>
                  <td style={{ padding: '10px' }}>{host.ip}</td>
                  <td style={{ padding: '10px' }}>{host.type}</td>
                  <td style={{ padding: '10px' }}>
                    <button 
                      onClick={() => handleRemoveHost(host.id)}
                      className="icon-button"
                      style={{ color: '#ef4444', cursor: 'pointer', background: 'none', border: 'none' }}
                      title="Remove Device"
                    >
                      <Trash2 size={16} />
                    </button>
                  </td>
                </tr>
              ))}
              {hosts.length === 0 && (
                <tr>
                  <td colSpan="4" style={{ padding: '10px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                    No devices monitored. Add one below.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card" style={{ width: '300px' }}>
          <h3 style={{ marginBottom: '15px' }}>Add Device</h3>
          <form onSubmit={handleAddHost} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '5px', fontSize: '0.85rem' }}>Device Name</label>
              <input 
                type="text" 
                value={newHostName} 
                onChange={(e) => setNewHostName(e.target.value)} 
                placeholder="e.g., SRV-DB-01" 
                style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '5px', fontSize: '0.85rem' }}>IP Address</label>
              <input 
                type="text" 
                value={newHostIp} 
                onChange={(e) => setNewHostIp(e.target.value)} 
                placeholder="e.g., 192.168.1.100" 
                style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '5px', fontSize: '0.85rem' }}>Type</label>
              <select 
                value={newHostType} 
                onChange={(e) => setNewHostType(e.target.value)}
                style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}
              >
                <option value="Windows">Windows</option>
                <option value="Linux">Linux</option>
                <option value="Network">Network</option>
                <option value="Other">Other</option>
              </select>
            </div>
            <button 
              type="submit" 
              style={{ padding: '10px', background: 'var(--accent-color)', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '5px' }}
            >
              <Plus size={16} /> Add Device
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Hosts;
