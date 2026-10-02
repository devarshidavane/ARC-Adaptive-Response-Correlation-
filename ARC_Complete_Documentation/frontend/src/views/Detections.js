import React, { useState, useEffect } from 'react';
import { Trash2, Ban, Save, Search, Play } from 'lucide-react';

const Detections = () => {
  const [rules, setRules] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchRules = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/v1/detections/rules');
        if (!response.ok) {
          throw new Error('Detection rules unavailable');
        }
        const data = await response.json();
        setRules(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    fetchRules();
  }, []);

  return (
    <div style={{padding: '24px', display: 'flex', flexDirection: 'column', height: '100%', overflowY: 'auto'}}>
      <div className="page-header" style={{marginBottom: '24px'}}>
        <div className="page-title">
          <h2>Detection Rules</h2>
          <p style={{fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '8px'}}>Manage and author detection logic</p>
        </div>
      </div>

      <div className="card" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', height: '300px', color: 'var(--text-secondary)'}}>
        {loading ? 'Loading detection rules...' : error ? error : (rules || 'No detection rules found.')}
      </div>
    </div>
  );
};

export default Detections;
