import React, { useState, useEffect } from 'react';
import { AlertTriangle, Clock, Server, Monitor, Crosshair, Target, CheckCircle, Search, Copy } from 'lucide-react';

const Investigations = () => {
  const [investigation, setInvestigation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchInvestigation = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/v1/cases/investigations');
        if (!response.ok) {
          throw new Error('Investigations unavailable');
        }
        const data = await response.json();
        setInvestigation(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    fetchInvestigation();
  }, []);

  return (
    <div style={{padding: '24px', display: 'flex', flexDirection: 'column', height: '100%', overflowY: 'auto'}}>
      <div className="page-header" style={{marginBottom: '24px'}}>
        <div className="page-title">
          <h2>Investigations</h2>
          <p style={{fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '8px'}}>Active Alert Investigations</p>
        </div>
      </div>

      <div className="card" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', height: '300px', color: 'var(--text-secondary)'}}>
        {loading ? 'Loading investigations...' : error ? error : (investigation || 'No investigations found. Waiting for case data.')}
      </div>
    </div>
  );
};

export default Investigations;
