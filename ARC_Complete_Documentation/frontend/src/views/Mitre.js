import React, { useState, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';

const Mitre = () => {
  const [mitreData, setMitreData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchMitre = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/v1/mitre/techniques');
        if (!response.ok) {
          throw new Error('MITRE data unavailable');
        }
        const data = await response.json();
        setMitreData(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    fetchMitre();
  }, []);

  return (
    <div style={{padding: '24px', display: 'flex', flexDirection: 'column', height: '100%', overflowY: 'auto'}}>
      <div className="page-header" style={{marginBottom: '24px'}}>
        <div className="page-title">
          <h2>MITRE ATT&CK</h2>
          <p>Explore technique coverage and detection mapping</p>
        </div>
      </div>

      <div className="card" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', height: '300px', color: 'var(--text-secondary)'}}>
        {loading ? 'Loading MITRE matrix...' : error ? error : (mitreData || 'No detection techniques mapped. Waiting for correlation data.')}
      </div>
    </div>
  );
};

export default Mitre;
