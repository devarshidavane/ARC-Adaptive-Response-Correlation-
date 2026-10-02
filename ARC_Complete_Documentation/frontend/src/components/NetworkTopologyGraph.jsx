import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { 
  ZoomIn, ZoomOut, Maximize2, RotateCcw, 
  Radio, Activity
} from 'lucide-react';

/**
 * Dynamic Network Topology Graph Component
 * Enterprise Cytoscape.js canvas visualization with dark-mode SOC styling.
 */
const NetworkTopologyGraph = ({ 
  nodes = [], 
  edges = [], 
  selectedNodeId = null, 
  onSelectNode = () => {},
  className = '' 
}) => {
  const graphContainerRef = useRef(null);
  const cyRef = useRef(null);
  const [layoutMode, setLayoutMode] = useState('cose');
  const [selectedNodeDetails, setSelectedNodeDetails] = useState(null);
  const onSelectNodeRef = useRef(onSelectNode);
  useEffect(() => {
    onSelectNodeRef.current = onSelectNode;
  });

  // Initialize Cytoscape Instance
  useEffect(() => {
    if (!graphContainerRef.current) return;

    // Graceful degradation for empty topology datasets (TC-T2-F3-01)
    if (!nodes || nodes.length === 0) {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
      return;
    }

    // Transform raw nodes to Cytoscape elements with defensive property fallbacks
    const cyNodes = (nodes || []).map((node) => {
      const id = node?.id || `node-${Math.random()}`;
      const label = node?.label || id;
      const nodeType = node?.type || node?.node_type || 'workstation';
      const status = node?.status || 'normal';
      const subnet = node?.subnet || node?.zone || '10.0.0.0/24';
      const ip = node?.ip || node?.ip_address || '10.0.0.x';

      return {
        data: {
          id,
          label: `${label}\n[${ip}]`,
          rawLabel: label,
          nodeType,
          status,
          subnet,
          ip,
          threatLevel: status === 'compromised' ? 'critical' : status === 'investigating' ? 'high' : 'normal'
        }
      };
    });

    // Transform edges with defensive property fallbacks
    const cyEdges = (edges || []).map((edge, index) => {
      const id = edge?.id || `edge-${index}`;
      const source = edge?.source || '';
      const target = edge?.target || '';
      const protocol = edge?.protocol || 'TCP';
      const threatLevel = edge?.threat_level || edge?.threat || edge?.status || 'normal';

      return {
        data: {
          id,
          source,
          target,
          protocol,
          threatLevel,
          label: protocol
        }
      };
    });

    // Destroy existing instance before recreation
    if (cyRef.current) {
      cyRef.current.destroy();
    }

    // Initialize Cytoscape with enterprise SOC dark styling
    const cy = cytoscape({
      container: graphContainerRef.current,
      elements: [...cyNodes, ...cyEdges],
      boxSelectionEnabled: false,
      autounselectify: false,
      style: [
        // Base Node Style
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#f3f4f6',
            'font-family': 'Inter, sans-serif',
            'font-size': '11px',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-wrap': 'wrap',
            'background-color': '#1f2937',
            'border-width': 2,
            'border-color': '#3b82f6',
            'width': 42,
            'height': 42,
            'text-background-opacity': 0.85,
            'text-background-color': '#06090e',
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'transition-property': 'background-color, border-color, border-width, width, height',
            'transition-duration': '0.3s'
          }
        },
        // Node Taxonomy: Workstation
        {
          selector: 'node[nodeType = "workstation"]',
          style: {
            'shape': 'ellipse',
            'background-color': '#1e293b',
            'border-color': '#64748b'
          }
        },
        // Node Taxonomy: Server
        {
          selector: 'node[nodeType = "server"]',
          style: {
            'shape': 'roundrectangle',
            'background-color': '#0f172a',
            'border-color': '#3b82f6',
            'width': 46,
            'height': 46
          }
        },
        // Node Taxonomy: Firewall
        {
          selector: 'node[nodeType = "firewall"]',
          style: {
            'shape': 'diamond',
            'background-color': '#2a1a08',
            'border-color': '#f97316',
            'width': 50,
            'height': 50
          }
        },
        // Node Taxonomy: Router
        {
          selector: 'node[nodeType = "router"]',
          style: {
            'shape': 'hexagon',
            'background-color': '#1a102e',
            'border-color': '#a855f7',
            'width': 44,
            'height': 44
          }
        },
        // Node Taxonomy: C2 Threat Actor Node
        {
          selector: 'node[nodeType = "c2_server"]',
          style: {
            'shape': 'octagon',
            'background-color': '#450a0a',
            'border-color': '#ef4444',
            'border-width': 3,
            'width': 52,
            'height': 52
          }
        },
        // Status: Compromised (Active Threat Indicator)
        {
          selector: 'node[status = "compromised"]',
          style: {
            'border-color': '#ef4444',
            'border-width': 4,
            'background-color': '#7f1d1d'
          }
        },
        // Status: Investigating
        {
          selector: 'node[status = "investigating"]',
          style: {
            'border-color': '#eab308',
            'border-width': 3,
            'background-color': '#422006'
          }
        },
        // Selected / Focused Node State
        {
          selector: 'node:selected',
          style: {
            'border-color': '#00f0ff',
            'border-width': 5,
            'width': 56,
            'height': 56,
            'text-background-color': '#0f766e',
            'text-background-opacity': 1
          }
        },
        // Edge Base Style
        {
          selector: 'edge',
          style: {
            'width': 2,
            'curve-style': 'bezier',
            'line-color': '#4b5563',
            'target-arrow-shape': 'triangle',
            'target-arrow-color': '#4b5563',
            'arrow-scale': 1.1,
            'label': 'data(label)',
            'font-family': 'Inter, sans-serif',
            'font-size': '9px',
            'color': '#9ca3af',
            'text-background-opacity': 0.8,
            'text-background-color': '#0a0f18',
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle'
          }
        },
        // Edge Threat Level: Critical
        {
          selector: 'edge[threatLevel = "critical"]',
          style: {
            'width': 3.5,
            'line-color': '#ef4444',
            'target-arrow-color': '#ef4444',
            'line-style': 'dashed',
            'color': '#fca5a5'
          }
        },
        // Edge Threat Level: High
        {
          selector: 'edge[threatLevel = "high"]',
          style: {
            'width': 3,
            'line-color': '#f97316',
            'target-arrow-color': '#f97316',
            'color': '#fdba74'
          }
        },
        // Edge Threat Level: Medium
        {
          selector: 'edge[threatLevel = "medium"]',
          style: {
            'width': 2.5,
            'line-color': '#eab308',
            'target-arrow-color': '#eab308'
          }
        },
        // Edge Threat Level: Low
        {
          selector: 'edge[threatLevel = "low"]',
          style: {
            'width': 2,
            'line-color': '#3b82f6',
            'target-arrow-color': '#3b82f6'
          }
        }
      ],
      layout: getLayoutOptions(layoutMode)
    });

    // Bind Node Click Selection
    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data();
      setSelectedNodeDetails(nodeData);
      onSelectNodeRef.current(nodeData);
    });

    // Deselect on background click
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNodeDetails(null);
        onSelectNodeRef.current(null);
      }
    });

    cyRef.current = cy;

    // Viewport auto-fit
    cy.ready(() => {
      cy.fit(undefined, 40);
    });

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [nodes, edges, layoutMode]);

  // Synchronize external selection (e.g. from Alert click)
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    cy.$(':selected').unselect();

    if (selectedNodeId) {
      const target = cy.$(`#${selectedNodeId}`);
      if (target.length > 0) {
        target.select();
        cy.animate({
          center: { eles: target },
          zoom: Math.max(cy.zoom(), 1.2),
          duration: 350
        });
        setSelectedNodeDetails(target.data());
      }
    }
  }, [selectedNodeId]);

  // Responsive Viewport Resize Handling (TC-T2-F3-05)
  useEffect(() => {
    const handleResize = () => {
      if (cyRef.current) {
        cyRef.current.resize();
        cyRef.current.fit(undefined, 30);
      }
    };

    window.addEventListener('resize', handleResize);

    let resizeObserver = null;
    if (typeof ResizeObserver !== 'undefined' && graphContainerRef.current) {
      resizeObserver = new ResizeObserver(() => {
        handleResize();
      });
      resizeObserver.observe(graphContainerRef.current);
    }

    return () => {
      window.removeEventListener('resize', handleResize);
      if (resizeObserver) resizeObserver.disconnect();
    };
  }, []);

  // Layout Algorithm Switcher (TC-T2-F3-02)
  function getLayoutOptions(mode) {
    switch (mode) {
      case 'concentric':
        return {
          name: 'concentric',
          concentric: (node) => (node.data('nodeType') === 'firewall' ? 10 : node.data('nodeType') === 'server' ? 7 : 3),
          levelWidth: () => 2,
          padding: 30,
          animate: true,
          animationDuration: 400
        };
      case 'grid':
        return {
          name: 'grid',
          padding: 30,
          animate: true,
          animationDuration: 300
        };
      case 'cose':
      default:
        return {
          name: 'cose',
          animate: true,
          animationDuration: 500,
          randomize: false,
          componentSpacing: 100,
          nodeRepulsion: 450000,
          nodeOverlap: 20,
          idealEdgeLength: 100,
          edgeElasticity: 100,
          gravity: 80,
          numIter: 1000,
          initialTemp: 200,
          coolingFactor: 0.95,
          minTemp: 1.0,
          padding: 40
        };
    }
  }

  // Toolbar Actions
  const handleZoomIn = () => cyRef.current && cyRef.current.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current && cyRef.current.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current && cyRef.current.fit(undefined, 40);
  const handleReset = () => {
    if (cyRef.current) {
      cyRef.current.layout(getLayoutOptions(layoutMode)).run();
      cyRef.current.fit(undefined, 40);
    }
  };

  // Graceful empty state degradation (TC-T2-F3-01)
  if (!nodes || nodes.length === 0) {
    return (
      <div 
        id="network-topology-graph"
        className={`network-topology-graph card ${className}`}
        data-testid="network-topology-graph"
        style={{
          height: '520px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexDirection: 'column',
          color: 'var(--text-secondary)',
          background: 'var(--bg-card)',
          border: '1px solid var(--border-color)',
          borderRadius: '8px'
        }}
      >
        <Radio size={40} style={{ opacity: 0.5, marginBottom: '12px', color: 'var(--accent-blue)' }} />
        <h3 style={{ margin: '0 0 6px 0', color: 'var(--text-primary)' }}>Topology Telemetry Pending</h3>
        <p style={{ margin: 0, fontSize: '0.85rem' }}>No network topology data available. Waiting for infrastructure telemetry.</p>
      </div>
    );
  }

  return (
    <div 
      className={`card ${className}`} 
      style={{ 
        position: 'relative', 
        padding: 0, 
        overflow: 'hidden',
        border: '1px solid var(--border-color)',
        borderRadius: '8px',
        background: '#06090e'
      }}
    >
      {/* Topology Header Controls */}
      <div 
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 16px',
          borderBottom: '1px solid var(--border-color)',
          background: 'var(--bg-card)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={18} color="var(--accent-blue)" />
          <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Enterprise Network Infrastructure</span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginLeft: '8px' }}>
            ({nodes.length} nodes, {edges.length} links)
          </span>
        </div>

        {/* Toolbar & Layout Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <select 
            value={layoutMode} 
            onChange={(e) => setLayoutMode(e.target.value)}
            style={{
              background: 'var(--bg-main)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '4px',
              padding: '4px 8px',
              fontSize: '0.75rem',
              cursor: 'pointer'
            }}
          >
            <option value="cose">CoSE Physics Layout</option>
            <option value="concentric">Concentric Tiered Layout</option>
            <option value="grid">Orthogonal Grid Layout</option>
          </select>

          <button onClick={handleZoomIn} className="page-btn" title="Zoom In">
            <ZoomIn size={14} />
          </button>
          <button onClick={handleZoomOut} className="page-btn" title="Zoom Out">
            <ZoomOut size={14} />
          </button>
          <button onClick={handleFit} className="page-btn" title="Fit Viewport">
            <Maximize2 size={14} />
          </button>
          <button onClick={handleReset} className="page-btn" title="Re-run Layout">
            <RotateCcw size={14} />
          </button>
        </div>
      </div>

      {/* Main Cytoscape Canvas Container (Satisfies #network-topology-graph and .network-topology-graph) */}
      <div 
        ref={graphContainerRef} 
        id="network-topology-graph"
        className="network-topology-graph"
        data-testid="network-topology-graph"
        style={{ 
          width: '100%', 
          height: '500px', 
          background: '#06090e',
          position: 'relative'
        }}
      />

      {/* Visual Legend Overlay */}
      <div 
        style={{
          position: 'absolute',
          bottom: '12px',
          left: '12px',
          background: 'rgba(17, 24, 39, 0.85)',
          backdropFilter: 'blur(4px)',
          border: '1px solid var(--border-color)',
          borderRadius: '6px',
          padding: '8px 12px',
          display: 'flex',
          gap: '16px',
          fontSize: '0.7rem',
          color: 'var(--text-secondary)',
          pointerEvents: 'none',
          zIndex: 10
        }}
      >
        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#64748b', display: 'inline-block' }}></span> Workstation
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <span style={{ width: 8, height: 8, borderRadius: '2px', background: '#3b82f6', display: 'inline-block' }}></span> Server
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <span style={{ width: 8, height: 8, transform: 'rotate(45deg)', background: '#f97316', display: 'inline-block' }}></span> Firewall
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444', display: 'inline-block', boxShadow: '0 0 6px #ef4444' }}></span> Threat Node (C2)
        </span>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNodeDetails && (
        <div 
          style={{
            position: 'absolute',
            top: '55px',
            right: '12px',
            width: '240px',
            background: 'rgba(17, 24, 39, 0.95)',
            backdropFilter: 'blur(6px)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            padding: '12px',
            fontSize: '0.75rem',
            zIndex: 10,
            boxShadow: '0 4px 12px rgba(0,0,0,0.5)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{selectedNodeDetails.rawLabel}</span>
            <span 
              className={`severity-badge ${selectedNodeDetails.status === 'compromised' ? 'critical' : selectedNodeDetails.status === 'investigating' ? 'high' : 'low'}`}
              style={{ fontSize: '0.6rem' }}
            >
              {selectedNodeDetails.status}
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-secondary)' }}>
            <div><strong>IP:</strong> {selectedNodeDetails.ip}</div>
            <div><strong>Subnet:</strong> {selectedNodeDetails.subnet}</div>
            <div><strong>Type:</strong> {selectedNodeDetails.nodeType}</div>
          </div>
        </div>
      )}
    </div>
  );
};

export default NetworkTopologyGraph;
