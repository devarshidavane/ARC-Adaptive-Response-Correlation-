/**
 * ARC Threat Intelligence Console - Tauri IPC & Telemetry Abstraction
 * Handles typed communication with Rust backend (src-tauri/src/main.rs)
 * with robust offline/standalone fallback telemetry.
 */

// Check if running inside native Tauri desktop webview
export const isTauriEnvironment = () => {
  return typeof window !== 'undefined' && Boolean(window.__TAURI__?.invoke);
};

// Safe IPC Command Invoker
export const invokeIpc = async (cmd, args = {}) => {
  if (isTauriEnvironment()) {
    try {
      return await window.__TAURI__.invoke(cmd, args);
    } catch (err) {
      console.warn(`[Tauri IPC] Command "${cmd}" failed:`, err);
      // Fall through to offline fallback
    }
  }
  return getOfflineFallback(cmd, args);
};

// Safe Tauri Event Listener
export const listenIpc = async (eventName, handler) => {
  if (typeof window !== 'undefined' && window.__TAURI__?.event?.listen) {
    try {
      return await window.__TAURI__.event.listen(eventName, handler);
    } catch (err) {
      console.warn(`[Tauri IPC] Listen for "${eventName}" failed:`, err);
    }
  }
  // Return no-op unlisten function for web/test environments
  return () => {};
};

// ============================================================================
// TYPED IPC API METHODS
// ============================================================================

// Native Tauri invoke and listen aliases
export const invoke = (cmd, args = {}) => invokeIpc(cmd, args);
export const listen = (eventName, handler) => listenIpc(eventName, handler);

export const fetchNetworkTopology = () => invoke('get_network_topology');
export const fetchLiveAlerts = () => invoke('get_live_alerts');
export const fetchThreatIntelFeeds = () => invoke('get_threat_intel_feeds');
export const fetchSystemInfo = () => invoke('get_system_info');
export const acknowledgeAlert = (alertId) => invoke('acknowledge_alert', { id: alertId, alert_id: alertId });
export const lookupIoc = (indicator) => invoke('lookup_ioc', { value: indicator, query: indicator, indicator });
export const fetchAnalyticsOverview = () => invoke('get_analytics_overview');
export const simulateAlertEvent = () => invoke('simulate_alert_event');

// ============================================================================
// OFFLINE & STANDALONE FALLBACK TELEMETRY DATA
// ============================================================================

export const FALLBACK_TOPOLOGY = {
  nodes: [
    {
      id: 'fw-01',
      label: 'Edge Firewall (Palo Alto)',
      node_type: 'firewall',
      type: 'firewall',
      status: 'normal',
      subnet: '10.0.0.0/24',
      zone: '10.0.0.0/24',
      ip: '10.0.0.1',
      ip_address: '10.0.0.1'
    },
    {
      id: 'srv-ad01',
      label: 'Primary DC (AD-01)',
      node_type: 'server',
      type: 'server',
      status: 'compromised',
      subnet: '10.0.10.0/24',
      zone: '10.0.10.0/24',
      ip: '10.0.10.5',
      ip_address: '10.0.10.5'
    },
    {
      id: 'srv-db01',
      label: 'Database Cluster (DB-01)',
      node_type: 'server',
      type: 'server',
      status: 'investigating',
      subnet: '10.0.10.0/24',
      zone: '10.0.10.0/24',
      ip: '10.0.10.12',
      ip_address: '10.0.10.12'
    },
    {
      id: 'work-soc1',
      label: 'SOC Analyst Workstation (SOC-1)',
      node_type: 'workstation',
      type: 'workstation',
      status: 'normal',
      subnet: '10.0.20.0/24',
      zone: '10.0.20.0/24',
      ip: '10.0.20.104',
      ip_address: '10.0.20.104'
    },
    {
      id: 'srv-web01',
      label: 'Web Application Ingress',
      node_type: 'server',
      type: 'server',
      status: 'normal',
      subnet: '10.0.0.0/24',
      zone: '10.0.0.0/24',
      ip: '10.0.0.15',
      ip_address: '10.0.0.15'
    },
    {
      id: 'router-core',
      label: 'Core Enterprise Backbone',
      node_type: 'router',
      type: 'router',
      status: 'normal',
      subnet: '10.0.0.0/16',
      zone: '10.0.0.0/16',
      ip: '10.0.0.254',
      ip_address: '10.0.0.254'
    },
    {
      id: 'threat-c2',
      label: 'External C2 Node (APT29)',
      node_type: 'c2_server',
      type: 'c2_server',
      status: 'compromised',
      subnet: '185.220.101.0/24',
      zone: '185.220.101.0/24',
      ip: '185.220.101.5',
      ip_address: '185.220.101.5'
    }
  ],
  edges: [
    {
      id: 'e1',
      source: 'threat-c2',
      target: 'fw-01',
      protocol: 'HTTPS/443',
      threat_level: 'critical',
      threat: 'critical',
      status: 'critical'
    },
    {
      id: 'e2',
      source: 'fw-01',
      target: 'srv-web01',
      protocol: 'TCP/443',
      threat_level: 'low',
      threat: 'low',
      status: 'low'
    },
    {
      id: 'e3',
      source: 'srv-web01',
      target: 'srv-ad01',
      protocol: 'LDAP/389',
      threat_level: 'high',
      threat: 'high',
      status: 'high'
    },
    {
      id: 'e4',
      source: 'srv-ad01',
      target: 'srv-db01',
      protocol: 'SQL/5432',
      threat_level: 'medium',
      threat: 'medium',
      status: 'medium'
    },
    {
      id: 'e5',
      source: 'work-soc1',
      target: 'srv-ad01',
      protocol: 'RDP/3389',
      threat_level: 'normal',
      threat: 'normal',
      status: 'normal'
    },
    {
      id: 'e6',
      source: 'threat-c2',
      target: 'srv-ad01',
      protocol: 'DNS-Tunnel/53',
      threat_level: 'critical',
      threat: 'critical',
      status: 'critical'
    }
  ]
};

export const FALLBACK_ALERTS = [
  {
    id: 'ALT-2026-0091',
    timestamp: new Date().toISOString(),
    severity: 'critical',
    title: 'Pass-the-Hash Credential Dumping (Mimikatz)',
    source_ip: '10.0.20.104',
    dest_ip: '10.0.10.5',
    destination_ip: '10.0.10.5',
    mitre_technique: 'T1003.001 - LSASS Memory',
    description: 'LSASS process memory access detected with sekurlsa::logonpasswords signature',
    status: 'NEW',
    risk_score: 96,
    host: 'SRV-AD01'
  },
  {
    id: 'ALT-2026-0090',
    timestamp: new Date(Date.now() - 35000).toISOString(),
    severity: 'high',
    title: 'Suspicious PowerShell Encoded Payload Execution',
    source_ip: '10.0.20.104',
    dest_ip: '185.220.101.5',
    destination_ip: '185.220.101.5',
    mitre_technique: 'T1059.001 - PowerShell',
    description: 'Obfuscated base64 command downloading stage-2 payload via WebClient',
    status: 'INVESTIGATING',
    risk_score: 84,
    host: 'WORK-SOC1'
  },
  {
    id: 'ALT-2026-0089',
    timestamp: new Date(Date.now() - 85000).toISOString(),
    severity: 'medium',
    title: 'Periodic Beaconing to External Tor Exit Node',
    source_ip: '10.0.10.12',
    dest_ip: '194.26.29.112',
    destination_ip: '194.26.29.112',
    mitre_technique: 'T1071.001 - Web Protocols',
    description: 'Encrypted HTTPS session beaconing at regular 300-second intervals',
    status: 'INVESTIGATING',
    risk_score: 65,
    host: 'SRV-DB01'
  },
  {
    id: 'ALT-2026-0088',
    timestamp: new Date(Date.now() - 190000).toISOString(),
    severity: 'low',
    title: 'Reconnaissance Port Scan on DMZ Perimeter',
    source_ip: '198.51.100.24',
    dest_ip: '10.0.0.1',
    destination_ip: '10.0.0.1',
    mitre_technique: 'T1046 - Network Service Discovery',
    description: 'Sequential SYN packets across port range 1-1024 blocked by firewall policy',
    status: 'RESOLVED',
    risk_score: 35,
    host: 'FW-01'
  }
];

export const FALLBACK_FEEDS = {
  iocs: [
    {
      id: 'IOC-2026-001',
      ioc_type: 'IPv4',
      value: '185.220.101.5',
      threat_type: 'C2 Server',
      severity: 'critical',
      confidence: 96,
      description: 'Known APT29 command & control server hosting WellMess payload',
      first_seen: '2026-09-01T00:00:00Z',
      last_seen: new Date().toISOString(),
      tags: ['APT29', 'C2', 'Tor Exit Node']
    },
    {
      id: 'IOC-2026-002',
      ioc_type: 'SHA256',
      value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      threat_type: 'Ransomware Loader',
      severity: 'critical',
      confidence: 99,
      description: 'Lazarus Group TraderTraitor backdoor stager hash',
      first_seen: '2026-08-15T12:00:00Z',
      last_seen: new Date().toISOString(),
      tags: ['Lazarus', 'TraderTraitor', 'Ransomware']
    },
    {
      id: 'IOC-2026-003',
      ioc_type: 'Domain',
      value: 'cdn-update-auth-telemetry.com',
      threat_type: 'DGA / Cobalt Strike',
      severity: 'high',
      confidence: 88,
      description: 'Fast-flux domain spoofing update telemetry for Cobalt Strike beacon',
      first_seen: '2026-09-20T08:30:00Z',
      last_seen: new Date().toISOString(),
      tags: ['Cobalt Strike', 'DGA', 'Fast Flux']
    },
    {
      id: 'IOC-2026-004',
      ioc_type: 'URL',
      value: 'http://malicious-paste.ru/raw/beacon.bin',
      threat_type: 'Payload Hosting',
      severity: 'high',
      confidence: 92,
      description: 'Staging URL delivering encrypted second-stage shellcode',
      first_seen: '2026-09-22T04:15:00Z',
      last_seen: new Date().toISOString(),
      tags: ['Payload Stager', 'Shellcode']
    }
  ],
  cves: [
    {
      id: 'CVE-2024-38812',
      cve_id: 'CVE-2024-38812',
      cvss_score: 9.8,
      severity: 'critical',
      affected_systems: ['vCenter Server 7.0/8.0', 'Cloud Foundation 4.x/5.x'],
      description: 'VMware vCenter Server DCE/RPC Remote Code Execution Vulnerability',
      published_date: '2024-09-17'
    },
    {
      id: 'CVE-2024-3400',
      cve_id: 'CVE-2024-3400',
      cvss_score: 10.0,
      severity: 'critical',
      affected_systems: ['PAN-OS 10.2', 'PAN-OS 11.0', 'PAN-OS 11.1'],
      description: 'Palo Alto Networks PAN-OS GlobalProtect Command Injection Vulnerability',
      published_date: '2024-04-12'
    },
    {
      id: 'CVE-2024-21413',
      cve_id: 'CVE-2024-21413',
      cvss_score: 9.8,
      severity: 'critical',
      affected_systems: ['Microsoft Outlook 2016', 'Outlook 2019', 'Outlook LTSC'],
      description: 'Microsoft Outlook Remote Code Execution Vulnerability (Moniker Link)',
      published_date: '2024-02-13'
    }
  ],
  threat_actors: [
    {
      id: 'TA-001',
      name: 'APT29 (Midnight Blizzard / Cozy Bear)',
      aliases: ['Nobelium', 'Cozy Bear', 'UNC2452'],
      origin: 'State-Sponsored (Foreign Intelligence)',
      targeted_sectors: ['Government', 'Diplomatic', 'Defense', 'Cloud Providers'],
      motivation: 'Espionage & Intelligence Gathering',
      description: 'State-sponsored cyber espionage group active since 2008, known for SolarWinds supply chain and token abuse.'
    },
    {
      id: 'TA-002',
      name: 'Lazarus Group (Hidden Cobra)',
      aliases: ['APT38', 'Whois Team', 'Zinc'],
      origin: 'State-Sponsored (Financial & Defense)',
      targeted_sectors: ['Financial', 'Cryptocurrency', 'Defense', 'Aerospace'],
      motivation: 'Financial Theft & Strategic Espionage',
      description: 'State-sponsored cyber group specializing in cryptocurrency theft, ransomware deployment, and defense infiltration.'
    },
    {
      id: 'TA-003',
      name: 'Volt Typhoon (Vanguard Panda)',
      aliases: ['Bronze Silhouette', 'Insidious Taurus'],
      origin: 'State-Sponsored (Critical Infrastructure)',
      targeted_sectors: ['Critical Infrastructure', 'Telecommunications', 'Energy', 'Ports'],
      motivation: 'Pre-positioning & Disruption',
      description: 'State-sponsored actor focused on stealthy living-off-the-land (LotL) persistence within critical infrastructure.'
    }
  ]
};

export const FALLBACK_SYSTEM_INFO = {
  os_name: 'Windows 11 Enterprise (SOC Workstation)',
  kernel_version: '10.0.22631',
  host_name: 'ARC-DESKTOP-SOC1',
  cpu_count: 16,
  memory_used_mb: 6144,
  memory_total_mb: 32768
};

// Dispatcher for fallback mock responses
function getOfflineFallback(cmd, args) {
  switch (cmd) {
    case 'get_network_topology':
      return Promise.resolve(FALLBACK_TOPOLOGY);
    case 'get_live_alerts':
      return Promise.resolve(FALLBACK_ALERTS);
    case 'get_threat_intel_feeds':
      return Promise.resolve(FALLBACK_FEEDS);
    case 'get_system_info':
      return Promise.resolve(FALLBACK_SYSTEM_INFO);
    case 'acknowledge_alert':
      return Promise.resolve({
        success: true,
        alert_id: args?.id || args?.alert_id || 'ALT-FALLBACK',
        acknowledged_at: new Date().toISOString(),
        status: 'ACKNOWLEDGED',
        message: `Alert ${args?.id || args?.alert_id} acknowledged in offline mode.`
      });
    case 'lookup_ioc': {
      const term = (args?.value || args?.query || args?.indicator || '').trim();
      const matchedIoc = FALLBACK_FEEDS.iocs.find(i => i.value.toLowerCase() === term.toLowerCase());
      if (matchedIoc) {
        return Promise.resolve({
          indicator: term,
          ioc_type: matchedIoc.ioc_type,
          reputation: matchedIoc.severity === 'critical' ? 'MALICIOUS' : 'SUSPICIOUS',
          confidence: matchedIoc.confidence,
          threat_actor: matchedIoc.tags[0] || 'Unknown',
          malware_family: matchedIoc.threat_type,
          tags: matchedIoc.tags,
          first_seen: matchedIoc.first_seen,
          last_seen: matchedIoc.last_seen,
          description: matchedIoc.description,
          matched: true
        });
      }
      return Promise.resolve({
        indicator: term,
        ioc_type: 'Generic',
        reputation: 'CLEAN',
        confidence: 45,
        threat_actor: null,
        malware_family: null,
        tags: ['Uncorrelated'],
        first_seen: null,
        last_seen: null,
        description: 'No known malicious associations found in local offline threat intel cache.',
        matched: false
      });
    }
    case 'get_analytics_overview':
      return Promise.resolve({
        critical_alerts: 4,
        high_alerts: 12,
        medium_alerts: 28,
        low_alerts: 54,
        total_alerts: 98,
        events_per_sec: 1420,
        open_cases: 6,
        system_health_pct: 99,
        os_platform: 'windows',
        host_name: 'ARC-DESKTOP-SOC1',
        memory_used_mb: 6144,
        memory_total_mb: 32768
      });
    case 'simulate_alert_event': {
      const idNum = Math.floor(Math.random() * 9000) + 1000;
      const sample = FALLBACK_ALERTS[Math.floor(Math.random() * FALLBACK_ALERTS.length)];
      return Promise.resolve({
        ...sample,
        id: `ALT-SIM-${idNum}`,
        timestamp: new Date().toISOString()
      });
    }
    default:
      return Promise.resolve(null);
  }
}
