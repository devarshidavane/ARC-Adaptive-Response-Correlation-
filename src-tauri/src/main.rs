// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tauri::Manager;

// ============================================================================
// HELPER UTILITIES
// ============================================================================

/// Generates an ISO 8601 UTC timestamp string (e.g., "2026-09-26T14:30:00Z")
/// using standard library SystemTime and civil calendar mathematics.
/// Eliminates external dependencies on chrono while maintaining RFC 3339 compliance.
fn current_utc_iso8601() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = duration.as_secs();

    let days = (total_secs / 86400) as i64;
    let day_secs = total_secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Howard Hinnant's civil date algorithm (Gregorian calendar from epoch days)
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hours, minutes, seconds
    )
}

// ============================================================================
// 1. DATA MODELS & STRUCTS (serde::Serialize, serde::Deserialize)
// ============================================================================

/// Represents a discrete infrastructure node in the logical network topology graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    #[serde(alias = "type")]
    pub node_type: String, // e.g. "workstation", "server", "firewall", "c2_server", "router"
    pub status: String,    // e.g. "normal", "compromised", "investigating", "warning"
    #[serde(alias = "zone")]
    pub subnet: String,    // e.g. "10.0.0.0/24", "10.0.10.0/24"
    #[serde(alias = "ip_address")]
    pub ip: String,        // e.g. "10.0.0.1", "10.0.10.5"
}

/// Represents a communication vector / telemetry link between two topology nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub protocol: String,
    #[serde(alias = "status")]
    pub threat_level: String, // e.g. "critical", "high", "medium", "low", "normal"
}

/// Represents the complete network topology graph dataset for Cytoscape.js.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

/// Represents a real-time security alert event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: String,
    pub timestamp: String,
    pub severity: String, // "critical", "high", "medium", "low"
    pub title: String,
    pub source_ip: String,
    #[serde(alias = "destination_ip")]
    pub dest_ip: String,
    pub mitre_technique: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// Represents an individual Indicator of Compromise (IOC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocItem {
    pub id: String,
    pub ioc_type: String, // "IPv4", "Domain", "SHA256", "URL"
    pub value: String,
    pub threat_type: String,
    pub severity: String, // "critical", "high", "medium", "low"
    pub confidence: u32,  // 0 - 100
    pub description: String,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Represents an active Common Vulnerability and Exposure (CVE) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveItem {
    pub id: String,
    pub cve_id: String,
    pub cvss_score: f64,
    pub severity: String,
    pub affected_systems: Vec<String>,
    pub description: String,
    pub published_date: String,
}

/// Represents an adversarial Threat Actor profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorItem {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub origin: String,
    pub targeted_sectors: Vec<String>,
    pub motivation: String,
    pub description: String,
}

/// Aggregated container for threat intelligence feeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeeds {
    pub iocs: Vec<IocItem>,
    pub cves: Vec<CveItem>,
    pub threat_actors: Vec<ThreatActorItem>,
}

/// System host information queried via the sysinfo crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_name: String,
    pub kernel_version: String,
    pub host_name: String,
    pub cpu_count: usize,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
}

/// Acknowledgment response payload for alert triage actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertAckResponse {
    pub success: bool,
    pub alert_id: String,
    pub acknowledged_at: String,
    pub status: String,
    pub message: String,
}

/// Result payload for IOC search queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocLookupResult {
    pub indicator: String,
    pub ioc_type: String,
    pub reputation: String, // "MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"
    pub confidence: u32,
    pub threat_actor: Option<String>,
    pub malware_family: Option<String>,
    pub tags: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub description: String,
    pub matched: bool,
}

/// Analytics overview metrics for SOC dashboard telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsOverview {
    pub critical_alerts: u32,
    pub high_alerts: u32,
    pub medium_alerts: u32,
    pub low_alerts: u32,
    pub total_alerts: u32,
    pub events_per_sec: u32,
    pub open_cases: u32,
    pub system_health_pct: u32,
    pub os_platform: String,
    pub host_name: String,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
}

// ============================================================================
// 2. TAURI IPC COMMAND HANDLERS (#[tauri::command])
// ============================================================================

/// Returns the logical enterprise network topology graph dataset.
/// Explicitly excludes any geographical coordinates or world map schemas.
#[tauri::command]
fn get_network_topology() -> Result<NetworkTopology, String> {
    Ok(NetworkTopology {
        nodes: vec![
            TopologyNode {
                id: "fw-01".into(),
                label: "Edge Firewall (Palo Alto)".into(),
                node_type: "firewall".into(),
                status: "normal".into(),
                subnet: "10.0.0.0/24".into(),
                ip: "10.0.0.1".into(),
            },
            TopologyNode {
                id: "srv-ad01".into(),
                label: "Primary DC (AD-01)".into(),
                node_type: "server".into(),
                status: "compromised".into(),
                subnet: "10.0.10.0/24".into(),
                ip: "10.0.10.5".into(),
            },
            TopologyNode {
                id: "srv-db01".into(),
                label: "Database Cluster (DB-01)".into(),
                node_type: "server".into(),
                status: "investigating".into(),
                subnet: "10.0.10.0/24".into(),
                ip: "10.0.10.12".into(),
            },
            TopologyNode {
                id: "work-soc1".into(),
                label: "SOC Analyst Workstation (SOC-1)".into(),
                node_type: "workstation".into(),
                status: "normal".into(),
                subnet: "10.0.20.0/24".into(),
                ip: "10.0.20.104".into(),
            },
            TopologyNode {
                id: "srv-web01".into(),
                label: "Web Application Ingress".into(),
                node_type: "server".into(),
                status: "normal".into(),
                subnet: "10.0.0.0/24".into(),
                ip: "10.0.0.15".into(),
            },
            TopologyNode {
                id: "router-core".into(),
                label: "Core Enterprise Backbone".into(),
                node_type: "router".into(),
                status: "normal".into(),
                subnet: "10.0.0.0/16".into(),
                ip: "10.0.0.254".into(),
            },
            TopologyNode {
                id: "threat-c2".into(),
                label: "External C2 Node (APT29)".into(),
                node_type: "c2_server".into(),
                status: "compromised".into(),
                subnet: "185.220.101.0/24".into(),
                ip: "185.220.101.5".into(),
            },
        ],
        edges: vec![
            TopologyEdge {
                id: "e1".into(),
                source: "threat-c2".into(),
                target: "fw-01".into(),
                protocol: "HTTPS/443".into(),
                threat_level: "critical".into(),
            },
            TopologyEdge {
                id: "e2".into(),
                source: "fw-01".into(),
                target: "srv-web01".into(),
                protocol: "TCP/443".into(),
                threat_level: "low".into(),
            },
            TopologyEdge {
                id: "e3".into(),
                source: "srv-web01".into(),
                target: "srv-ad01".into(),
                protocol: "LDAP/389".into(),
                threat_level: "high".into(),
            },
            TopologyEdge {
                id: "e4".into(),
                source: "srv-ad01".into(),
                target: "srv-db01".into(),
                protocol: "SQL/5432".into(),
                threat_level: "medium".into(),
            },
            TopologyEdge {
                id: "e5".into(),
                source: "work-soc1".into(),
                target: "srv-ad01".into(),
                protocol: "RDP/3389".into(),
                threat_level: "normal".into(),
            },
            TopologyEdge {
                id: "e6".into(),
                source: "threat-c2".into(),
                target: "srv-ad01".into(),
                protocol: "DNS-Tunnel/53".into(),
                threat_level: "critical".into(),
            },
        ],
    })
}

/// Returns the initial batch of high-fidelity threat alerts.
#[tauri::command]
fn get_live_alerts() -> Result<Vec<ThreatAlert>, String> {
    Ok(vec![
        ThreatAlert {
            id: "ALT-2026-0091".into(),
            timestamp: current_utc_iso8601(),
            severity: "critical".into(),
            title: "Pass-the-Hash Credential Dumping (Mimikatz)".into(),
            source_ip: "10.0.20.104".into(),
            dest_ip: "10.0.10.5".into(),
            mitre_technique: "T1003.001 - LSASS Memory".into(),
            description: Some("LSASS process memory access detected with sekurlsa::logonpasswords signature".into()),
            status: Some("NEW".into()),
            risk_score: Some(96),
            host: Some("SRV-AD01".into()),
        },
        ThreatAlert {
            id: "ALT-2026-0090".into(),
            timestamp: current_utc_iso8601(),
            severity: "high".into(),
            title: "Suspicious PowerShell Encoded Payload Execution".into(),
            source_ip: "10.0.20.104".into(),
            dest_ip: "185.220.101.5".into(),
            mitre_technique: "T1059.001 - PowerShell".into(),
            description: Some("Obfuscated base64 command downloading stage-2 payload via WebClient".into()),
            status: Some("INVESTIGATING".into()),
            risk_score: Some(84),
            host: Some("WORK-SOC1".into()),
        },
        ThreatAlert {
            id: "ALT-2026-0089".into(),
            timestamp: current_utc_iso8601(),
            severity: "medium".into(),
            title: "Periodic Beaconing to External Tor Exit Node".into(),
            source_ip: "10.0.10.12".into(),
            dest_ip: "194.26.29.112".into(),
            mitre_technique: "T1071.001 - Web Protocols".into(),
            description: Some("Encrypted HTTPS session beaconing at regular 300-second intervals".into()),
            status: Some("INVESTIGATING".into()),
            risk_score: Some(65),
            host: Some("SRV-DB01".into()),
        },
        ThreatAlert {
            id: "ALT-2026-0088".into(),
            timestamp: current_utc_iso8601(),
            severity: "low".into(),
            title: "Reconnaissance Port Scan on DMZ Perimeter".into(),
            source_ip: "198.51.100.24".into(),
            dest_ip: "10.0.0.1".into(),
            mitre_technique: "T1046 - Network Service Discovery".into(),
            description: Some("Sequential SYN packets across port range 1-1024 blocked by firewall policy".into()),
            status: Some("RESOLVED".into()),
            risk_score: Some(35),
            host: Some("FW-01".into()),
        },
    ])
}

/// Returns aggregated threat intelligence feeds including IOCs, CVEs, and Threat Actor dossiers.
#[tauri::command]
fn get_threat_intel_feeds() -> Result<ThreatIntelFeeds, String> {
    Ok(ThreatIntelFeeds {
        iocs: vec![
            IocItem {
                id: "IOC-2026-001".into(),
                ioc_type: "IPv4".into(),
                value: "185.220.101.5".into(),
                threat_type: "C2 Server".into(),
                severity: "critical".into(),
                confidence: 96,
                description: "Known APT29 command & control server hosting WellMess payload".into(),
                first_seen: "2026-09-01T00:00:00Z".into(),
                last_seen: current_utc_iso8601(),
                tags: vec!["APT29".into(), "C2".into(), "Tor Exit Node".into()],
            },
            IocItem {
                id: "IOC-2026-002".into(),
                ioc_type: "SHA256".into(),
                value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                threat_type: "Ransomware Loader".into(),
                severity: "critical".into(),
                confidence: 99,
                description: "Lazarus Group TraderTraitor backdoor stager hash".into(),
                first_seen: "2026-08-15T12:00:00Z".into(),
                last_seen: current_utc_iso8601(),
                tags: vec!["Lazarus".into(), "TraderTraitor".into(), "Ransomware".into()],
            },
            IocItem {
                id: "IOC-2026-003".into(),
                ioc_type: "Domain".into(),
                value: "cdn-update-auth-telemetry.com".into(),
                threat_type: "DGA / Cobalt Strike".into(),
                severity: "high".into(),
                confidence: 88,
                description: "Fast-flux domain spoofing update telemetry for Cobalt Strike beacon".into(),
                first_seen: "2026-09-20T08:30:00Z".into(),
                last_seen: current_utc_iso8601(),
                tags: vec!["Cobalt Strike".into(), "DGA".into(), "Fast Flux".into()],
            },
            IocItem {
                id: "IOC-2026-004".into(),
                ioc_type: "URL".into(),
                value: "http://malicious-paste.ru/raw/beacon.bin".into(),
                threat_type: "Payload Hosting".into(),
                severity: "high".into(),
                confidence: 92,
                description: "Staging URL delivering encrypted second-stage shellcode".into(),
                first_seen: "2026-09-22T04:15:00Z".into(),
                last_seen: current_utc_iso8601(),
                tags: vec!["Payload Stager".into(), "Shellcode".into()],
            },
        ],
        cves: vec![
            CveItem {
                id: "CVE-2024-38812".into(),
                cve_id: "CVE-2024-38812".into(),
                cvss_score: 9.8,
                severity: "critical".into(),
                affected_systems: vec!["vCenter Server 7.0/8.0".into(), "Cloud Foundation 4.x/5.x".into()],
                description: "VMware vCenter Server DCE/RPC Remote Code Execution Vulnerability".into(),
                published_date: "2024-09-17".into(),
            },
            CveItem {
                id: "CVE-2024-3400".into(),
                cve_id: "CVE-2024-3400".into(),
                cvss_score: 10.0,
                severity: "critical".into(),
                affected_systems: vec!["PAN-OS 10.2".into(), "PAN-OS 11.0".into(), "PAN-OS 11.1".into()],
                description: "Palo Alto Networks PAN-OS GlobalProtect Command Injection Vulnerability".into(),
                published_date: "2024-04-12".into(),
            },
            CveItem {
                id: "CVE-2024-21413".into(),
                cve_id: "CVE-2024-21413".into(),
                cvss_score: 9.8,
                severity: "critical".into(),
                affected_systems: vec!["Microsoft Outlook 2016".into(), "Outlook 2019".into(), "Outlook LTSC".into()],
                description: "Microsoft Outlook Remote Code Execution Vulnerability (Moniker Link)".into(),
                published_date: "2024-02-13".into(),
            },
        ],
        threat_actors: vec![
            ThreatActorItem {
                id: "TA-001".into(),
                name: "APT29 (Midnight Blizzard / Cozy Bear)".into(),
                aliases: vec!["Nobelium".into(), "Cozy Bear".into(), "UNC2452".into()],
                origin: "Russia (SVR)".into(),
                targeted_sectors: vec!["Government".into(), "Diplomatic".into(), "Defense".into(), "Cloud Providers".into()],
                motivation: "Espionage & Intelligence Gathering".into(),
                description: "State-sponsored cyber espionage group active since 2008, known for SolarWinds supply chain and token abuse.".into(),
            },
            ThreatActorItem {
                id: "TA-002".into(),
                name: "Lazarus Group (Hidden Cobra)".into(),
                aliases: vec!["APT38".into(), "Whois Team".into(), "Zinc".into()],
                origin: "North Korea (RGB)".into(),
                targeted_sectors: vec!["Financial".into(), "Cryptocurrency".into(), "Defense".into(), "Aerospace".into()],
                motivation: "Financial Theft & Strategic Espionage".into(),
                description: "State-sponsored cyber group specializing in cryptocurrency theft, ransomware deployment, and defense infiltration.".into(),
            },
            ThreatActorItem {
                id: "TA-003".into(),
                name: "Volt Typhoon (Vanguard Panda)".into(),
                aliases: vec!["Bronze Silhouette".into(), "Insidious Taurus".into()],
                origin: "China (PLA)".into(),
                targeted_sectors: vec!["Critical Infrastructure".into(), "Telecommunications".into(), "Energy".into(), "Ports".into()],
                motivation: "Pre-positioning & Disruption".into(),
                description: "State-sponsored actor focused on stealthy living-off-the-land (LotL) persistence within US critical infrastructure.".into(),
            },
        ],
    })
}

/// Retrieves system hardware and OS metrics via the sysinfo crate (0.30+).
#[tauri::command]
fn get_system_info() -> Result<SystemInfo, String> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let os_name = System::name().unwrap_or_else(|| std::env::consts::OS.to_string());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "unknown".to_string());
    let host_name = System::host_name().unwrap_or_else(|| "ARC-HOST".to_string());
    let cpu_count = sys.cpus().len();
    let memory_used_mb = sys.used_memory() / (1024 * 1024);
    let memory_total_mb = sys.total_memory() / (1024 * 1024);

    Ok(SystemInfo {
        os_name,
        kernel_version,
        host_name,
        cpu_count,
        memory_used_mb,
        memory_total_mb,
    })
}

/// Acknowledges a threat alert and transitions its status in the triage pipeline.
/// Accepts either `id` or `alert_id` parameter to guarantee resilient frontend invocation.
#[tauri::command]
fn acknowledge_alert(id: Option<String>, alert_id: Option<String>) -> Result<AlertAckResponse, String> {
    let target_id = id.or(alert_id).unwrap_or_else(|| "ALT-UNKNOWN".to_string());
    Ok(AlertAckResponse {
        success: true,
        alert_id: target_id.clone(),
        acknowledged_at: current_utc_iso8601(),
        status: "ACKNOWLEDGED".into(),
        message: format!("Alert {} successfully acknowledged by SOC analyst.", target_id),
    })
}

/// Looks up an IOC value against known intelligence feeds and returns enriched threat metadata.
/// Resilient parameter resolution accepts `value`, `query`, or `indicator`.
#[tauri::command]
fn lookup_ioc(
    value: Option<String>,
    query: Option<String>,
    indicator: Option<String>,
) -> Result<IocLookupResult, String> {
    let term = value
        .or(query)
        .or(indicator)
        .unwrap_or_default()
        .trim()
        .to_string();

    if term.is_empty() {
        return Ok(IocLookupResult {
            indicator: String::new(),
            ioc_type: "UNKNOWN".into(),
            reputation: "UNKNOWN".into(),
            confidence: 0,
            threat_actor: None,
            malware_family: None,
            tags: vec![],
            first_seen: None,
            last_seen: None,
            description: "Empty search query provided.".into(),
            matched: false,
        });
    }

    if term == "185.220.101.5" {
        Ok(IocLookupResult {
            indicator: term,
            ioc_type: "IPv4".into(),
            reputation: "MALICIOUS".into(),
            confidence: 96,
            threat_actor: Some("APT29 (Cozy Bear)".into()),
            malware_family: Some("WellMess".into()),
            tags: vec!["C2".into(), "Tor Exit Node".into(), "State-Sponsored".into()],
            first_seen: Some("2026-09-01T00:00:00Z".into()),
            last_seen: Some(current_utc_iso8601()),
            description: "Active Command & Control infrastructure associated with APT29 campaigns.".into(),
            matched: true,
        })
    } else if term.contains("e3b0c442") || term.len() == 64 {
        Ok(IocLookupResult {
            indicator: term,
            ioc_type: "SHA256".into(),
            reputation: "MALICIOUS".into(),
            confidence: 99,
            threat_actor: Some("Lazarus Group".into()),
            malware_family: Some("TraderTraitor".into()),
            tags: vec!["Ransomware Loader".into(), "Backdoor".into()],
            first_seen: Some("2026-08-15T12:00:00Z".into()),
            last_seen: Some(current_utc_iso8601()),
            description: "Compiled malicious payload dropper targeting defense contractors.".into(),
            matched: true,
        })
    } else if term.contains("cdn-update-auth-telemetry.com") || term.contains(".com") || term.contains(".net") {
        Ok(IocLookupResult {
            indicator: term,
            ioc_type: "Domain".into(),
            reputation: "SUSPICIOUS".into(),
            confidence: 88,
            threat_actor: Some("UNC2452".into()),
            malware_family: Some("Cobalt Strike".into()),
            tags: vec!["DGA".into(), "Fast Flux".into()],
            first_seen: Some("2026-09-20T08:30:00Z".into()),
            last_seen: Some(current_utc_iso8601()),
            description: "Dynamic fast-flux domain matching known beaconing communication profiles.".into(),
            matched: true,
        })
    } else {
        Ok(IocLookupResult {
            indicator: term,
            ioc_type: "Generic".into(),
            reputation: "CLEAN".into(),
            confidence: 50,
            threat_actor: None,
            malware_family: None,
            tags: vec!["Uncorrelated".into()],
            first_seen: None,
            last_seen: None,
            description: "No known malicious associations found in local threat intelligence cache.".into(),
            matched: false,
        })
    }
}

/// Returns aggregated SOC console telemetry metrics for overview panels.
#[tauri::command]
fn get_analytics_overview() -> Result<AnalyticsOverview, String> {
    let mut sys = System::new_all();
    sys.refresh_all();

    Ok(AnalyticsOverview {
        critical_alerts: 4,
        high_alerts: 12,
        medium_alerts: 28,
        low_alerts: 54,
        total_alerts: 98,
        events_per_sec: 1420,
        open_cases: 6,
        system_health_pct: 99,
        os_platform: std::env::consts::OS.to_string(),
        host_name: System::host_name().unwrap_or_else(|| "ARC-HOST".into()),
        memory_used_mb: sys.used_memory() / (1024 * 1024),
        memory_total_mb: sys.total_memory() / (1024 * 1024),
    })
}

/// Triggers manual generation of a simulated alert event for development testing.
#[tauri::command]
fn simulate_alert_event() -> Result<ThreatAlert, String> {
    let counter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    Ok(generate_simulated_alert(counter))
}

// ============================================================================
// 3. BACKGROUND ALERT STREAM EMITTER & GENERATOR
// ============================================================================

/// Generates a rotating, contextually realistic security alert event.
pub fn generate_simulated_alert(counter: u64) -> ThreatAlert {
    let variants = [
        (
            "critical",
            "DCSync Domain Controller Replay Attack Detected",
            "10.0.20.104",
            "10.0.10.5",
            "T1003.006 - DCSync",
            "Direct replication request to Directory Service Agent from unauthorized workstation",
            "SRV-AD01",
            98,
        ),
        (
            "high",
            "Suspicious Cobalt Strike DNS Beacon Activity",
            "10.0.10.12",
            "185.220.101.5",
            "T1071.004 - DNS",
            "High volume of encrypted TXT query anomalies targeting external domain",
            "SRV-DB01",
            87,
        ),
        (
            "medium",
            "Unusual Kerberos Golden Ticket Request",
            "10.0.20.104",
            "10.0.10.5",
            "T1558.001 - Golden Ticket",
            "TGT ticket lifetime exceeds configured Active Directory policy limit",
            "SRV-AD01",
            72,
        ),
        (
            "low",
            "SSH Brute Force Velocity Anomaly on Gateway",
            "198.51.100.44",
            "10.0.0.15",
            "T1110.001 - Password Guessing",
            "Repeated failed authentication attempts against SSH ingress gateway",
            "SRV-WEB01",
            45,
        ),
    ];

    let index = (counter as usize) % variants.len();
    let (severity, title, src, dst, technique, desc, host, risk) = variants[index];

    ThreatAlert {
        id: format!("ALT-STREAM-{:05}", counter),
        timestamp: current_utc_iso8601(),
        severity: severity.to_string(),
        title: title.to_string(),
        source_ip: src.to_string(),
        dest_ip: dst.to_string(),
        mitre_technique: technique.to_string(),
        description: Some(desc.to_string()),
        status: Some("NEW".to_string()),
        risk_score: Some(risk),
        host: Some(host.to_string()),
    }
}

// ============================================================================
// 4. MAIN ENTRY POINT & TAURI APPLICATION BUILDER
// ============================================================================

struct BackendProcess(std::sync::Mutex<Option<std::process::Child>>);

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_handle = app.handle();
            
            // Spawn Python backend using the executable path for reliable resolution
            let exe_path = std::env::current_exe().expect("Failed to get current executable path");
            let mut base_dir = exe_path.parent().expect("Failed to get executable directory").to_path_buf();
            
            // In a development build, the executable is inside target/debug/ or target/release/
            if base_dir.ends_with("debug") || base_dir.ends_with("release") {
                if let Some(target_dir) = base_dir.parent() {
                    if let Some(src_tauri_dir) = target_dir.parent() {
                        if let Some(root_dir) = src_tauri_dir.parent() {
                            base_dir = root_dir.to_path_buf();
                        }
                    }
                }
            }
            
            let backend_path = base_dir.join("ARC_Complete_Documentation").join("backend");
            let python_exe = backend_path.join("venv").join("Scripts").join("python.exe");
            
            if !python_exe.exists() {
                let err_msg = format!("Python executable not found at {:?}", python_exe);
                eprintln!("Fatal error: {}", err_msg);
                tauri::api::dialog::blocking::message(None::<&tauri::Window>, "ARC - Fatal Error", &err_msg);
                return Err(err_msg.into());
            }
            
            #[cfg(target_os = "windows")]
            use std::os::windows::process::CommandExt;
            
            let mut cmd = std::process::Command::new(&python_exe);
            cmd.current_dir(&backend_path)
                .arg("-m")
                .arg("uvicorn")
                .arg("arc.main:app")
                .arg("--port")
                .arg("8000");
                
            #[cfg(target_os = "windows")]
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            
            let child = match cmd.spawn() {
                Ok(c) => Some(c),
                Err(e) => {
                    let err_msg = format!("Failed to spawn Python backend process from {:?}: {}", python_exe, e);
                    eprintln!("Fatal error: {}", err_msg);
                    tauri::api::dialog::blocking::message(None::<&tauri::Window>, "ARC - Fatal Error", &err_msg);
                    return Err(err_msg.into());
                }
            };
                
            app.manage(BackendProcess(std::sync::Mutex::new(child)));

            // Asynchronous background alert emitter:
            // Spawns a Tokio background task emitting `threat_alert_stream` events
            // every 5 seconds to all open windows.
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                let mut counter: u64 = 1000;
                loop {
                    interval.tick().await;
                    counter += 1;
                    let simulated_alert = generate_simulated_alert(counter);
                    let _ = app_handle.emit_all("threat_alert_stream", &simulated_alert);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_network_topology,
            get_live_alerts,
            get_threat_intel_feeds,
            get_system_info,
            acknowledge_alert,
            lookup_ioc,
            get_analytics_overview,
            simulate_alert_event
        ])
        .build(tauri::generate_context!())
        .expect("error while building ARC desktop application")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                let state: tauri::State<BackendProcess> = app_handle.state();
                let _ = state.0.lock().map(|mut lock| {
                    if let Some(mut child) = lock.take() {
                        let _ = child.kill();
                    }
                });
            }
        });
}
