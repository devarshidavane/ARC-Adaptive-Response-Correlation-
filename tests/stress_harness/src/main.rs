use serde::{Deserialize, Serialize};
use std::time::Instant;

// ============================================================================
// DATA MODELS & STRUCTS (Mirroring src-tauri/src/main.rs)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    #[serde(alias = "type")]
    pub node_type: String,
    pub status: String,
    #[serde(alias = "zone")]
    pub subnet: String,
    #[serde(alias = "ip_address")]
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub protocol: String,
    #[serde(alias = "status")]
    pub threat_level: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: String,
    pub timestamp: String,
    pub severity: String,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IocItem {
    pub id: String,
    pub ioc_type: String,
    pub value: String,
    pub threat_type: String,
    pub severity: String,
    pub confidence: u32,
    pub description: String,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveItem {
    pub id: String,
    pub cve_id: String,
    pub cvss_score: f64,
    pub severity: String,
    pub affected_systems: Vec<String>,
    pub description: String,
    pub published_date: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatActorItem {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub origin: String,
    pub targeted_sectors: Vec<String>,
    pub motivation: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatIntelFeeds {
    pub iocs: Vec<IocItem>,
    pub cves: Vec<CveItem>,
    pub threat_actors: Vec<ThreatActorItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_name: String,
    pub kernel_version: String,
    pub host_name: String,
    pub cpu_count: usize,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertAckResponse {
    pub success: bool,
    pub alert_id: String,
    pub acknowledged_at: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IocLookupResult {
    pub indicator: String,
    pub ioc_type: String,
    pub reputation: String,
    pub confidence: u32,
    pub threat_actor: Option<String>,
    pub malware_family: Option<String>,
    pub tags: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub description: String,
    pub matched: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcknowledgeAlertArgs {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub alert_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LookupIocArgs {
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub indicator: Option<String>,
}

pub fn handle_acknowledge_alert(id: Option<String>, alert_id: Option<String>) -> Result<AlertAckResponse, String> {
    let target_id = id.or(alert_id).unwrap_or_else(|| "ALT-UNKNOWN".to_string());
    Ok(AlertAckResponse {
        success: true,
        alert_id: target_id.clone(),
        acknowledged_at: "2026-09-29T12:00:00Z".to_string(),
        status: "ACKNOWLEDGED".into(),
        message: format!("Alert {} successfully acknowledged by SOC analyst.", target_id),
    })
}

pub fn handle_lookup_ioc(
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
            last_seen: Some("2026-09-29T12:00:00Z".into()),
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
            last_seen: Some("2026-09-29T12:00:00Z".into()),
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
            last_seen: Some("2026-09-29T12:00:00Z".into()),
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

// ============================================================================
// STRESS TEST SUITE
// ============================================================================

fn main() {
    println!("=== STRESS TESTING RUST DATA STRUCTURES & SERIALIZATION ===");
    let mut total_tests = 0;
    let mut passed_tests = 0;

    macro_rules! assert_test {
        ($cond:expr, $name:expr) => {
            total_tests += 1;
            if $cond {
                passed_tests += 1;
                println!("  [PASS] {}", $name);
            } else {
                eprintln!("  [FAIL] {}", $name);
                std::process::exit(1);
            }
        };
    }

    // ------------------------------------------------------------------------
    // TEST GROUP 1: Normal Round-Trip Serialization / Deserialization
    // ------------------------------------------------------------------------
    println!("\n--- Group 1: Basic Round-Trip Fidelity ---");
    {
        let node = TopologyNode {
            id: "node-1".into(),
            label: "Firewall".into(),
            node_type: "firewall".into(),
            status: "normal".into(),
            subnet: "10.0.0.0/24".into(),
            ip: "10.0.0.1".into(),
        };
        let json = serde_json::to_string(&node).expect("Serialize TopologyNode");
        let de: TopologyNode = serde_json::from_str(&json).expect("Deserialize TopologyNode");
        assert_test!(node == de, "TopologyNode round-trip fidelity");
    }

    {
        let edge = TopologyEdge {
            id: "edge-1".into(),
            source: "node-1".into(),
            target: "node-2".into(),
            protocol: "HTTPS".into(),
            threat_level: "critical".into(),
        };
        let json = serde_json::to_string(&edge).expect("Serialize TopologyEdge");
        let de: TopologyEdge = serde_json::from_str(&json).expect("Deserialize TopologyEdge");
        assert_test!(edge == de, "TopologyEdge round-trip fidelity");
    }

    {
        let alert = ThreatAlert {
            id: "ALT-001".into(),
            timestamp: "2026-09-29T12:00:00Z".into(),
            severity: "critical".into(),
            title: "Mimikatz Dumping".into(),
            source_ip: "10.0.0.2".into(),
            dest_ip: "10.0.0.1".into(),
            mitre_technique: "T1003".into(),
            description: Some("Memory dump".into()),
            status: Some("NEW".into()),
            risk_score: Some(99),
            host: Some("DC-01".into()),
        };
        let json = serde_json::to_string(&alert).expect("Serialize ThreatAlert");
        let de: ThreatAlert = serde_json::from_str(&json).expect("Deserialize ThreatAlert");
        assert_test!(alert == de, "ThreatAlert round-trip fidelity with all Option fields");
    }

    {
        let sys = SystemInfo {
            os_name: "Windows".into(),
            kernel_version: "10.0.26200".into(),
            host_name: "SOC-CONSOLE".into(),
            cpu_count: 16,
            memory_used_mb: 8192,
            memory_total_mb: 32768,
        };
        let json = serde_json::to_string(&sys).expect("Serialize SystemInfo");
        let de: SystemInfo = serde_json::from_str(&json).expect("Deserialize SystemInfo");
        assert_test!(sys == de, "SystemInfo round-trip fidelity");
    }

    {
        let ack = AlertAckResponse {
            success: true,
            alert_id: "ALT-999".into(),
            acknowledged_at: "2026-09-29T12:05:00Z".into(),
            status: "ACKNOWLEDGED".into(),
            message: "Acknowledged".into(),
        };
        let json = serde_json::to_string(&ack).expect("Serialize AlertAckResponse");
        let de: AlertAckResponse = serde_json::from_str(&json).expect("Deserialize AlertAckResponse");
        assert_test!(ack == de, "AlertAckResponse round-trip fidelity");
    }

    {
        let ioc = IocLookupResult {
            indicator: "185.220.101.5".into(),
            ioc_type: "IPv4".into(),
            reputation: "MALICIOUS".into(),
            confidence: 95,
            threat_actor: Some("APT29".into()),
            malware_family: Some("WellMess".into()),
            tags: vec!["C2".into(), "Tor".into()],
            first_seen: Some("2026-09-01T00:00:00Z".into()),
            last_seen: Some("2026-09-29T00:00:00Z".into()),
            description: "Known C2".into(),
            matched: true,
        };
        let json = serde_json::to_string(&ioc).expect("Serialize IocLookupResult");
        let de: IocLookupResult = serde_json::from_str(&json).expect("Deserialize IocLookupResult");
        assert_test!(ioc == de, "IocLookupResult round-trip fidelity");
    }

    {
        let analytics = AnalyticsOverview {
            critical_alerts: 5,
            high_alerts: 10,
            medium_alerts: 20,
            low_alerts: 40,
            total_alerts: 75,
            events_per_sec: 1500,
            open_cases: 3,
            system_health_pct: 98,
            os_platform: "windows".into(),
            host_name: "ARC-HOST".into(),
            memory_used_mb: 4096,
            memory_total_mb: 16384,
        };
        let json = serde_json::to_string(&analytics).expect("Serialize AnalyticsOverview");
        let de: AnalyticsOverview = serde_json::from_str(&json).expect("Deserialize AnalyticsOverview");
        assert_test!(analytics == de, "AnalyticsOverview round-trip fidelity");
    }

    // ------------------------------------------------------------------------
    // TEST GROUP 2: Serde Alias Resolution Resilience
    // ------------------------------------------------------------------------
    println!("\n--- Group 2: Serde Alias Resolution ---");
    {
        // TopologyNode aliases: "type" -> node_type, "zone" -> subnet, "ip_address" -> ip
        let raw_json = r#"{
            "id": "node-alias",
            "label": "Workstation",
            "type": "workstation",
            "status": "normal",
            "zone": "10.0.20.0/24",
            "ip_address": "10.0.20.55"
        }"#;
        let de: TopologyNode = serde_json::from_str(raw_json).expect("Deserialize with aliases");
        assert_test!(
            de.node_type == "workstation" && de.subnet == "10.0.20.0/24" && de.ip == "10.0.20.55",
            "TopologyNode resolves 'type', 'zone', and 'ip_address' aliases"
        );
    }

    {
        // TopologyEdge alias: "status" -> threat_level
        let raw_json = r#"{
            "id": "edge-alias",
            "source": "n1",
            "target": "n2",
            "protocol": "TCP",
            "status": "high"
        }"#;
        let de: TopologyEdge = serde_json::from_str(raw_json).expect("Deserialize with edge alias");
        assert_test!(de.threat_level == "high", "TopologyEdge resolves 'status' alias to threat_level");
    }

    {
        // ThreatAlert alias: "destination_ip" -> dest_ip
        let raw_json = r#"{
            "id": "ALT-ALIAS",
            "timestamp": "2026-09-29T12:00:00Z",
            "severity": "medium",
            "title": "Port Scan",
            "source_ip": "1.2.3.4",
            "destination_ip": "5.6.7.8",
            "mitre_technique": "T1046"
        }"#;
        let de: ThreatAlert = serde_json::from_str(raw_json).expect("Deserialize with alert alias");
        assert_test!(
            de.dest_ip == "5.6.7.8" && de.description.is_none() && de.status.is_none(),
            "ThreatAlert resolves 'destination_ip' alias and defaults missing Option fields"
        );
    }

    // ------------------------------------------------------------------------
    // TEST GROUP 3: Option Serialization Skip & Deserialization Defaults
    // ------------------------------------------------------------------------
    println!("\n--- Group 3: Optional Fields & Null Handling ---");
    {
        let alert_none = ThreatAlert {
            id: "ALT-MIN".into(),
            timestamp: "2026-09-29T12:00:00Z".into(),
            severity: "low".into(),
            title: "Info Alert".into(),
            source_ip: "10.0.0.5".into(),
            dest_ip: "10.0.0.6".into(),
            mitre_technique: "T0000".into(),
            description: None,
            status: None,
            risk_score: None,
            host: None,
        };
        let json = serde_json::to_string(&alert_none).expect("Serialize minimal alert");
        assert_test!(
            !json.contains("description") && !json.contains("risk_score") && !json.contains("host"),
            "ThreatAlert skips serializing None fields (skip_serializing_if)"
        );

        // Deserializing with explicit nulls:
        let raw_with_nulls = r#"{
            "id": "ALT-NULLS",
            "timestamp": "2026-09-29T12:00:00Z",
            "severity": "low",
            "title": "Null Alert",
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.6",
            "mitre_technique": "T0000",
            "description": null,
            "status": null,
            "risk_score": null,
            "host": null
        }"#;
        let de_nulls: ThreatAlert = serde_json::from_str(raw_with_nulls).expect("Deserialize null fields");
        assert_test!(
            de_nulls.description.is_none() && de_nulls.risk_score.is_none(),
            "ThreatAlert handles explicit nulls without error"
        );
    }

    // ------------------------------------------------------------------------
    // TEST GROUP 4: Unicode, Emojis, RTL, Boundary Values
    // ------------------------------------------------------------------------
    println!("\n--- Group 4: Unicode, Emojis, RTL, and Boundary Values ---");
    {
        let unicode_node = TopologyNode {
            id: "node-unicode-🚀".into(),
            label: "核心防火墙 🛡️ / Enterprise Firewall / אש".into(),
            node_type: "firewall".into(),
            status: "investigating".into(),
            subnet: "192.168.1.0/24".into(),
            ip: "fe80::1ff:fe23:4567:890a".into(),
        };
        let json = serde_json::to_string(&unicode_node).expect("Serialize unicode");
        let de: TopologyNode = serde_json::from_str(&json).expect("Deserialize unicode");
        assert_test!(unicode_node == de, "UTF-8 multi-byte emojis, Chinese, and Hebrew fidelity");
    }

    {
        let extreme_cve = CveItem {
            id: "CVE-EXTREME".into(),
            cve_id: "CVE-2026-99999".into(),
            cvss_score: 10.0,
            severity: "critical".into(),
            affected_systems: vec!["Kernel 6.x".into()],
            description: "Boundary score 10.0".into(),
            published_date: "2026-09-29".into(),
        };
        let json = serde_json::to_string(&extreme_cve).expect("Serialize extreme CVE");
        let de: CveItem = serde_json::from_str(&json).expect("Deserialize extreme CVE");
        assert_test!((de.cvss_score - 10.0).abs() < f64::EPSILON, "CVSS float precision at maximum 10.0");
    }

    {
        let extreme_system = SystemInfo {
            os_name: "Linux".into(),
            kernel_version: "6.8.0-generic".into(),
            host_name: "HPC-CLUSTER".into(),
            cpu_count: 1024,
            memory_used_mb: u64::MAX - 1000,
            memory_total_mb: u64::MAX,
        };
        let json = serde_json::to_string(&extreme_system).expect("Serialize u64::MAX system");
        let de: SystemInfo = serde_json::from_str(&json).expect("Deserialize u64::MAX system");
        assert_test!(de.memory_total_mb == u64::MAX && de.cpu_count == 1024, "SystemInfo u64::MAX and 1024 CPU count boundary");
    }

    {
        // 1MB string stress test
        let large_string = "A".repeat(1_000_000);
        let alert_large = ThreatAlert {
            id: "ALT-HUGE".into(),
            timestamp: "2026-09-29T12:00:00Z".into(),
            severity: "critical".into(),
            title: "Large Payload Alert".into(),
            source_ip: "10.0.0.1".into(),
            dest_ip: "10.0.0.2".into(),
            mitre_technique: "T1000".into(),
            description: Some(large_string),
            status: Some("NEW".into()),
            risk_score: Some(100),
            host: Some("SERVER-01".into()),
        };
        let t0 = Instant::now();
        let json = serde_json::to_string(&alert_large).expect("Serialize 1MB string alert");
        let serialize_elapsed = t0.elapsed();
        let t1 = Instant::now();
        let de: ThreatAlert = serde_json::from_str(&json).expect("Deserialize 1MB string alert");
        let deserialize_elapsed = t1.elapsed();
        assert_test!(
            de.description.as_ref().unwrap().len() == 1_000_000,
            format!(
                "1MB payload stress passed (serialize: {:?}, deserialize: {:?})",
                serialize_elapsed, deserialize_elapsed
            )
        );
    }

    // ------------------------------------------------------------------------
    // TEST GROUP 5: High-Volume Scale Stress Test (10,000 Nodes & Edges)
    // ------------------------------------------------------------------------
    println!("\n--- Group 5: Extreme Graph Scale (10,000 Nodes, 20,000 Edges) ---");
    {
        let node_count = 10_000;
        let edge_count = 20_000;
        let mut nodes = Vec::with_capacity(node_count);
        let mut edges = Vec::with_capacity(edge_count);

        for i in 0..node_count {
            nodes.push(TopologyNode {
                id: format!("node-{:05}", i),
                label: format!("Endpoint {:05}", i),
                node_type: if i % 10 == 0 { "server".into() } else { "workstation".into() },
                status: if i % 100 == 0 { "compromised".into() } else { "normal".into() },
                subnet: format!("10.{}.0.0/16", (i / 256) % 256),
                ip: format!("10.{}.{}.{}", (i / 65536) % 256, (i / 256) % 256, i % 256),
            });
        }

        for i in 0..edge_count {
            edges.push(TopologyEdge {
                id: format!("edge-{:05}", i),
                source: format!("node-{:05}", i % node_count),
                target: format!("node-{:05}", (i * 7 + 1) % node_count),
                protocol: "TCP/443".into(),
                threat_level: if i % 50 == 0 { "critical".into() } else { "normal".into() },
            });
        }

        let topology = NetworkTopology { nodes, edges };

        let t0 = Instant::now();
        let json = serde_json::to_string(&topology).expect("Serialize 10k nodes topology");
        let ser_time = t0.elapsed();
        let json_size_mb = json.len() as f64 / (1024.0 * 1024.0);

        let t1 = Instant::now();
        let de: NetworkTopology = serde_json::from_str(&json).expect("Deserialize 10k nodes topology");
        let de_time = t1.elapsed();

        assert_test!(
            de.nodes.len() == node_count && de.edges.len() == edge_count,
            format!(
                "Scale test 10,000 nodes / 20,000 edges ({:.2} MB JSON in ser: {:?}, de: {:?})",
                json_size_mb, ser_time, de_time
            )
        );
    }

    // ------------------------------------------------------------------------
    // TEST GROUP 6: Adversarial Malformed Input Rejection (Error Boundary)
    // ------------------------------------------------------------------------
    println!("\n--- Group 6: Adversarial Malformed Input Rejection ---");
    {
        // Missing mandatory field: "id" missing from TopologyNode
        let malformed_json = r#"{
            "label": "Missing ID",
            "type": "workstation",
            "status": "normal",
            "subnet": "10.0.0.0/24",
            "ip": "10.0.0.1"
        }"#;
        let res: Result<TopologyNode, _> = serde_json::from_str(malformed_json);
        assert_test!(res.is_err(), "Rejects TopologyNode missing mandatory 'id' field");
    }

    {
        // Type mismatch: string for u32 confidence in IocItem
        let malformed_json = r#"{
            "id": "IOC-01",
            "ioc_type": "IPv4",
            "value": "1.1.1.1",
            "threat_type": "C2",
            "severity": "critical",
            "confidence": "HIGH_CONFIDENCE_STRING_INVALD",
            "description": "desc",
            "first_seen": "2026-01-01",
            "last_seen": "2026-01-02",
            "tags": []
        }"#;
        let res: Result<IocItem, _> = serde_json::from_str(malformed_json);
        assert_test!(res.is_err(), "Rejects IocItem with string instead of u32 for confidence");
    }

    {
        // Type mismatch: boolean for affected_systems array in CveItem
        let malformed_json = r#"{
            "id": "CVE-01",
            "cve_id": "CVE-2026-0001",
            "cvss_score": 9.5,
            "severity": "critical",
            "affected_systems": false,
            "description": "desc",
            "published_date": "2026-01-01"
        }"#;
        let res: Result<CveItem, _> = serde_json::from_str(malformed_json);
        assert_test!(res.is_err(), "Rejects CveItem with boolean instead of array for affected_systems");
    }

    {
        // Truncated/corrupted JSON syntax
        let corrupted_json = r#"{"id": "ALT-CORRUPT", "timestamp":"#;
        let res: Result<ThreatAlert, _> = serde_json::from_str(corrupted_json);
        assert_test!(res.is_err(), "Rejects truncated/corrupted JSON without panic");
    }

    {
        // Extra unknown fields should be ignored gracefully by serde
        let extra_fields_json = r#"{
            "id": "node-extra",
            "label": "Node",
            "node_type": "server",
            "status": "normal",
            "subnet": "10.0.0.0/24",
            "ip": "10.0.0.10",
            "unexpected_gis_payload": { "lat": 40.7128, "lon": -74.0060 },
            "random_injected_metadata": [1, 2, 3]
        }"#;
        let res: Result<TopologyNode, _> = serde_json::from_str(extra_fields_json);
        assert_test!(res.is_ok(), "Ignores unexpected/extra JSON fields gracefully without panic");
    }

    // ------------------------------------------------------------------------
    // TEST GROUP 7: IPC Command Argument Deserialization Edge Cases
    // ------------------------------------------------------------------------
    println!("\n--- Group 7: IPC Command Argument Deserialization Resiliency ---");
    {
        // acknowledge_alert argument tests:
        // A1: Standard `id`
        let json_a1 = r#"{"id": "ALT-2026-0091"}"#;
        let args_a1: AcknowledgeAlertArgs = serde_json::from_str(json_a1).expect("Deserialize A1");
        let res_a1 = handle_acknowledge_alert(args_a1.id, args_a1.alert_id).unwrap();
        assert_test!(res_a1.alert_id == "ALT-2026-0091" && res_a1.success, "acknowledge_alert handles standard 'id' argument");

        // A2: Alternative `alert_id`
        let json_a2 = r#"{"alert_id": "ALT-2026-0090"}"#;
        let args_a2: AcknowledgeAlertArgs = serde_json::from_str(json_a2).expect("Deserialize A2");
        let res_a2 = handle_acknowledge_alert(args_a2.id, args_a2.alert_id).unwrap();
        assert_test!(res_a2.alert_id == "ALT-2026-0090" && res_a2.success, "acknowledge_alert handles alternative 'alert_id' argument");

        // A3: Empty object {} (both optional missing)
        let json_a3 = r#"{}"#;
        let args_a3: AcknowledgeAlertArgs = serde_json::from_str(json_a3).expect("Deserialize A3");
        let res_a3 = handle_acknowledge_alert(args_a3.id, args_a3.alert_id).unwrap();
        assert_test!(res_a3.alert_id == "ALT-UNKNOWN" && res_a3.success, "acknowledge_alert handles empty object {} with ALT-UNKNOWN fallback");

        // A4: Explicit null values
        let json_a4 = r#"{"id": null, "alert_id": null}"#;
        let args_a4: AcknowledgeAlertArgs = serde_json::from_str(json_a4).expect("Deserialize A4");
        let res_a4 = handle_acknowledge_alert(args_a4.id, args_a4.alert_id).unwrap();
        assert_test!(res_a4.alert_id == "ALT-UNKNOWN" && res_a4.success, "acknowledge_alert handles null parameters safely");

        // A5: Extra unexpected fields
        let json_a5 = r#"{"id": "ALT-EXTRA", "analyst": "SOC-1", "override": true}"#;
        let args_a5: AcknowledgeAlertArgs = serde_json::from_str(json_a5).expect("Deserialize A5");
        let res_a5 = handle_acknowledge_alert(args_a5.id, args_a5.alert_id).unwrap();
        assert_test!(res_a5.alert_id == "ALT-EXTRA" && res_a5.success, "acknowledge_alert ignores unexpected payload fields");
    }

    {
        // lookup_ioc argument tests:
        // L1: Standard `value`
        let json_l1 = r#"{"value": "185.220.101.5"}"#;
        let args_l1: LookupIocArgs = serde_json::from_str(json_l1).expect("Deserialize L1");
        let res_l1 = handle_lookup_ioc(args_l1.value, args_l1.query, args_l1.indicator).unwrap();
        assert_test!(res_l1.matched && res_l1.ioc_type == "IPv4" && res_l1.reputation == "MALICIOUS", "lookup_ioc handles 'value' argument (APT29 IPv4)");

        // L2: Alternative `query`
        let json_l2 = r#"{"query": "185.220.101.5"}"#;
        let args_l2: LookupIocArgs = serde_json::from_str(json_l2).expect("Deserialize L2");
        let res_l2 = handle_lookup_ioc(args_l2.value, args_l2.query, args_l2.indicator).unwrap();
        assert_test!(res_l2.matched && res_l2.reputation == "MALICIOUS", "lookup_ioc handles 'query' alternative argument");

        // L3: Alternative `indicator`
        let json_l3 = r#"{"indicator": "185.220.101.5"}"#;
        let args_l3: LookupIocArgs = serde_json::from_str(json_l3).expect("Deserialize L3");
        let res_l3 = handle_lookup_ioc(args_l3.value, args_l3.query, args_l3.indicator).unwrap();
        assert_test!(res_l3.matched && res_l3.reputation == "MALICIOUS", "lookup_ioc handles 'indicator' alternative argument");

        // L4: Empty object {} (all missing)
        let json_l4 = r#"{}"#;
        let args_l4: LookupIocArgs = serde_json::from_str(json_l4).expect("Deserialize L4");
        let res_l4 = handle_lookup_ioc(args_l4.value, args_l4.query, args_l4.indicator).unwrap();
        assert_test!(!res_l4.matched && res_l4.reputation == "UNKNOWN" && res_l4.confidence == 0, "lookup_ioc handles empty object {} with safe UNKNOWN result");

        // L5: Whitespace only
        let json_l5 = r#"{"value": "   \t\n  "}"#;
        let args_l5: LookupIocArgs = serde_json::from_str(json_l5).expect("Deserialize L5");
        let res_l5 = handle_lookup_ioc(args_l5.value, args_l5.query, args_l5.indicator).unwrap();
        assert_test!(!res_l5.matched && res_l5.reputation == "UNKNOWN", "lookup_ioc handles whitespace query by trimming to empty");

        // L6: 64-char SHA256 (Lazarus)
        let json_l6 = r#"{"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#;
        let args_l6: LookupIocArgs = serde_json::from_str(json_l6).expect("Deserialize L6");
        let res_l6 = handle_lookup_ioc(args_l6.value, args_l6.query, args_l6.indicator).unwrap();
        assert_test!(res_l6.matched && res_l6.ioc_type == "SHA256" && res_l6.reputation == "MALICIOUS", "lookup_ioc matches 64-char SHA256 Lazarus loader");

        // L7: Domain (Cobalt Strike)
        let json_l7 = r#"{"value": "cdn-update-auth-telemetry.com"}"#;
        let args_l7: LookupIocArgs = serde_json::from_str(json_l7).expect("Deserialize L7");
        let res_l7 = handle_lookup_ioc(args_l7.value, args_l7.query, args_l7.indicator).unwrap();
        assert_test!(res_l7.matched && res_l7.ioc_type == "Domain" && res_l7.reputation == "SUSPICIOUS", "lookup_ioc matches fast-flux C2 domain");

        // L8: Unindexed generic clean IOC
        let json_l8 = r#"{"value": "192.168.1.1"}"#;
        let args_l8: LookupIocArgs = serde_json::from_str(json_l8).expect("Deserialize L8");
        let res_l8 = handle_lookup_ioc(args_l8.value, args_l8.query, args_l8.indicator).unwrap();
        assert_test!(!res_l8.matched && res_l8.ioc_type == "Generic" && res_l8.reputation == "CLEAN", "lookup_ioc returns CLEAN for unindexed indicator");
    }

    // ------------------------------------------------------------------------
    // TEST GROUP 8: Relative Path Resolution & Build Hook Validation
    // ------------------------------------------------------------------------
    println!("\n--- Group 8: Relative Path Resolution & Build Hook Validation ---");
    {
        use std::path::Path;
        // Verify relative path resolution from src-tauri to frontend build
        let src_tauri_dir = Path::new(r"c:\cybersecurity\ARC\src-tauri");
        let relative_dist = Path::new(r"../ARC_Complete_Documentation/frontend/build");
        let resolved_dist = src_tauri_dir.join(relative_dist);
        let normalized_dist = std::fs::canonicalize(&resolved_dist);
        assert_test!(normalized_dist.is_ok(), format!("Resolved distDir exists on disk: {:?}", normalized_dist));

        // Verify index.html inside resolved distribution
        let index_html = resolved_dist.join("index.html");
        assert_test!(index_html.exists(), "build/index.html asset exists in resolved frontend build directory");

        // Verify frontend package.json
        let frontend_pkg = Path::new(r"c:\cybersecurity\ARC\ARC_Complete_Documentation\frontend\package.json");
        assert_test!(frontend_pkg.exists(), "Frontend package.json exists for npm --prefix build execution");
    }

    // ------------------------------------------------------------------------
    // SUMMARY
    // ------------------------------------------------------------------------
    println!("\n============================================================");
    println!(" STRESS TEST SUMMARY: {} / {} PASSED (100%)", passed_tests, total_tests);
    println!("============================================================");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stress_harness_suite() {
        main();
    }
}
