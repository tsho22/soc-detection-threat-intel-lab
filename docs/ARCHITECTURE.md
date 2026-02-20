# System Architecture - SOC Detection & Threat Intelligence Lab

Detailed technical architecture and design documentation for the SOC Detection Lab.

---

## Table of Contents

- [Overview](#overview)
- [High-Level Architecture](#high-level-architecture)
- [Component Details](#component-details)
- [Data Flow](#data-flow)
- [Network Architecture](#network-architecture)
- [Security Design](#security-design)
- [Scalability Considerations](#scalability-considerations)
- [Performance Optimization](#performance-optimization)
- [Monitoring & Alerting](#monitoring--alerting)
- [Disaster Recovery](#disaster-recovery)

---

## Overview

This SOC Detection Lab implements a complete Security Operations Center (SOC) monitoring solution using open-source tools deployed on AWS infrastructure. The architecture follows industry best practices for security monitoring, threat detection, and incident response.

### Design Principles

- **Defense in Depth:** Multiple layers of detection (signatures, custom rules, threat intelligence)
- **Automation First:** Automated log collection, parsing, enrichment, and alerting
- **Scalability:** Designed to scale from lab to production environments
- **Open Source:** Leverages community-driven tools and threat intelligence
- **Cost Effective:** Optimized for AWS Free Tier when possible

### Architecture Goals

1. **Real-time Detection:** Identify threats as they occur (<2 second latency)
2. **Comprehensive Visibility:** Monitor all network traffic and system events
3. **Threat Intelligence:** Enrich alerts with external context automatically
4. **Incident Response:** Enable rapid triage, investigation, and containment
5. **Knowledge Transfer:** Document all processes for learning and improvement

---

## High-Level Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                        Internet Traffic                         │
│                              ↓                                  │
│                    AWS VPC (172.31.0.0/16)                      │
│                              ↓                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │          Security Group: SOC-Lab-SG                      │  │
│  │  Inbound: SSH(22), Kibana(5601), EveBox(5636)           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              ↓                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │         EC2 Instance: t3.large (Ubuntu 24.04)            │  │
│  │                                                          │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │          Detection Layer                        │    │  │
│  │  │  ┌──────────────────────────────────────────┐   │    │  │
│  │  │  │  Suricata IDS (AF_PACKET Mode)           │   │    │  │
│  │  │  │  • 48,270 Detection Rules                │   │    │  │
│  │  │  │  • Protocol Analysis                     │   │    │  │
│  │  │  │  • File Extraction                       │   │    │  │
│  │  │  └──────────────────────────────────────────┘   │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                      ↓                                   │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │          Processing Layer                       │    │  │
│  │  │  ┌──────────────────────────────────────────┐   │    │  │
│  │  │  │  Logstash                                │   │    │  │
│  │  │  │  • JSON Parsing                          │   │    │  │
│  │  │  │  • GeoIP Enrichment                      │   │    │  │
│  │  │  │  • Field Transformation                  │   │    │  │
│  │  │  └──────────────────────────────────────────┘   │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                      ↓                                   │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │          Storage Layer                          │    │  │
│  │  │  ┌──────────────────────────────────────────┐   │    │  │
│  │  │  │  Elasticsearch                           │   │    │  │
│  │  │  │  • Index: suricata-YYYY.MM.DD            │   │    │  │
│  │  │  │  • Retention: 30 days                    │   │    │  │
│  │  │  │  • Heap: 1GB (50% of available RAM)      │   │    │  │
│  │  │  └──────────────────────────────────────────┘   │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                      ↓                                   │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │       Visualization & Analysis Layer            │    │  │
│  │  │  ┌──────────────┐      ┌──────────────────┐     │    │  │
│  │  │  │   Kibana     │      │    EveBox UI     │     │    │  │
│  │  │  │  Port: 5601  │      │   Port: 5636     │     │    │  │
│  │  │  │  • Dashboards│      │   • Alert Triage │     │    │  │
│  │  │  │  • Analytics │      │   • Workflow Mgmt│     │    │  │
│  │  │  └──────────────┘      └──────────────────┘     │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                      ↓                                   │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │     Threat Intelligence Layer                   │    │  │
│  │  │  ┌──────────────────────────────────────────┐   │    │  │
│  │  │  │  Python Enrichment Scripts               │   │    │  │
│  │  │  │  • analyze_alerts.py                     │   │    │  │
│  │  │  │  • API Integration (OTX, AbuseIPDB)      │   │    │  │
│  │  │  │  • Threat Scoring Algorithm              │   │    │  │
│  │  │  └──────────────────────────────────────────┘   │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│             External Threat Intelligence APIs                   │
│                                                                 │
│  ┌──────────────────┐              ┌──────────────────────┐    │
│  │ AlienVault OTX   │              │    AbuseIPDB         │    │
│  │ • Threat Pulses  │              │    • IP Reputation   │    │
│  │ • IOC Database   │              │    • Abuse Reports   │    │
│  │ • Free Tier      │              │    • 1000 req/day    │    │
│  └──────────────────┘              └──────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Detection Layer - Suricata IDS

**Version:** 8.0.3  
**Mode:** IDS (Intrusion Detection System)  
**Capture Method:** AF_PACKET (Linux kernel capture)

#### Configuration
```yaml
Interface: enp39s0  (primary network interface)
Capture Mode: AF_PACKET with cluster flow load balancing
Thread Count: 2 (matches vCPU count)
Buffer Size: Default (optimized for t3.large)
```

#### Rule Sets

| Ruleset | Count | Source | Update Frequency |
|---------|-------|--------|------------------|
| Emerging Threats Open | 48,253 | Proofpoint | Daily |
| Custom Rules | 17 | Internal | As needed |
| **Total** | **48,270** | - | Daily |

#### Detection Capabilities

- **Protocol Analysis:** HTTP, DNS, TLS, SSH, SMB, FTP, SMTP
- **File Extraction:** Executables, documents, archives
- **Payload Inspection:** Deep packet inspection with regex
- **Behavioral Detection:** Anomaly detection for protocol violations
- **Custom Rules:** MITRE ATT&CK mapped detections

#### Output Format

**EVE JSON Schema:**
```json
{
  "timestamp": "ISO8601",
  "event_type": "alert|dns|http|tls|flow|fileinfo",
  "src_ip": "IPv4 address",
  "dest_ip": "IPv4 address",
  "proto": "TCP|UDP|ICMP",
  "alert": {
    "signature": "Rule description",
    "signature_id": 1000001,
    "severity": 1-3,
    "category": "Attack classification"
  }
}
```

#### Performance Metrics

- **Throughput:** ~10,000 events/second
- **Latency:** <100ms for rule processing
- **CPU Usage:** ~30-40% average
- **Memory:** ~500MB RAM usage

---

### 2. Processing Layer - Logstash

**Version:** 8.x  
**Role:** Log parsing, transformation, and enrichment

#### Pipeline Architecture
```
Input → Filter → Output
  ↓       ↓        ↓
File    GeoIP    Elasticsearch
       JSON
       Date
```

#### Input Configuration
```ruby
input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => json
    type => "suricata"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_suricata"
  }
}
```

**Features:**
- **File Monitoring:** Continuous tail of EVE JSON logs
- **Position Tracking:** Remembers last read position (sincedb)
- **JSON Parsing:** Native JSON codec for efficient parsing
- **Type Tagging:** Labels all events as "suricata" type

#### Filter Configuration

**GeoIP Enrichment:**
```ruby
filter {
  geoip {
    source => "src_ip"
    target => "src_geoip"
    fields => ["city_name", "country_name", "location", "region_name"]
  }
  
  geoip {
    source => "dest_ip"
    target => "dest_geoip"
    fields => ["city_name", "country_name", "location", "region_name"]
  }
}
```

**Date Parsing:**
```ruby
date {
  match => ["timestamp", "ISO8601"]
  target => "@timestamp"
}
```

#### Output Configuration
```ruby
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "suricata-%{+YYYY.MM.dd}"
    document_type => "_doc"
  }
}
```

**Index Strategy:**
- **Daily Indices:** One index per day (suricata-2026.02.12)
- **Rollover:** Automatic daily rollover
- **Retention:** 30 days (configurable via ILM policy)

#### Performance Metrics

- **Events/Second:** ~5,000
- **Latency:** <1 second end-to-end
- **CPU Usage:** ~20-30%
- **Memory:** ~1GB JVM heap

---

### 3. Storage Layer - Elasticsearch

**Version:** 8.19.11  
**Deployment:** Single-node cluster  
**Role:** Centralized log storage and search engine

#### Cluster Configuration
```yaml
Cluster Name: soc-lab-cluster
Node Name: soc-node-1
Discovery Type: single-node (no cluster formation)
Network: localhost only (not exposed externally)
```

#### Index Management

**Index Template:**
```json
{
  "index_patterns": ["suricata-*"],
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "refresh_interval": "5s"
  },
  "mappings": {
    "properties": {
      "@timestamp": {"type": "date"},
      "src_ip": {"type": "ip"},
      "dest_ip": {"type": "ip"},
      "alert.signature": {"type": "keyword"},
      "event_type": {"type": "keyword"}
    }
  }
}
```

**Index Lifecycle:**
```
Day 1-7:   Hot tier (active indexing and queries)
Day 8-30:  Warm tier (read-only, occasional queries)
Day 30+:   Deleted (configurable retention)
```

#### Storage Allocation

| Data Type | Size Estimate | Notes |
|-----------|---------------|-------|
| Alert Events | ~1KB per event | Compressed JSON |
| Flow Data | ~500B per flow | Network metadata |
| HTTP Logs | ~2KB per request | Full request/response |
| Daily Total | ~50-100MB | Varies with traffic |

**30-Day Retention:** ~1.5-3GB total

#### Query Performance

- **Simple Queries:** <100ms
- **Aggregations:** <500ms
- **Complex Searches:** <2 seconds
- **Index Size:** 2,757+ documents = 8.9MB

#### Heap Configuration
```
JVM Heap: 1GB (-Xms1g -Xmx1g)
Reasoning: 50% of available RAM (2GB on t3.large)
Max Recommended: 4GB (Elasticsearch best practice)
```

---

### 4. Visualization Layer

#### Kibana

**Version:** 8.x  
**Port:** 5601  
**Purpose:** Primary analytics and visualization platform

**Features:**
- **Discover:** Ad-hoc log exploration and search
- **Dashboards:** Custom security monitoring views
- **Canvas:** Infographic-style reporting
- **Alerting:** Rule-based notification system
- **Machine Learning:** Anomaly detection (not enabled in lab)

**Key Dashboards:**
1. **Alert Timeline:** Real-time alert visualization
2. **Top Attackers:** Source IP frequency analysis
3. **Attack Patterns:** Signature distribution
4. **Geographic View:** GeoIP mapping of threats
5. **Protocol Analysis:** Traffic breakdown by protocol

**Sample KQL Queries:**
```
# View all alerts
event_type: "alert"

# High severity alerts
event_type: "alert" AND alert.severity: 1

# Custom rule alerts
alert.signature: "CUSTOM*"

# SQL injection attempts
alert.signature: *"SQL Injection"*

# Specific source IP
src_ip: "194.180.48.63"
```

#### EveBox

**Version:** 0.18.0  
**Port:** 5636 (HTTPS)  
**Purpose:** Suricata-specific alert management interface

**Features:**
- **Alert Inbox:** Centralized alert triage workflow
- **Filtering:** Group alerts by signature, source, severity
- **Archiving:** Mark alerts as reviewed/escalated/false positive
- **Escalation:** Flag high-priority threats for investigation
- **Event Drill-down:** Full packet/payload inspection

**Workflow:**
```
New Alert → Inbox → Review → Archive/Escalate → Investigate
```

**Authentication:**
- Username: `admin` (auto-generated)
- Password: Auto-generated on first start (check logs)
- TLS: Self-signed certificate (HTTPS only)

---

### 5. Threat Intelligence Layer

#### Python Enrichment Engine

**Language:** Python 3.12  
**Dependencies:** requests, OTXv2, elasticsearch

#### Architecture
```
┌─────────────────────────────────────────┐
│    analyze_alerts.py (Main Script)      │
├─────────────────────────────────────────┤
│  1. Read alerts from eve.json           │
│  2. Extract unique public IPs           │
│  3. Query AlienVault OTX API            │
│  4. Query AbuseIPDB API                 │
│  5. Calculate composite threat score    │
│  6. Assign verdict (CRITICAL/HIGH/etc.) │
│  7. Generate JSON report                │
│  8. Index to Elasticsearch (optional)   │
└─────────────────────────────────────────┘
```

#### Threat Scoring Algorithm
```python
threat_score = 0

# AlienVault OTX contribution (0-50 points)
if otx_malicious:
    threat_score += 50

# AbuseIPDB contribution (0-50 points)
threat_score += (abuse_confidence * 0.5)

# Cap at 100
threat_score = min(threat_score, 100)

# Assign verdict
if threat_score >= 75:
    verdict = "CRITICAL"
elif threat_score >= 50:
    verdict = "HIGH"
elif threat_score >= 25:
    verdict = "MEDIUM"
else:
    verdict = "LOW"
```

#### API Integration

**AlienVault OTX:**
```python
Endpoint: https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general
Method: GET
Headers: {"X-OTX-API-KEY": "YOUR_KEY"}
Response: {
    "pulse_info": {
        "count": int,
        "pulses": [...]
    }
}
```

**AbuseIPDB:**
```python
Endpoint: https://api.abuseipdb.com/api/v2/check
Method: GET
Headers: {"Key": "YOUR_KEY"}
Params: {"ipAddress": ip, "maxAgeInDays": 90}
Response: {
    "data": {
        "abuseConfidenceScore": int,
        "totalReports": int,
        "countryCode": str
    }
}
```

#### Performance Characteristics

- **Enrichment Time:** 15-30 seconds per IP
- **Rate Limits:** OTX (unlimited), AbuseIPDB (1000/day)
- **Batch Processing:** 10-15 IPs per execution
- **Error Handling:** Retry logic with exponential backoff

---

## Data Flow

### End-to-End Data Pipeline
```
1. Network Packet
   ↓
2. Suricata IDS (enp39s0 interface)
   ↓ Inspection & Rule Matching
3. EVE JSON Log (/var/log/suricata/eve.json)
   ↓ File Monitoring
4. Logstash Input Plugin
   ↓ JSON Parsing
5. Logstash Filter (GeoIP enrichment)
   ↓ Field Transformation
6. Elasticsearch (suricata-YYYY.MM.DD index)
   ↓ Indexing
7. Kibana/EveBox (Query & Visualization)
   ↓ User Interaction
8. Python Scripts (Threat Intel Enrichment)
   ↓ API Calls
9. External Threat Intel Sources
   ↓ Enriched Data
10. Final Report (JSON + Elasticsearch)
```

### Data Flow Diagram
```
Internet Traffic
      ↓
┌─────────────┐
│ EC2 enp39s0 │ ← Network Interface
└─────────────┘
      ↓
┌─────────────┐
│  Suricata   │ ← Packet Capture & Analysis
│  AF_PACKET  │    • 48,270 rules evaluated
└─────────────┘    • ~100µs per packet
      ↓
┌─────────────┐
│  EVE JSON   │ ← Structured Log Output
│  eve.json   │    • JSON format
└─────────────┘    • ~1KB per alert
      ↓
┌─────────────┐
│  Logstash   │ ← Log Processing
│   Input     │    • Tail file continuously
└─────────────┘    • Parse JSON
      ↓
┌─────────────┐
│  Logstash   │ ← Enrichment
│   Filter    │    • Add GeoIP data
└─────────────┘    • Normalize fields
      ↓
┌─────────────┐
│  Logstash   │ ← Output
│   Output    │    • Index to Elasticsearch
└─────────────┘    • Daily indices
      ↓
┌─────────────┐
│Elasticsearch│ ← Storage & Search
│   Index     │    • suricata-2026.02.12
└─────────────┘    • 30-day retention
      ↓
┌─────────────┐
│Kibana/      │ ← Visualization
│EveBox       │    • Dashboards
└─────────────┘    • Alert triage
      ↓
┌─────────────┐
│  Python     │ ← Threat Intel
│  Scripts    │    • Read alerts
└─────────────┘    • Enrich with APIs
      ↓
┌─────────────┐
│  External   │ ← Threat Intelligence
│  APIs       │    • OTX, AbuseIPDB
└─────────────┘    • Return context
```

---

## Network Architecture

### AWS VPC Configuration
```
VPC CIDR: 172.31.0.0/16 (AWS Default VPC)
Subnet: 172.31.0.0/20 (Public subnet)
Internet Gateway: Attached
Route Table: 0.0.0.0/0 → Internet Gateway
```

### Security Group Rules

**Inbound:**
| Type | Protocol | Port | Source | Description |
|------|----------|------|--------|-------------|
| SSH | TCP | 22 | My IP | Management access |
| Custom TCP | TCP | 5601 | My IP | Kibana web UI |
| Custom TCP | TCP | 5636 | My IP | EveBox web UI |

**Outbound:**
| Type | Protocol | Port | Destination | Description |
|------|----------|------|-------------|-------------|
| All Traffic | All | All | 0.0.0.0/0 | Internet access |

### Network Interfaces
```
enp39s0: Primary network interface
  - IP: 172.31.X.X (Private)
  - Public IP: Elastic IP or auto-assigned
  - Suricata monitoring: Enabled
  - Promiscuous mode: Not required (AF_PACKET)
```

---

## Security Design

### Defense in Depth

**Layer 1: Network**
- AWS Security Groups (stateful firewall)
- Restricted ingress (IP whitelisting)
- No public exposure of Elasticsearch

**Layer 2: Host**
- SSH key-based authentication only
- fail2ban for brute force protection
- Automatic security updates (unattended-upgrades)
- Minimal attack surface (only required services)

**Layer 3: Application**
- Kibana/EveBox behind authentication
- Elasticsearch bound to localhost only
- No default credentials in use

**Layer 4: Data**
- Encrypted connections (HTTPS for EveBox)
- API keys stored locally (not in git)
- Log retention limits (30 days)

### Threat Model

**Assets:**
- Security monitoring data (alerts, logs)
- Threat intelligence API keys
- AWS access credentials

**Threats:**
- Unauthorized access to monitoring dashboards
- API key compromise
- Log tampering or deletion
- Resource exhaustion (DoS)

**Mitigations:**
- IP whitelisting (Security Groups)
- Strong authentication (SSH keys, MFA)
- Read-only Elasticsearch indices after indexing
- Resource limits and monitoring

---

## Scalability Considerations

### Current Capacity

| Metric | Current | Max Capacity |
|--------|---------|--------------|
| Events/Second | ~10,000 | ~15,000 |
| Storage (30 days) | ~3GB | ~10GB |
| Concurrent Users | 1-5 | ~10 |
| API Queries/Day | ~50 | ~1,000 |

### Horizontal Scaling Path

**Phase 1: Current (Single Node)**
```
[EC2 Instance]
  └─ All services on one host
```

**Phase 2: Separate ELK Stack (3 nodes)**
```
[Suricata Node] → [Logstash Node] → [Elasticsearch Cluster (3 nodes)]
                                    ↓
                              [Kibana Node]
```

**Phase 3: Production Scale (N nodes)**
```
[Suricata Sensors (N)] → [Logstash Cluster] → [Elasticsearch Cluster]
                                              ↓
                                        [Kibana/API Nodes]
                                              ↓
                                        [Load Balancer]
```

### Vertical Scaling Options

| Instance Type | vCPU | RAM | EBS | Use Case |
|---------------|------|-----|-----|----------|
| t3.large (current) | 2 | 8GB | 30GB | Lab/Small |
| t3.xlarge | 4 | 16GB | 50GB | Medium |
| m5.2xlarge | 8 | 32GB | 100GB | Production |

---

## Performance Optimization

### Elasticsearch Tuning
```yaml
# JVM Heap: 50% of available RAM, max 4GB
-Xms1g
-Xmx1g

# Index refresh interval (affects search latency)
index.refresh_interval: 5s

# Replica count (0 for single node)
number_of_replicas: 0

# Shard count (1 per index for small data)
number_of_shards: 1
```

### Logstash Tuning
```ruby
# Pipeline workers (matches CPU cores)
pipeline.workers: 2

# Batch size (events processed together)
pipeline.batch.size: 125

# Batch delay (max wait time)
pipeline.batch.delay: 50
```

### Suricata Tuning
```yaml
# Thread count (matches CPU cores)
threading.cpu-affinity: 0-1

# Packet buffer size
af-packet.buffer-size: 32768

# Ring size (packet queue)
af-packet.ring-size: 2048
```

---

## Monitoring & Alerting

### System Monitoring
```bash
# CPU and Memory
htop

# Disk Usage
df -h /var/log/suricata
df -h /var/lib/elasticsearch

# Network Stats
sudo iftop -i enp39s0

# Service Status
systemctl status elasticsearch kibana logstash suricata
```

### Elasticsearch Monitoring
```bash
# Cluster health
curl localhost:9200/_cluster/health?pretty

# Index stats
curl localhost:9200/_cat/indices?v

# Node stats
curl localhost:9200/_nodes/stats?pretty
```

### Log Monitoring
```bash
# Suricata logs
sudo tail -f /var/log/suricata/suricata.log

# Elasticsearch logs
sudo journalctl -u elasticsearch -f

# Logstash logs
sudo journalctl -u logstash -f
```

---

## Disaster Recovery

### Backup Strategy

**What to Backup:**
1. Configuration files
2. Custom Suricata rules
3. Kibana dashboards (export as JSON)
4. Elasticsearch indices (optional - logs are ephemeral)

**Backup Commands:**
```bash
# Configurations
sudo tar -czf soc-backup-$(date +%Y%m%d).tar.gz \
  /etc/suricata/suricata.yaml \
  /etc/suricata/rules/custom/ \
  /etc/logstash/conf.d/ \
  /etc/elasticsearch/elasticsearch.yml \
  /etc/kibana/kibana.yml

# Copy to S3 (optional)
aws s3 cp soc-backup-$(date +%Y%m%d).tar.gz s3://your-bucket/
```

### Recovery Procedures

**Service Failure Recovery:**
```bash
# Restart individual service
sudo systemctl restart SERVICE_NAME

# Check logs for errors
sudo journalctl -u SERVICE_NAME -n 100

# Restore from backup if config corrupted
sudo tar -xzf soc-backup-YYYYMMDD.tar.gz -C /
```

**Complete System Rebuild:**
1. Launch new EC2 instance
2. Follow installation guide
3. Restore configurations from backup
4. Update DNS/IP references
5. Verify all services

---

## Technology Stack Summary

| Layer | Technology | Version | Purpose |
|-------|------------|---------|---------|
| **Infrastructure** | AWS EC2 | - | Cloud hosting |
| | Ubuntu Server | 24.04 LTS | Operating system |
| **Detection** | Suricata | 8.0.3 | Network IDS |
| **Processing** | Logstash | 8.x | Log pipeline |
| **Storage** | Elasticsearch | 8.19.11 | Search engine |
| **Visualization** | Kibana | 8.x | Analytics platform |
| | EveBox | 0.18.0 | Alert management |
| **Enrichment** | Python | 3.12 | Threat intel scripts |
| **Threat Intel** | AlienVault OTX | API v1 | Threat intelligence |
| | AbuseIPDB | API v2 | IP reputation |

---

## Performance Benchmarks

### Current System Performance

| Metric | Value | Notes |
|--------|-------|-------|
| Alert Processing Latency | <2s | Detection → Elasticsearch |
| Threat Intel Enrichment | 15-30s/IP | API call latency |
| Kibana Query Response | <500ms | Simple queries |
| Dashboard Load Time | <2s | Initial load |
| Elasticsearch Indexing | ~1000 events/s | Sustained rate |
| Storage Growth | ~50MB/day | With current traffic |

---

## Future Architecture Enhancements

### Planned Improvements

1. **SOAR Integration**
   - TheHive for case management
   - Cortex for automated enrichment
   - Automated response playbooks

2. **Machine Learning**
   - Elasticsearch ML for anomaly detection
   - Behavioral analysis for zero-day threats
   - Predictive alerting

3. **Additional Data Sources**
   - Syslog from network devices
   - Cloud Trail logs from AWS
   - Application logs from services

4. **High Availability**
   - Elasticsearch cluster (3+ nodes)
   - Load-balanced Kibana instances
   - Logstash cluster for redundancy

---

## References

- **Suricata Documentation:** https://suricata.readthedocs.io/
- **Elasticsearch Guide:** https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html
- **MITRE ATT&CK:** https://attack.mitre.org/
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework

---

*Last Updated: February 2026*
