# SECURITY INCIDENT REPORT
## SOC Detection & Threat Intelligence Lab

---

## INCIDENT SUMMARY

**Incident ID:** INC-2026-001  
**Date Detected:** February 12, 2026  
**Severity:** HIGH  
**Status:** CONTAINED  
**Analyst:** Hassan Omotosho Folarori  
**Report Date:** February 12, 2026

---

## EXECUTIVE SUMMARY

During routine security monitoring, the SOC detected multiple high-confidence malicious activities targeting our infrastructure. Through integration with threat intelligence platforms (AlienVault OTX, AbuseIPDB) and custom detection rules, we identified 8 HIGH-threat IP addresses conducting SSH brute force attacks, port scanning, and connections from known compromised hosts. This report documents the detection, analysis, containment, and remediation activities performed in accordance with the NIST Cybersecurity Framework.

**Key Findings:**
- 8 malicious IPs with 100% confidence scores (4,909-55,162 abuse reports)
- SSH brute force attacks from multiple geographic locations
- Traffic from Spamhaus DROP-listed infrastructure
- Known compromised/hostile host communications
- Custom detection rules successfully identified attack patterns

---

## NIST CYBERSECURITY FRAMEWORK RESPONSE

### 1. IDENTIFY

#### Assets Affected
- **Primary Target:** AWS EC2 Instance (Ubuntu 24.04)
  - Instance ID: i-0a7562a267731e45a
  - IP Address: 172.31.5.250
  - Services: SSH (22), Kibana (5601), EveBox (5636)

#### Business Impact Assessment
- **Confidentiality:** MEDIUM - Potential unauthorized access attempts
- **Integrity:** LOW - No evidence of successful compromise
- **Availability:** LOW - Services remained operational
- **Overall Risk:** MEDIUM

---

### 2. PROTECT

#### Existing Security Controls
1. **Network Intrusion Detection System (IDS)**
   - Platform: Suricata 8.0.3
   - Rules: 48,253 signatures (ET Open + 17 custom rules)
   - Monitoring: Real-time traffic analysis

2. **SIEM Platform**
   - Stack: Elasticsearch + Logstash + Kibana (ELK)
   - Log Retention: 7 days
   - Alert Correlation: Enabled

3. **Threat Intelligence Integration**
   - AlienVault OTX: Threat pulse monitoring
   - AbuseIPDB: IP reputation checks (1000 queries/day)
   - Automated enrichment pipeline

4. **AWS Security Groups**
   - SSH: Restricted to authorized IPs
   - Web Services: Limited exposure
   - Default Deny: All other ports

---

### 3. DETECT

#### Detection Timeline

| Time (UTC) | Event | Source | Signature |
|------------|-------|--------|-----------|
| 07:28:24 | SSH Brute Force | 24.84.207.4 | CUSTOM BRUTEFORCE SSH Multiple Attempts |
| 07:31:16 | SSH Brute Force | 24.84.207.4 | CUSTOM BRUTEFORCE SSH Multiple Attempts |
| 07:32:48 | SSH Brute Force | 24.84.207.4 | CUSTOM BRUTEFORCE SSH Multiple Attempts |
| Various | Malicious IPs | Multiple | ET CINS Active Threat Intelligence |

#### Custom Detection Rules Triggered
1. **CUSTOM BRUTEFORCE SSH Multiple Attempts** (SID: 1000014)
   - Threshold: 5 attempts in 60 seconds
   - Action: Alert + Log

2. **CUSTOM MALWARE Suspicious User-Agent** (SID: 1000001, 1000003)
   - Pattern: BlackSun, Metasploit signatures
   - Action: Alert + Block recommended

#### Threat Intelligence Findings

**Top Malicious IPs Detected:**

| IP Address | Country | Confidence | Reports | Threat Type |
|------------|---------|------------|---------|-------------|
| 80.94.92.168 | Romania | 100% | 55,162 | Spamhaus DROP Listed |
| 194.180.48.63 | Poland | 100% | 14,659 | Compromised Host |
| 178.20.210.151 | Finland | 100% | 12,221 | Active Threat Intel |
| 139.19.117.131 | Germany | 100% | 4,909 | SSH Brute Force |
| 18.218.118.203 | USA | 100% | 539 | Protocol Anomaly |
| 206.189.106.27 | Netherlands | 100% | 413 | SSH Scanning |
| 221.151.84.6 | South Korea | 100% | 258 | SSH Brute Force |
| 178.62.243.132 | Netherlands | 100% | 108 | SSH Brute Force |

**Attack Patterns:**
- SSH Brute Force: 4 sources
- Port Scanning: 3 sources  
- Known Botnet Infrastructure: 2 sources
- Protocol Anomalies: Multiple instances

---

### 4. RESPOND

#### Immediate Actions Taken

1. **Alert Triage** (T+0 minutes)
   - Alerts reviewed in EveBox and Kibana
   - High-confidence threats prioritized
   - Automated threat intelligence enrichment executed

2. **Incident Analysis** (T+15 minutes)
   - IOC extraction from 683 alerts
   - 197 unique IPs analyzed
   - 8 confirmed malicious sources identified
   - Attack vectors documented

3. **Containment Measures** (T+30 minutes)
   - AWS Security Group rules updated
   - Malicious IPs added to blocklist
   - SSH access logs reviewed
   - No successful authentication attempts found

#### Recommended Actions

**Immediate (0-24 hours):**
-  Block identified malicious IPs at firewall
-  Enable fail2ban for automated SSH blocking
-  Implement geo-blocking for high-risk countries
-  Enable MFA for all SSH access

**Short-term (1-7 days):**
- Change SSH default port
- Implement VPN requirement for administrative access
- Deploy honeypot for attack attribution
- Schedule penetration testing

**Long-term (1-3 months):**
- Implement Zero Trust architecture
- Deploy EDR solution
- Establish 24/7 SOC operations
- Conduct security awareness training

---

### 5. RECOVER

#### Remediation Activities

1. **Network Security Hardening**
```bash
   # Firewall rules implemented
   sudo ufw deny from 80.94.92.168
   sudo ufw deny from 194.180.48.63
   sudo ufw deny from 178.20.210.151
   # [All 8 malicious IPs blocked]
```

2. **SSH Hardening**
   - Disabled password authentication
   - Enabled key-based authentication only
   - Implemented connection rate limiting

3. **Monitoring Enhancement**
   - Added custom rules for new attack patterns
   - Increased log retention to 30 days
   - Configured automated threat intel updates

4. **Validation**
   - No successful breaches detected
   - All services operational
   - Threat intelligence feeds updated
   - Custom detection rules validated

---

## INDICATORS OF COMPROMISE (IOCs)

### Malicious IP Addresses
```
80.94.92.168        # Romania - Spamhaus DROP
194.180.48.63       # Poland - Compromised Host
178.20.210.151      # Finland - Active Threat
139.19.117.131      # Germany - SSH Brute Force
18.218.118.203      # USA - Protocol Anomaly
206.189.106.27      # Netherlands - SSH Scan
221.151.84.6        # South Korea - SSH Brute Force
178.62.243.132      # Netherlands - SSH Brute Force
```

### Attack Signatures
- SSH-2.0-Go version string (likely automated tool)
- Multiple authentication failures
- Port scanning patterns (SYN floods)
- Suspicious user-agents (BlackSun, Metasploit)

---

## LESSONS LEARNED

### What Went Well
 Custom detection rules effectively identified attack patterns  
 Threat intelligence integration provided valuable context  
 SELK stack performed reliably under load  
 Alert correlation identified related activities  
 No successful compromise occurred  

### Areas for Improvement
 Initial security group rules too permissive  
 Lack of automated blocking for repeated offenders  
 No geo-blocking for high-risk regions  
 Limited visibility into application-layer attacks  
 Manual threat intelligence enrichment process  

### Recommendations
1. Implement automated response playbooks
2. Deploy fail2ban with IP reputation integration
3. Enable CloudWatch anomaly detection
4. Establish formal incident response procedures
5. Conduct quarterly threat hunting exercises

---

## TECHNICAL APPENDIX

### Detection Infrastructure

**Suricata Configuration:**
```yaml
Version: 8.0.3
Rules Loaded: 48,253
Custom Rules: 17
Interface: enp39s0
Mode: IDS (Inline capable)
```

**Custom Detection Rules:**
- CUSTOM BRUTEFORCE SSH Multiple Attempts
- CUSTOM MALWARE Suspicious User-Agent BlackSun
- CUSTOM MALWARE Metasploit User-Agent
- CUSTOM SCAN Potential Port Scan
- CUSTOM WEB SQL Injection
- [12 additional custom rules]

**Threat Intelligence Sources:**
- AlienVault OTX (Free tier)
- AbuseIPDB (1000 queries/day)
- Emerging Threats Open ruleset

---

## EVIDENCE & ARTIFACTS

### Log Samples

**SSH Brute Force Attack:**
```json
{
  "timestamp": "2026-02-12T07:28:24.431587+0000",
  "event_type": "alert",
  "src_ip": "24.84.207.4",
  "dest_ip": "172.31.5.250",
  "proto": "TCP",
  "alert": {
    "signature": "CUSTOM BRUTEFORCE SSH Multiple Attempts",
    "severity": 2,
    "signature_id": 1000014
  }
}
```

**Threat Intelligence Enrichment:**
```json
{
  "ip": "194.180.48.63",
  "threat_score": 50,
  "verdict": "HIGH",
  "abuseipdb": {
    "confidence_score": 100,
    "total_reports": 14659,
    "country": "PL"
  }
}
```

---

## CONCLUSION

This incident demonstrates the effectiveness of layered security controls combined with threat intelligence integration. While multiple malicious actors attempted to compromise our infrastructure through SSH brute force attacks and other methods, all attempts were detected and blocked before any successful breach occurred.

The custom detection rules developed for this SOC lab successfully identified attack patterns that may have been missed by signature-based detection alone. The integration with AlienVault OTX and AbuseIPDB provided critical context, allowing for confident classification of threats and prioritization of response activities.

All recommended containment and remediation activities have been implemented. Continued monitoring will ensure that these threat actors do not return through alternative methods. This incident has been fully documented and can be referenced for future security enhancements and training purposes.

**Incident Status:** CLOSED  
**Final Risk Level:** LOW (after remediation)

---

**Report Prepared By:** Hassan Omotosho Folarori  
**Title:** SOC Analyst / Security Engineer  
**Date:** February 12, 2026  
**Signature:** H.O
