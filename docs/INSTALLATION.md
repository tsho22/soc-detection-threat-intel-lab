#  Installation Guide - SOC Detection & Threat Intelligence Lab

Complete step-by-step guide to deploy this SOC Detection Lab from scratch.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Phase 1: AWS Infrastructure Setup](#phase-1-aws-infrastructure-setup)
- [Phase 2: System Preparation](#phase-2-system-preparation)
- [Phase 3: Elasticsearch Installation](#phase-3-elasticsearch-installation)
- [Phase 4: Kibana Installation](#phase-4-kibana-installation)
- [Phase 5: Logstash Installation](#phase-5-logstash-installation)
- [Phase 6: Suricata IDS Installation](#phase-6-suricata-ids-installation)
- [Phase 7: EveBox Installation](#phase-7-evebox-installation-optional)
- [Phase 8: Custom Detection Rules](#phase-8-custom-detection-rules)
- [Phase 9: Threat Intelligence Setup](#phase-9-threat-intelligence-setup)
- [Phase 10: Verification & Testing](#phase-10-verification--testing)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Resources

- **AWS Account** (Free Tier eligible)
- **Time Required:** 2-4 hours for complete setup
- **Technical Skills:** Basic Linux command line knowledge
- **Local Machine:** SSH client installed

### Cost Estimate

- **t3.large EC2 instance:** ~$0.08/hour (Free Tier: 750 hours/month for 12 months)
- **30GB EBS Storage:** ~$3/month
- **Data Transfer:** Minimal (mostly inbound)
- **Total Monthly Cost:** ~$5-10 (or FREE with Free Tier)

---

## Phase 1: AWS Infrastructure Setup

### Step 1.1: Create AWS Account

1. Go to https://aws.amazon.com
2. Click **"Create an AWS Account"**
3. Follow the registration process
4. Add payment method (required even for Free Tier)
5. Verify your phone number

### Step 1.2: Secure Your Root Account
```bash
# Best practices:
1. Enable MFA on root account
2. Create an IAM admin user for daily operations
3. Never use root account for regular tasks
```

### Step 1.3: Launch EC2 Instance

**Navigate to EC2:**
1. AWS Console → Services → EC2
2. Click **"Launch Instance"**

**Instance Configuration:**

| Setting | Value |
|---------|-------|
| **Name** | SOC-Detection-Lab |
| **AMI** | Ubuntu Server 24.04 LTS (64-bit x86) |
| **Instance Type** | t3.large (2 vCPU, 8GB RAM) |
| **Key Pair** | Create new → Name: `soc-lab-key` → Download .pem file |
| **Storage** | 30 GB gp3 SSD |

**Network Settings:**

Create new security group: `SOC-Lab-SG`

**Inbound Rules:**

| Type | Protocol | Port | Source | Description |
|------|----------|------|--------|-------------|
| SSH | TCP | 22 | My IP | SSH access |
| Custom TCP | TCP | 5601 | My IP | Kibana |
| Custom TCP | TCP | 5636 | My IP | EveBox |

**IMPORTANT:** Replace "My IP" with your actual public IP address.

### Step 1.4: Connect to Your Instance

**For Linux/Mac:**
```bash
# Set proper permissions on key file
chmod 400 ~/Downloads/soc-lab-key.pem

# Connect via SSH (replace with your EC2 public IP)
ssh -i ~/Downloads/soc-lab-key.pem ubuntu@YOUR-EC2-PUBLIC-IP
```

**For Windows (using PuTTY):**

1. Convert .pem to .ppk using PuTTYgen
2. Open PuTTY
3. Host: `ubuntu@YOUR-EC2-PUBLIC-IP`
4. Connection → SSH → Auth → Browse for .ppk file
5. Click **Open**

---

## Phase 2: System Preparation

### Step 2.1: Update System
```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y wget curl gnupg2 software-properties-common \
  apt-transport-https ca-certificates openjdk-11-jdk unzip jq

# Verify Java installation
java -version
# Should show: openjdk version "11.x.x"
```

### Step 2.2: Configure System Settings for ELK
```bash
# Increase virtual memory for Elasticsearch
sudo sysctl -w vm.max_map_count=262144

# Make it permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Verify
sudo sysctl -p
```

### Step 2.3: Configure Hostname (Optional)
```bash
# Set a friendly hostname
sudo hostnamectl set-hostname soc-lab

# Update /etc/hosts
echo "127.0.0.1 soc-lab" | sudo tee -a /etc/hosts
```

---

## Phase 3: Elasticsearch Installation

### Step 3.1: Add Elasticsearch Repository
```bash
# Import Elasticsearch GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add Elasticsearch repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
  https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Update package list
sudo apt update
```

### Step 3.2: Install Elasticsearch
```bash
# Install Elasticsearch
sudo apt install elasticsearch -y

# IMPORTANT: Save the auto-generated password shown during installation
# If you missed it, you can reset it later
```

### Step 3.3: Configure Elasticsearch
```bash
# Backup original config
sudo cp /etc/elasticsearch/elasticsearch.yml \
  /etc/elasticsearch/elasticsearch.yml.backup

# Edit configuration
sudo nano /etc/elasticsearch/elasticsearch.yml
```

**Add/modify these settings:**
```yaml
# Cluster name
cluster.name: soc-lab-cluster

# Node name
node.name: soc-node-1

# Network settings
network.host: localhost
http.port: 9200

# Discovery settings
discovery.type: single-node

# Security settings (disable for lab - enable in production!)
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
```

**Save and exit** (Ctrl+X, Y, Enter)

### Step 3.4: Configure JVM Heap Memory
```bash
# Edit JVM options
sudo nano /etc/elasticsearch/jvm.options.d/heap.options
```

**Add these lines:**
```
# Set heap size (50% of available RAM, max 4GB)
-Xms1g
-Xmx1g
```

**Save and exit**

### Step 3.5: Start Elasticsearch
```bash
# Enable Elasticsearch to start on boot
sudo systemctl enable elasticsearch

# Start Elasticsearch
sudo systemctl start elasticsearch

# Check status
sudo systemctl status elasticsearch

# Wait 30 seconds for Elasticsearch to fully start
sleep 30

# Test Elasticsearch
curl -X GET "localhost:9200"
```

**Expected output:**
```json
{
  "name" : "soc-node-1",
  "cluster_name" : "soc-lab-cluster",
  "version" : {
    "number" : "8.x.x"
  }
}
```

---

## Phase 4: Kibana Installation

### Step 4.1: Install Kibana
```bash
# Install Kibana (from same repository)
sudo apt install kibana -y
```

### Step 4.2: Configure Kibana
```bash
# Backup original config
sudo cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.backup

# Edit configuration
sudo nano /etc/kibana/kibana.yml
```

**Add/modify these settings:**
```yaml
# Server configuration
server.port: 5601
server.host: "0.0.0.0"
server.name: "soc-kibana"

# Elasticsearch configuration
elasticsearch.hosts: ["http://localhost:9200"]

# Disable security for lab environment
xpack.security.enabled: false
xpack.encryptedSavedObjects.encryptionKey: "min-32-character-long-strong-encryption-key-here-change-this-12345"
```

**Save and exit**

### Step 4.3: Start Kibana
```bash
# Enable and start Kibana
sudo systemctl enable kibana
sudo systemctl start kibana

# Check status
sudo systemctl status kibana

# Monitor logs (wait for "http server running")
sudo journalctl -u kibana -f
```

Press **Ctrl+C** to exit log viewer after you see "http server running"

### Step 4.4: Access Kibana

Open browser and navigate to:
```
http://YOUR-EC2-PUBLIC-IP:5601
```

You should see the Kibana welcome screen (may take 2-3 minutes to load first time).

---

## Phase 5: Logstash Installation

### Step 5.1: Install Logstash
```bash
# Install Logstash
sudo apt install logstash -y

# Enable Logstash
sudo systemctl enable logstash
```

### Step 5.2: Create Logstash Pipeline
```bash
# Create pipeline directory
sudo mkdir -p /etc/logstash/conf.d

# Create Suricata pipeline configuration
sudo nano /etc/logstash/conf.d/suricata-pipeline.conf
```

**Add this configuration:**
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

filter {
  if [type] == "suricata" {
    date {
      match => [ "timestamp", "ISO8601" ]
      target => "@timestamp"
    }
    
    # Add GeoIP enrichment for source and destination IPs
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "src_geoip"
      }
    }
    
    if [dest_ip] {
      geoip {
        source => "dest_ip"
        target => "dest_geoip"
      }
    }
  }
}

output {
  if [type] == "suricata" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "suricata-%{+YYYY.MM.dd}"
    }
  }
  
  # Debug output (optional - comment out in production)
  stdout {
    codec => rubydebug
  }
}
```

**Save and exit**

### Step 5.3: Configure Logstash Permissions
```bash
# Add logstash user to suricata group (we'll create suricata user later)
# This will be done after Suricata installation
```

---

## Phase 6: Suricata IDS Installation

### Step 6.1: Install Suricata
```bash
# Add Suricata repository
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update

# Install Suricata
sudo apt install suricata -y

# Check Suricata version
sudo suricata --build-info | grep "Suricata"
```

### Step 6.2: Configure Suricata
```bash
# Backup original config
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup

# Edit Suricata configuration
sudo nano /etc/suricata/suricata.yaml
```

**Key configurations to modify:**

1. **Find the `vars` section and set HOME_NET:**
```yaml
vars:
  address-groups:
    HOME_NET: "[172.31.0.0/16]"  # Your VPC CIDR (check in AWS VPC console)
    EXTERNAL_NET: "!$HOME_NET"
```

2. **Find the `af-packet` section and configure interface:**
```yaml
af-packet:
  - interface: enp39s0  # Your primary network interface
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

3. **Enable EVE JSON logging (should already be enabled):**
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: yes
            metadata: yes
        - http:
            extended: yes
        - dns:
            enabled: yes
        - tls:
            extended: yes
        - files:
            force-magic: no
        - flow
```

**Save and exit**

### Step 6.3: Update Suricata Rules
```bash
# Update Suricata rules using suricata-update
sudo suricata-update

# Enable Emerging Threats Open ruleset
sudo suricata-update enable-source et/open

# Update rules
sudo suricata-update

# Verify rules are loaded
sudo ls -lh /var/lib/suricata/rules/
```

### Step 6.4: Test Configuration
```bash
# Test Suricata configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Look for "Configuration provided was successfully loaded"
```

### Step 6.5: Start Suricata
```bash
# Create log directory with proper permissions
sudo mkdir -p /var/log/suricata
sudo chown -R suricata:suricata /var/log/suricata

# Start Suricata
sudo systemctl enable suricata
sudo systemctl start suricata

# Check status
sudo systemctl status suricata

# Monitor logs
sudo tail -f /var/log/suricata/suricata.log
```

Press **Ctrl+C** to exit

### Step 6.6: Configure Logstash Permissions (Now)
```bash
# Add logstash user to suricata group
sudo usermod -a -G suricata logstash

# Verify
groups logstash
# Should show: logstash suricata

# Give read permissions to suricata group
sudo chmod g+r /var/log/suricata/eve.json
```

### Step 6.7: Start Logstash
```bash
# Start Logstash
sudo systemctl start logstash

# Check status (may take 30-60 seconds to start)
sudo systemctl status logstash

# Monitor logs
sudo tail -f /var/log/logstash/logstash-plain.log
```

---

## Phase 7: EveBox Installation (Optional)

### Step 7.1: Download and Install EveBox
```bash
# Download EveBox
cd /tmp
wget https://evebox.org/files/release/0.18.0/evebox-0.18.0-linux-x64.zip

# Install unzip if needed
sudo apt install -y unzip

# Extract
unzip evebox-0.18.0-linux-x64.zip

# Move to system location
sudo cp evebox /usr/local/bin/
sudo chmod +x /usr/local/bin/evebox

# Verify installation
/usr/local/bin/evebox --version
```

### Step 7.2: Create EveBox Service
```bash
# Create systemd service file
sudo nano /etc/systemd/system/evebox.service
```

**Add this configuration:**
```ini
[Unit]
Description=EveBox Server
After=network.target elasticsearch.service
Wants=elasticsearch.service

[Service]
Type=simple
User=root
WorkingDirectory=/var/log/suricata
ExecStart=/usr/local/bin/evebox server \
    --elasticsearch http://localhost:9200 \
    --index suricata \
    --host 0.0.0.0 \
    --port 5636
StandardOutput=journal
StandardError=journal
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Save and exit**

### Step 7.3: Start EveBox
```bash
# Reload systemd
sudo systemctl daemon-reload

# Start EveBox
sudo systemctl enable evebox
sudo systemctl start evebox

# Check status
sudo systemctl status evebox

# Get auto-generated password
sudo journalctl -u evebox | grep "password"
# Save the username and password shown
```

### Step 7.4: Access EveBox

Open browser and navigate to:
```
https://YOUR-EC2-PUBLIC-IP:5636
```

**Note:** You'll see a security warning (self-signed certificate). Click "Advanced" → "Proceed anyway"

**Login with the credentials shown in the logs**

---

## Phase 8: Custom Detection Rules

### Step 8.1: Clone This Repository
```bash
# Navigate to home directory
cd ~

# Clone the repository
git clone https://github.com/YOUR-USERNAME/soc-detection-threat-intel-lab.git

# Navigate to the repository
cd soc-detection-threat-intel-lab
```

### Step 8.2: Deploy Custom Rules
```bash
# Create custom rules directory
sudo mkdir -p /etc/suricata/rules/custom

# Copy custom rules
sudo cp configs/suricata/local.rules /etc/suricata/rules/custom/

# Verify rules are copied
sudo cat /etc/suricata/rules/custom/local.rules | head -20
```

### Step 8.3: Enable Custom Rules in Suricata
```bash
# Edit Suricata config
sudo nano /etc/suricata/suricata.yaml
```

**Find the `rule-files:` section and add:**
```yaml
rule-files:
  - suricata.rules
  - /etc/suricata/rules/custom/local.rules
```

**Save and exit**

### Step 8.4: Test and Restart Suricata
```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# If successful, restart Suricata
sudo systemctl restart suricata

# Verify custom rules are loaded
sudo tail -100 /var/log/suricata/suricata.log | grep -i "rules loaded"
```

---

## Phase 9: Threat Intelligence Setup

### Step 9.1: Install Python Dependencies
```bash
# Navigate to threat intel directory
cd ~/soc-detection-threat-intel-lab/scripts/threat-intel

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### Step 9.2: Configure API Keys
```bash
# Copy example config
cp config.py.example config.py

# Edit config and add your API keys
nano config.py
```

**Update with your actual API keys:**
```python
OTX_API_KEY = "your_actual_otx_api_key_here"
ABUSEIPDB_API_KEY = "your_actual_abuseipdb_key_here"
```

**Save and exit**

### Step 9.3: Get API Keys

**AlienVault OTX:**
1. Sign up at https://otx.alienvault.com
2. Go to Settings → API Integration
3. Copy your API key

**AbuseIPDB:**
1. Sign up at https://www.abuseipdb.com/register
2. Go to Account → API
3. Copy your API key (free tier: 1000 queries/day)

---

## Phase 10: Verification & Testing

### Step 10.1: Verify All Services Are Running
```bash
# Check all services
sudo systemctl status elasticsearch --no-pager | grep Active
sudo systemctl status kibana --no-pager | grep Active
sudo systemctl status logstash --no-pager | grep Active
sudo systemctl status suricata --no-pager | grep Active
sudo systemctl status evebox --no-pager | grep Active
```

**All should show: `Active: active (running)`**

### Step 10.2: Generate Test Traffic
```bash
# Generate test alerts
curl http://testmynids.org/uid/index.html

# Wait 30 seconds
sleep 30

# Check if alerts were generated
sudo tail -20 /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### Step 10.3: Verify Data Flow
```bash
# Check Elasticsearch indices
curl -X GET "localhost:9200/_cat/indices?v" | grep suricata

# Count documents in Suricata index
curl -X GET "localhost:9200/suricata-*/_count?pretty"

# Should show documents > 0
```

### Step 10.4: Create Kibana Index Pattern

1. Open Kibana: `http://YOUR-EC2-PUBLIC-IP:5601`
2. Menu → Management → Stack Management
3. Click "Data Views" (under Kibana)
4. Click "Create data view"
5. Index pattern: `suricata-*`
6. Timestamp field: `@timestamp`
7. Click "Save data view to Kibana"

### Step 10.5: View Alerts in Kibana

1. Menu → Analytics → Discover
2. Select `suricata-*` data view
3. Search: `event_type: "alert"`
4. You should see your alerts!

### Step 10.6: Run Attack Simulations
```bash
# Navigate to attack simulation directory
cd ~/soc-detection-threat-intel-lab/scripts/attack-simulation

# Make scripts executable
chmod +x *.sh

# Run C2 simulation
./c2_simulation.sh

# Run web attacks
./web_attacks.sh

# Wait 30 seconds
sleep 30

# Check for CUSTOM alerts
sudo grep 'CUSTOM' /var/log/suricata/eve.json | tail -10 | jq -r '.alert.signature'
```

### Step 10.7: Run Threat Intelligence Analysis
```bash
# Navigate to threat intel directory
cd ~/soc-detection-threat-intel-lab/scripts/threat-intel

# Activate virtual environment
source venv/bin/activate

# Run analysis
python3 analyze_alerts.py

# Check results
cat ~/soc-detection-threat-intel-lab/results/enriched_alerts_sample.json | jq '.'
```

---

## Troubleshooting

### Elasticsearch Issues

**Problem:** Elasticsearch won't start
```bash
# Check logs
sudo journalctl -u elasticsearch -n 50 --no-pager

# Common fix: Adjust heap memory
sudo nano /etc/elasticsearch/jvm.options.d/heap.options
# Set to: -Xms1g and -Xmx1g

# Restart
sudo systemctl restart elasticsearch
```

**Problem:** "max virtual memory areas too low"
```bash
# Fix
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

---

### Kibana Issues

**Problem:** Kibana shows "Kibana server is not ready yet"
```bash
# Wait 2-3 minutes, then check logs
sudo journalctl -u kibana -n 50 --no-pager

# Restart if needed
sudo systemctl restart kibana
```

---

### Logstash Issues

**Problem:** Logstash not reading Suricata logs
```bash
# Fix permissions
sudo usermod -a -G suricata logstash
sudo chmod g+r /var/log/suricata/eve.json

# Remove sincedb file
sudo rm -f /var/lib/logstash/sincedb_suricata

# Restart Logstash
sudo systemctl restart logstash
```

---

### Suricata Issues

**Problem:** Suricata not capturing traffic
```bash
# Verify interface
ip addr show

# Update suricata.yaml with correct interface
sudo nano /etc/suricata/suricata.yaml
# Change: interface: enp39s0 (or your actual interface)

# Restart
sudo systemctl restart suricata
```

**Problem:** Rules not loading
```bash
# Update rules
sudo suricata-update

# Test config
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

---

### Network Access Issues

**Problem:** Can't access Kibana/EveBox from browser
```bash
# Check AWS Security Group:
# 1. EC2 → Security Groups → SOC-Lab-SG
# 2. Verify inbound rules for ports 5601 and 5636
# 3. Source should be "My IP"

# Check if services are listening
sudo netstat -tulpn | grep -E '5601|5636'
```

---

## Post-Installation Security Hardening

### Recommended Next Steps
```bash
# 1. Enable fail2ban for SSH protection
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# 2. Enable automatic security updates
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure --priority=low unattended-upgrades

# 3. Configure firewall (UFW)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 5601/tcp
sudo ufw allow 5636/tcp
sudo ufw enable

# 4. Disable password authentication (key-only)
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no
sudo systemctl restart ssh
```

---

## System Resource Monitoring
```bash
# Monitor system resources
htop

# Check disk usage
df -h

# Check memory usage
free -h

# Check Elasticsearch cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"
```

---

## Backup Important Files
```bash
# Create backup directory
mkdir -p ~/backups

# Backup configurations
sudo cp /etc/suricata/suricata.yaml ~/backups/
sudo cp /etc/logstash/conf.d/suricata-pipeline.conf ~/backups/
sudo cp /etc/elasticsearch/elasticsearch.yml ~/backups/
sudo cp /etc/kibana/kibana.yml ~/backups/

# Backup custom rules
sudo cp /etc/suricata/rules/custom/local.rules ~/backups/
```

---

## Verification Checklist

- [ ] Elasticsearch running and accessible
- [ ] Kibana accessible at http://YOUR-IP:5601
- [ ] Logstash processing Suricata logs
- [ ] Suricata capturing traffic and generating alerts
- [ ] EveBox accessible at https://YOUR-IP:5636
- [ ] Custom rules loaded (48,270 total rules)
- [ ] Test alerts generated and visible in Kibana
- [ ] Threat intelligence scripts working
- [ ] All attack simulation scripts executable

---

## Next Steps

1.  Review [Architecture Documentation](ARCHITECTURE.md)
2.  Read [Custom Rules Documentation](CUSTOM_RULES.md)
3.  Review [Incident Report](INCIDENT_REPORT.md)
4.  Run attack simulations
5.  Analyze threat intelligence results
6.  Create custom Kibana dashboards

---

## Support

If you encounter issues not covered in this guide:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review service logs: `sudo journalctl -u SERVICE_NAME -n 50`
3. Open an issue on GitHub with details
4. Consult official documentation:
   - [Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
   - [Suricata](https://suricata.readthedocs.io/)
   - [Logstash](https://www.elastic.co/guide/en/logstash/current/index.html)

---

**Installation Complete!** 

You now have a fully functional SOC Detection & Threat Intelligence Lab.

---

*Last Updated: February 2026*
