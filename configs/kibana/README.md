#  Kibana Dashboards Configuration

This directory contains Kibana dashboard configurations for the SOC Detection Lab.

---

## Dashboard Overview

### 1. Security Overview Dashboard
**Purpose:** High-level security monitoring and metrics

**Visualizations:**
- Alert Timeline (Line chart)
- Top 10 Source IPs (Bar chart)
- Alert Severity Distribution (Pie chart)
- Top Signatures (Data table)
- Geographic Attack Map (Coordinate map)
- Alerts by Protocol (Pie chart)

### 2. Threat Intelligence Dashboard
**Purpose:** Enriched threat analysis and IOC tracking

**Visualizations:**
- Malicious IP Detections (Metric)
- Threat Score Distribution (Histogram)
- Top Countries (Source) (Bar chart)
- AbuseIPDB Confidence Scores (Gauge)
- IOC Timeline (Area chart)

### 3. Custom Rules Dashboard
**Purpose:** Monitor effectiveness of custom detection rules

**Visualizations:**
- Custom Rule Triggers (Bar chart)
- Rule Performance (Data table)
- False Positive Rate (Metric)
- MITRE ATT&CK Coverage (Tag cloud)

---

## Creating Dashboards

### Step 1: Create Data View

1. Open Kibana: `http://YOUR-EC2-IP:5601`
2. Menu → **Stack Management** → **Data Views**
3. Click **"Create data view"**
4. Settings:
   - **Name:** `Suricata Alerts`
   - **Index pattern:** `suricata-*`
   - **Timestamp field:** `@timestamp`
5. Click **"Save data view to Kibana"**

---

### Step 2: Create Security Overview Dashboard

#### Visualization 1: Alert Timeline

1. Menu → **Analytics** → **Dashboard**
2. Click **"Create dashboard"**
3. Click **"Create visualization"**
4. Select **"Line"** chart type
5. Configuration:
   - **Horizontal axis:** `@timestamp` (Date histogram, Auto interval)
   - **Vertical axis:** Count
   - **Break down by:** `alert.signature.keyword` (Top 10)
6. Click **"Save and return"**
7. Title: "Alert Timeline"

#### Visualization 2: Top Source IPs

1. Click **"Create visualization"**
2. Select **"Bar horizontal"**
3. Configuration:
   - **Horizontal axis:** Count
   - **Vertical axis:** `src_ip.keyword` (Top 10)
4. Click **"Save and return"**
5. Title: "Top 10 Source IPs"

#### Visualization 3: Alert Severity Distribution

1. Click **"Create visualization"**
2. Select **"Donut"** (Pie chart)
3. Configuration:
   - **Slice by:** `alert.severity` (Top values)
   - **Metric:** Count
4. Click **"Save and return"**
5. Title: "Alert Severity Distribution"

#### Visualization 4: Top Signatures

1. Click **"Create visualization"**
2. Select **"Table"**
3. Configuration:
   - **Rows:** `alert.signature.keyword` (Top 20)
   - **Metrics:** 
     - Count
     - Unique count of `src_ip.keyword`
     - Unique count of `dest_ip.keyword`
4. Column names:
   - "Signature"
   - "Alert Count"
   - "Unique Sources"
   - "Unique Destinations"
5. Click **"Save and return"**
6. Title: "Top Alert Signatures"

#### Visualization 5: Geographic Map

1. Click **"Create visualization"**
2. Select **"Maps"**
3. Click **"Add layer"** → **"Clusters and grids"**
4. Configuration:
   - **Index pattern:** `suricata-*`
   - **Geospatial field:** `src_geoip.location`
5. Click **"Save and return"**
6. Title: "Attack Source Locations"

#### Visualization 6: Protocol Distribution

1. Click **"Create visualization"**
2. Select **"Donut"**
3. Configuration:
   - **Slice by:** `proto.keyword`
   - **Metric:** Count
4. Click **"Save and return"**
5. Title: "Traffic by Protocol"

#### Save Dashboard

1. Click **"Save"** (top right)
2. Title: "Security Overview Dashboard"
3. Click **"Save"**

---

### Step 3: Create Custom Rules Dashboard

#### Visualization 1: Custom Rule Triggers

1. Create new dashboard or add to existing
2. Click **"Create visualization"**
3. Select **"Bar vertical"**
4. Configuration:
   - **Horizontal axis:** `alert.signature.keyword`
   - **Vertical axis:** Count
   - **Filter:** Add filter
     - Field: `alert.signature`
     - Operator: `contains`
     - Value: `CUSTOM`
5. Click **"Save and return"**
6. Title: "Custom Rule Triggers"

#### Visualization 2: MITRE ATT&CK Techniques

1. Click **"Create visualization"**
2. Select **"Tag cloud"**
3. Configuration:
   - **Tags:** `alert.metadata.mitre_technique` (if available)
   - Or create tags from signature names
4. Click **"Save and return"**
5. Title: "MITRE ATT&CK Coverage"

---

## Exporting Dashboards

### Export Individual Dashboard

1. Menu → **Stack Management** → **Saved Objects**
2. Find your dashboard
3. Check the box next to it
4. Click **"Export X objects"**
5. Save as: `security-overview-dashboard.ndjson`

### Export All Dashboards

1. Menu → **Stack Management** → **Saved Objects**
2. Click **"Export all"**
3. Save as: `all-kibana-objects.ndjson`

Place exported files in: `configs/kibana/`

---

## Importing Dashboards

### From Another System

1. Menu → **Stack Management** → **Saved Objects**
2. Click **"Import"**
3. Select your `.ndjson` file
4. Click **"Import"**
5. If conflicts, choose **"Overwrite"** or **"Skip"**

---

## Sample KQL Queries

### View All Alerts
```
event_type: "alert"
```

### High Severity Alerts Only
```
event_type: "alert" AND alert.severity: 1
```

### Custom Rule Alerts
```
event_type: "alert" AND alert.signature: CUSTOM*
```

### SQL Injection Attempts
```
event_type: "alert" AND alert.signature: *"SQL Injection"*
```

### Specific Source IP
```
src_ip: "194.180.48.63"
```

### Alerts from Last 24 Hours
```
event_type: "alert" AND @timestamp >= now-24h
```

### SSH Brute Force Alerts
```
event_type: "alert" AND alert.signature: *"SSH"* AND alert.signature: *"Brute"*
```

### Traffic from Specific Country
```
src_geoip.country_name: "Romania"
```

### High Confidence Threats (if using threat intel)
```
threat_score >= 50
```

---

## Dashboard Maintenance

### Best Practices

1. **Refresh Interval:** Set to 30-60 seconds for near real-time
2. **Time Range:** Default to "Last 24 hours"
3. **Auto-refresh:** Enable for monitoring dashboards
4. **Filters:** Save commonly used filters
5. **Export:** Backup dashboards weekly

### Performance Optimization

1. Limit visualizations to 6-8 per dashboard
2. Use aggregations instead of raw documents
3. Set reasonable time ranges
4. Use index patterns instead of wildcards when possible

---

## Troubleshooting

### Dashboard Not Showing Data

**Check:**
1. Data view exists: `suricata-*`
2. Time range includes data
3. Elasticsearch has data: `curl localhost:9200/suricata-*/_count`
4. Refresh the page

### Visualizations Empty

**Check:**
1. Field exists in index: Menu → **Stack Management** → **Data Views** → `suricata-*` → Field list
2. Filter not too restrictive
3. Time range too narrow

### Slow Performance

**Solutions:**
1. Reduce time range
2. Limit number of visualizations
3. Use smaller aggregation intervals
4. Increase Elasticsearch heap memory

---

## Additional Dashboards to Create

### Network Traffic Dashboard
- Packet count over time
- Bytes transferred
- Top talkers (src/dest IPs)
- Port distribution

### DNS Dashboard
- DNS query volume
- Top queried domains
- NXDOMAIN responses
- Suspicious TLDs

### HTTP Dashboard
- HTTP status codes
- User agents
- Top URLs
- POST vs GET ratio

---

## References

- **Kibana Guide:** https://www.elastic.co/guide/en/kibana/current/index.html
- **KQL Reference:** https://www.elastic.co/guide/en/kibana/current/kuery-query.html
- **Visualization Types:** https://www.elastic.co/guide/en/kibana/current/dashboard.html

---

*Last Updated: February 2026*
