#!/usr/bin/env python3
"""
SOC Lab - Advanced Alert Analysis with Threat Intelligence
Analyzes Suricata alerts and enriches with multiple threat intel sources
"""

import requests
import json
import time
from datetime import datetime, timedelta
from OTXv2 import OTXv2
from collections import defaultdict
import config

class AlertAnalyzer:
    def __init__(self):
        self.otx = OTXv2(config.OTX_API_KEY)
        self.abuseipdb_headers = {
            'Key': config.ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        self.analyzed_ips = {}
        
    def read_recent_alerts(self, hours=24):
        """Read alerts from eve.json from the last N hours"""
        print(f"[*] Reading alerts from last {hours} hours...")
        
        alerts = []
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        try:
            with open('/var/log/suricata/eve.json', 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                            if event_time.replace(tzinfo=None) >= cutoff_time:
                                alerts.append(event)
                    except:
                        continue
        except Exception as e:
            print(f"[!] Error reading eve.json: {e}")
            
        print(f"[+] Found {len(alerts)} alerts in the last {hours} hours")
        return alerts
    
    def extract_iocs(self, alerts):
        """Extract Indicators of Compromise from alerts"""
        print("[*] Extracting IOCs...")
        
        iocs = {
            'ips': defaultdict(list),
            'domains': set(),
            'urls': set()
        }
        
        for alert in alerts:
            # Extract IPs
            src_ip = alert.get('src_ip')
            dest_ip = alert.get('dest_ip')
            signature = alert.get('alert', {}).get('signature', '')
            
            # Skip private IPs
            if src_ip and not self._is_private_ip(src_ip):
                iocs['ips'][src_ip].append({
                    'signature': signature,
                    'timestamp': alert.get('timestamp'),
                    'direction': 'source'
                })
                
            if dest_ip and not self._is_private_ip(dest_ip):
                iocs['ips'][dest_ip].append({
                    'signature': signature,
                    'timestamp': alert.get('timestamp'),
                    'direction': 'destination'
                })
            
            # Extract domains from HTTP/DNS
            if 'http' in alert:
                hostname = alert['http'].get('hostname')
                if hostname:
                    iocs['domains'].add(hostname)
                    
            if 'dns' in alert:
                query = alert['dns'].get('query', {}).get('rrname')
                if query:
                    iocs['domains'].add(query)
        
        print(f"[+] Extracted {len(iocs['ips'])} unique IPs")
        print(f"[+] Extracted {len(iocs['domains'])} unique domains")
        
        return iocs
    
    def _is_private_ip(self, ip):
        """Check if IP is private"""
        if ip.startswith(('10.', '172.', '192.168.', '127.')):
            return True
        if ip.startswith('169.254.'):
            return True
        return False
    
    def check_ip_reputation(self, ip):
        """Check IP against multiple threat intel sources"""
        if ip in self.analyzed_ips:
            return self.analyzed_ips[ip]
        
        print(f"\n[+] Analyzing IP: {ip}")
        
        result = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Check OTX
        try:
            print(f"  → Checking AlienVault OTX...")
            otx_data = self.otx.get_indicator_details_by_section(ip, 'general')
            
            otx_result = {
                'malicious': False,
                'pulse_count': 0,
                'pulses': []
            }
            
            if 'pulse_info' in otx_data and otx_data['pulse_info']['count'] > 0:
                otx_result['malicious'] = True
                otx_result['pulse_count'] = otx_data['pulse_info']['count']
                
                for pulse in otx_data['pulse_info']['pulses'][:3]:
                    otx_result['pulses'].append({
                        'name': pulse.get('name', 'Unknown'),
                        'tags': pulse.get('tags', [])[:5],
                        'created': pulse.get('created', '')
                    })
                    
            result['sources']['otx'] = otx_result
            print(f"    ✓ OTX: {'MALICIOUS' if otx_result['malicious'] else 'Clean'} ({otx_result['pulse_count']} pulses)")
            
        except Exception as e:
            print(f"    ✗ OTX Error: {e}")
            result['sources']['otx'] = {'error': str(e)}
        
        time.sleep(1)  # Rate limiting
        
        # Check AbuseIPDB
        try:
            print(f"  → Checking AbuseIPDB...")
            url = 'https://api.abuseipdb.com/api/v2/check'
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            
            response = requests.get(url, headers=self.abuseipdb_headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()['data']
                abuse_result = {
                    'malicious': data['abuseConfidenceScore'] > 50,
                    'confidence_score': data['abuseConfidenceScore'],
                    'total_reports': data['totalReports'],
                    'country': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }
                result['sources']['abuseipdb'] = abuse_result
                print(f"    ✓ AbuseIPDB: Confidence {abuse_result['confidence_score']}% ({abuse_result['total_reports']} reports)")
            else:
                print(f"    ✗ AbuseIPDB: Status {response.status_code}")
                
        except Exception as e:
            print(f"    ✗ AbuseIPDB Error: {e}")
            result['sources']['abuseipdb'] = {'error': str(e)}
        
        # Calculate overall threat score
        threat_score = 0
        
        if result['sources'].get('otx', {}).get('malicious'):
            threat_score += 50
            
        abuse_score = result['sources'].get('abuseipdb', {}).get('confidence_score', 0)
        threat_score += (abuse_score * 0.5)
        
        result['threat_score'] = min(int(threat_score), 100)
        result['verdict'] = self._get_verdict(result['threat_score'])
        
        self.analyzed_ips[ip] = result
        
        print(f"  → Overall Threat Score: {result['threat_score']}/100 [{result['verdict']}]")
        
        return result
    
    def _get_verdict(self, score):
        """Get threat verdict based on score"""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"
    
    def generate_report(self, iocs, enriched_ips):
        """Generate threat intelligence report"""
        print("\n" + "="*70)
        print("THREAT INTELLIGENCE REPORT")
        print("="*70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total IPs Analyzed: {len(enriched_ips)}")
        print("="*70)
        
        # Categorize by threat level
        critical = [ip for ip in enriched_ips if ip['verdict'] == 'CRITICAL']
        high = [ip for ip in enriched_ips if ip['verdict'] == 'HIGH']
        medium = [ip for ip in enriched_ips if ip['verdict'] == 'MEDIUM']
        low = [ip for ip in enriched_ips if ip['verdict'] == 'LOW']
        
        print(f"\nTHREAT SUMMARY:")
        print(f"  🔴 CRITICAL: {len(critical)}")
        print(f"  🟠 HIGH:     {len(high)}")
        print(f"  🟡 MEDIUM:   {len(medium)}")
        print(f"  🟢 LOW:      {len(low)}")
        
        # Show critical threats
        if critical:
            print(f"\n{'='*70}")
            print("⚠️  CRITICAL THREATS - IMMEDIATE ACTION REQUIRED")
            print(f"{'='*70}")
            for ip_data in critical:
                self._print_ip_details(ip_data, iocs)
        
        # Show high threats
        if high:
            print(f"\n{'='*70}")
            print("⚠️  HIGH THREATS - INVESTIGATE PROMPTLY")
            print(f"{'='*70}")
            for ip_data in high:
                self._print_ip_details(ip_data, iocs)
        
        print(f"\n{'='*70}")
        
        # Save to file
        report_data = {
            'generated': datetime.now().isoformat(),
            'summary': {
                'total_ips': len(enriched_ips),
                'critical': len(critical),
                'high': len(high),
                'medium': len(medium),
                'low': len(low)
            },
            'detailed_results': enriched_ips,
            'iocs': {
                'ips': {ip: alerts for ip, alerts in iocs['ips'].items()},
                'domains': list(iocs['domains'])
            }
        }
        
        output_file = config.OUTPUT_FILE
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Full report saved to: {output_file}")
        
    def _print_ip_details(self, ip_data, iocs):
        """Print detailed IP information"""
        ip = ip_data['ip']
        print(f"\nIP: {ip}")
        print(f"Threat Score: {ip_data['threat_score']}/100")
        
        # OTX data
        if 'otx' in ip_data['sources']:
            otx = ip_data['sources']['otx']
            if otx.get('malicious'):
                print(f"  AlienVault OTX: {otx['pulse_count']} threat pulses")
                for pulse in otx.get('pulses', [])[:2]:
                    print(f"    - {pulse['name']}")
                    if pulse.get('tags'):
                        print(f"      Tags: {', '.join(pulse['tags'][:3])}")
        
        # AbuseIPDB data
        if 'abuseipdb' in ip_data['sources']:
            abuse = ip_data['sources']['abuseipdb']
            if not abuse.get('error'):
                print(f"  AbuseIPDB: {abuse['confidence_score']}% confidence, {abuse['total_reports']} reports")
                print(f"    Country: {abuse['country']}, ISP: {abuse['isp']}")
        
        # Show related alerts
        if ip in iocs['ips']:
            alerts = iocs['ips'][ip]
            print(f"  Related Alerts: {len(alerts)}")
            unique_sigs = set(a['signature'] for a in alerts)
            for sig in list(unique_sigs)[:3]:
                print(f"    - {sig}")

def main():
    print("="*70)
    print("SOC LAB - THREAT INTELLIGENCE ANALYSIS")
    print("="*70)
    
    analyzer = AlertAnalyzer()
    
    # Read recent alerts
    alerts = analyzer.read_recent_alerts(hours=48)
    
    if not alerts:
        print("[!] No alerts found. Generate some test traffic first!")
        return
    
    # Extract IOCs
    iocs = analyzer.extract_iocs(alerts)
    
    if not iocs['ips']:
        print("[!] No public IPs found in alerts.")
        return
    
    # Analyze top IPs (limit to 15 to avoid rate limits)
    ip_list = sorted(iocs['ips'].items(), key=lambda x: len(x[1]), reverse=True)[:15]
    
    enriched_ips = []
    for ip, alert_data in ip_list:
        result = analyzer.check_ip_reputation(ip)
        enriched_ips.append(result)
        time.sleep(2)  # Rate limiting
    
    # Generate report
    analyzer.generate_report(iocs, enriched_ips)

if __name__ == "__main__":
    main()
