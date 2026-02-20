#!/bin/bash
# C2 Communication Simulation

echo "========================================="
echo "C2 Communication Simulation"
echo "========================================="
echo ""

# Malware user agents (triggers SID 1000001, 1000003)
echo "[*] Simulating malware beacons..."
curl -s -A "BlackSun" http://www.example.com > /dev/null
echo "  → BlackSun user-agent sent"
sleep 2

curl -s -A "Metasploit RSPEC" http://www.example.com > /dev/null
echo "  → Metasploit user-agent sent"
sleep 2

curl -s -A "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" http://www.example.com > /dev/null
echo "  → Suspicious IE user-agent sent"

# Connections to common C2 ports (triggers SID 1000012)
echo ""
echo "[*] Testing C2 port connections..."
nc -zv -w 3 8.8.8.8 4444 2>&1 | grep -q "succeeded\|open" && echo "  → Port 4444 test complete" || echo "  → Port 4444 test complete"
sleep 1
nc -zv -w 3 8.8.8.8 5555 2>&1 | grep -q "succeeded\|open" && echo "  → Port 5555 test complete" || echo "  → Port 5555 test complete"

# Suspicious DNS queries (triggers SID 1000005, 1000006)
echo ""
echo "[*] Simulating suspicious DNS queries..."
nslookup malicious-domain.xyz 8.8.8.8 2>/dev/null > /dev/null && echo "  → .xyz domain query sent"
sleep 1
nslookup botnet-c2.tk 8.8.8.8 2>/dev/null > /dev/null && echo "  → .tk domain query sent"

echo ""
echo "========================================="
echo "C2 simulation complete!"
echo "Check alerts:"
echo "  sudo grep 'CUSTOM MALWARE' /var/log/suricata/eve.json | tail -10 | jq ."
echo "  sudo grep 'CUSTOM C2' /var/log/suricata/eve.json | tail -10 | jq ."
echo "========================================="
