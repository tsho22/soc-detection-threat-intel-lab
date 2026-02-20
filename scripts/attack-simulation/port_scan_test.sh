#!/bin/bash
# Port Scan Simulation for Testing Suricata Detection

echo "========================================="
echo "Port Scan Simulation"
echo "========================================="
echo ""

# Get local IP and subnet
MY_IP=$(hostname -I | awk '{print $1}')
SUBNET=$(echo $MY_IP | cut -d'.' -f1-3).0/24

echo "Target Subnet: $SUBNET"
echo "Starting port scan..."
echo ""

# Perform SYN scan (will trigger custom rule SID 1000004)
sudo nmap -sS -p 22,80,443,3306,5432 $SUBNET -T4 --max-retries 1

echo ""
echo "========================================="
echo "Port scan complete!"
echo "Check Suricata alerts:"
echo "  sudo tail -50 /var/log/suricata/eve.json | jq 'select(.event_type==\"alert\")'"
echo "========================================="
