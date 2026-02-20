#!/bin/bash
# Master script to run all attack simulations

echo "╔════════════════════════════════════════════════╗"
echo "║  SOC Lab - Attack Simulation Test Suite       ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test 1: C2 Communication
echo "▶ Test 1/3: C2 Communication Simulation"
bash "$SCRIPT_DIR/c2_simulation.sh"
echo ""
sleep 5

# Test 2: Web Attacks
echo "▶ Test 2/3: Web Application Attacks"
bash "$SCRIPT_DIR/web_attacks.sh"
echo ""
sleep 5

# Test 3: Port Scan (requires sudo)
echo "▶ Test 3/3: Port Scan Simulation"
echo "Note: This test requires sudo privileges"
bash "$SCRIPT_DIR/port_scan_test.sh"

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║  All Tests Complete!                           ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "View all CUSTOM alerts:"
echo "  sudo grep '\"event_type\":\"alert\"' /var/log/suricata/eve.json | grep 'CUSTOM' | tail -20 | jq -r '.alert.signature'"
echo ""
echo "View in Kibana: http://YOUR-IP:5601"
echo "View in EveBox: https://YOUR-IP:5636"
