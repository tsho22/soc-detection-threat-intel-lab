#!/bin/bash
# Web Application Attack Simulation

echo "========================================="
echo "Web Application Attack Simulation"
echo "========================================="
echo ""

# SQL Injection attempts (triggers SID 1000007, 1000008)
echo "[*] Testing SQL Injection detection..."
curl -s "http://testmynids.org/?id=1' OR '1'='1" > /dev/null
sleep 1
curl -s "http://testmynids.org/?id=1' UNION SELECT password FROM users--" > /dev/null
sleep 1
curl -s "http://www.google.com/?user=admin' AND 1=1--" > /dev/null

# XSS attempts
echo "[*] Testing XSS detection..."
curl -s "http://testmynids.org/?search=<script>alert('XSS')</script>" > /dev/null
sleep 1

# Command injection
echo "[*] Testing command injection detection..."
curl -s "http://testmynids.org/?cmd=;cat%20/etc/passwd" > /dev/null
sleep 1

# Path traversal
echo "[*] Testing path traversal detection..."
curl -s "http://testmynids.org/../../../../etc/passwd" > /dev/null

echo ""
echo "========================================="
echo "Web attacks simulation complete!"
echo "Check alerts:"
echo "  sudo grep 'CUSTOM WEB' /var/log/suricata/eve.json | tail -10 | jq ."
echo "========================================="
