#!/bin/bash
echo "[*] Triggering Wazuh alerts..."

# Failed SSH attempts
ssh invalid@localhost 2>/dev/null
ssh root@localhost 2>/dev/null

# Port scan
nmap -sS localhost -p 22,80,443 2>/dev/null

# Suspicious commands
whoami
id
cat /etc/passwd | head -5
sudo -l 2>/dev/null

# File modifications
touch /tmp/suspicious_file_$$.txt
echo "test" > /tmp/suspicious_file_$$.txt
rm /tmp/suspicious_file_$$.txt

echo "[+] Alert triggers sent. Wait 30 seconds for Wazuh to process..."
