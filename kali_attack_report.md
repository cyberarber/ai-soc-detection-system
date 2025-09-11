
# Kali Linux Attack Simulation Report

**Date**: 2025-09-10 22:15
**Attacker**: Kali Linux (192.168.110.129)
**Target**: Ubuntu SOC (192.168.110.128)

## Attack Summary

### Phase 1: SSH Brute Force
- **Attempts**: 20 failed authentication attempts
- **Target Users**: admin, root
- **Method**: Password spraying with sshpass

### Phase 2: Elasticsearch Reconnaissance
- Attempted to delete all indices
- Queried cluster master information
- Attempted to set indices to read-only

### Phase 3: Port Scanning
- Scanned common service ports
- Ports targeted: 22, 80, 443, 1433, 3306, 3389, 5432

## Detection Status

✅ **Attack Executed Successfully from Kali**
⚠️  **Detection**: Wazuh agent configuration may need tuning for network attacks

## Recommendations

1. **Enable Suricata IDS** for network-level detection
2. **Configure fail2ban** to block brute force attempts
3. **Add custom Wazuh rules** for SSH brute force patterns
4. **Enable Elasticsearch audit logging**

## Evidence

- Attack script executed: detectable_attack.sh
- Source IP: 192.168.110.129 (Kali)
- Target IP: 192.168.110.128 (Ubuntu)
- Time: 2025-09-10T22:15:42.675603
