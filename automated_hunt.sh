#!/bin/bash
while true; do
    echo "[$(date)] Running automated threat hunt..."
    python ~/ai-soc-detection-system/src/agents/threat_hunter_v2.py >> threat_hunt.log 2>&1
    
    # Check if threat detected
    if grep -q "THREAT DETECTED" threat_hunt.log; then
        echo "⚠️ ALERT: Threat detected! Check threat_hunt.log"
        # Could add email/Slack notification here
    fi
    
    sleep 3600  # Run every hour
done
