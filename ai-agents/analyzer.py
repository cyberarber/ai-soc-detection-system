#!/usr/bin/env python3
import json
import os

alert_file = "reports/cases/C-2025-0001/alert.json"
if os.path.getsize(alert_file) > 0:
    with open(alert_file) as f:
        alert = json.load(f)
    print(f"Alert: {alert.get('rule', {}).get('description', 'Unknown')}")
    print(f"Level: {alert.get('rule', {}).get('level', 0)}")
else:
    print("No alerts captured yet")
