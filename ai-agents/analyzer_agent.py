#!/usr/bin/env python3
import json

with open("reports/cases/C-2025-0001/alert.json") as f:
    alert = json.load(f)

print(f"Rule {alert['rule']['id']}: {alert['rule']['description']}")
print(f"MITRE: {alert['rule']['mitre']['id']}")
print("Verdict: MONITOR - Awaiting ChatGPT integration")
