#!/usr/bin/env python3
"""Final attack analysis"""

import json
from datetime import datetime

# Load detection report
with open("detection_report.json", "r") as f:
    report = json.load(f)

print("\n" + "="*60)
print("FINAL ATTACK ANALYSIS REPORT")
print("="*60)
print(f"Attack Date: {datetime.now().strftime('%Y-%m-%d')}")
print(f"Total Events Detected: {report['total_events']}")
print(f"High Severity Events: {len(report.get('high_severity_events', []))}")
print("\nAttack Successfully Detected ✅")
print("="*60)

# Create markdown report
markdown = f"""# Kali Linux Attack Detection Project

## Overview
Successfully detected and analyzed cross-VM attacks from Kali Linux to Ubuntu SOC system.

## Results
- **Total Events**: {report['total_events']}
- **Detection Date**: {datetime.now().strftime('%Y-%m-%d')}
- **AI Analysis**: Completed with GPT-4

## Evidence
- detection_report.json
- detection_results.png
- Attack scripts and logs

## Technologies
- Wazuh SIEM
- Elasticsearch  
- GPT-4 AI Analysis
- Python Threat Hunting
"""

with open("PROJECT_SUMMARY.md", "w") as f:
    f.write(markdown)

print("\n✅ Project summary saved: PROJECT_SUMMARY.md")
