#!/usr/bin/env python3
"""Hunt for Kali Linux attack patterns"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.agents.threat_hunter_v2 import ThreatHunter
import json
from datetime import datetime

class KaliAttackHunter(ThreatHunter):
    def hunt_kali_attacks(self):
        print("\n[*] Hunting for Kali Linux attack patterns...")
        
        # Query for suspicious patterns
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"data.command": "nmap"}},
                        {"match": {"data.srcip": "192.168"}},  # Adjust for your network
                        {"match": {"rule.groups": "web_scan"}},
                        {"match": {"rule.groups": "ids"}},
                        {"wildcard": {"data.url": "*cmd=*"}},
                        {"match": {"data.user_agent": "Suspicious"}}
                    ],
                    "filter": {
                        "range": {
                            "@timestamp": {
                                "gte": "now-1h"
                            }
                        }
                    }
                }
            },
            "size": 100
        }
        
        results = self.es.search(index="wazuh-alerts-*", body=query)
        events = results['hits']['hits']
        
        if events:
            print(f"[+] Found {len(events)} suspicious events")
            
            # Prepare for AI analysis
            attack_timeline = []
            for event in events:
                src = event['_source']
                attack_timeline.append({
                    "time": src.get('@timestamp'),
                    "rule": src.get('rule', {}).get('description'),
                    "source": src.get('data', {}).get('srcip'),
                    "details": src.get('full_log', '')[:200]
                })
            
            # AI Analysis
            analysis_prompt = f"""
            Analyze this attack sequence from a Kali Linux system:
            {json.dumps(attack_timeline, indent=2)}
            
            Provide a detailed incident report with:
            1. Attack campaign summary
            2. MITRE ATT&CK techniques identified
            3. Attack timeline reconstruction
            4. Impact assessment
            5. Indicators of Compromise (IoCs)
            6. Recommended response actions
            7. Lessons learned
            
            Format as a professional incident report.
            """
            
            report = self.analyze_with_ai(attack_timeline, analysis_prompt)
            
            # Save report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            with open(f"incident_report_{timestamp}.json", "w") as f:
                json.dump(report, f, indent=2)
            
            print("\n" + "="*60)
            print("INCIDENT REPORT")
            print("="*60)
            print(json.dumps(report, indent=2))
            
            return report

if __name__ == "__main__":
    hunter = KaliAttackHunter()
    hunter.hunt_kali_attacks()
