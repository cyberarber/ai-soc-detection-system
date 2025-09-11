#!/usr/bin/env python3
"""Real-time Kali attack detection and analysis"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.agents.threat_hunter_v2 import ThreatHunter
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json
import time

class LiveAttackDetector(ThreatHunter):
    def __init__(self):
        super().__init__()
        self.attack_start = datetime.now()
        
    def monitor_live_attack(self, duration=180):
        """Monitor for 3 minutes"""
        print(f"\n{'='*60}")
        print("🔴 LIVE ATTACK MONITORING ACTIVE")
        print(f"{'='*60}\n")
        print("Waiting for attacks from Kali...")
        
        end_time = datetime.now() + timedelta(seconds=duration)
        detected_events = []
        
        while datetime.now() < end_time:
            # Query for recent suspicious events
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": "now-30s"}}},
                            {"range": {"rule.level": {"gte": 5}}}
                        ]
                    }
                },
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            try:
                results = self.es.search(index="wazuh-alerts-*", body=query)
                
                for hit in results['hits']['hits']:
                    event_id = hit['_id']
                    if event_id not in [e['id'] for e in detected_events]:
                        src = hit['_source']
                        event = {
                            'id': event_id,
                            'timestamp': src.get('@timestamp'),
                            'rule': src.get('rule', {}).get('description', 'Unknown'),
                            'level': src.get('rule', {}).get('level', 0),
                            'source': src.get('data', {}).get('srcip', 'unknown'),
                            'agent': src.get('agent', {}).get('name', 'unknown')
                        }
                        detected_events.append(event)
                        
                        # Real-time alert
                        if event['level'] >= 7:
                            print(f"⚠️  [{event['timestamp']}] Level {event['level']}: {event['rule']}")
                            print(f"   Source: {event['source']} | Agent: {event['agent']}\n")
                
            except Exception as e:
                pass  # Silent continue
            
            time.sleep(5)  # Check every 5 seconds
        
        # Final analysis
        if detected_events:
            print(f"\n{'='*60}")
            print(f"📊 ATTACK SUMMARY: {len(detected_events)} events detected")
            print(f"{'='*60}\n")
            
            # AI Analysis
            self.generate_incident_report(detected_events)
        else:
            print("No attacks detected during monitoring period")
    
    def generate_incident_report(self, events):
        """Generate comprehensive incident report"""
        
        print("🤖 Generating AI-powered incident report...")
        
        analysis_prompt = f"""
        Analyze this attack sequence from Kali Linux:
        
        Events: {json.dumps(events[:20], indent=2)}
        
        Provide:
        1. EXECUTIVE SUMMARY - Attack classification and impact
        2. ATTACK TIMELINE - Chronological sequence
        3. MITRE ATT&CK MAPPING - Techniques identified
        4. INDICATORS OF COMPROMISE - IPs, tools, patterns
        5. RECOMMENDED ACTIONS - Immediate response steps
        
        Be concise but thorough.
        """
        
        report = self.analyze_with_ai(events[:20], analysis_prompt)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"incident_report_{timestamp}.json"
        
        with open(report_file, "w") as f:
            json.dump({
                "metadata": {
                    "generated": datetime.now().isoformat(),
                    "events_analyzed": len(events)
                },
                "report": report
            }, f, indent=2)
        
        print(f"\n✅ Report saved: {report_file}")
        print("\n" + "="*60)
        print("AI INCIDENT ANALYSIS")
        print("="*60)
        if isinstance(report, dict):
            print(json.dumps(report, indent=2))
        else:
            print(report)
        
        return report

if __name__ == "__main__":
    print("="*60)
    print("🛡️  KALI ATTACK DETECTION SYSTEM")
    print("="*60)
    
    detector = LiveAttackDetector()
    print("\n▶️  Starting live monitoring...")
    print("▶️  Now run the attack from Kali Linux!\n")
    detector.monitor_live_attack(duration=180)  # Monitor for 3 minutes
    print("\n✅ Monitoring complete!")
