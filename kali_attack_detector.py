#!/usr/bin/env python3
"""Complete Kali Attack Detection System"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.agents.threat_hunter_v2 import ThreatHunter
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json
import time

class KaliAttackDetector(ThreatHunter):
    def __init__(self):
        super().__init__()
        self.start_time = datetime.now()
        
    def detect_attacks(self, duration=180):
        """Monitor for attacks for 3 minutes"""
        print("\n" + "="*60)
        print("🛡️ KALI ATTACK DETECTION SYSTEM ACTIVE")
        print("="*60)
        print(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("Monitoring for attacks from Kali Linux...")
        print("="*60 + "\n")
        
        end_time = datetime.now() + timedelta(seconds=duration)
        all_events = []
        
        while datetime.now() < end_time:
            # Query for any security events
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": "now-1m"}}},
                            {"range": {"rule.level": {"gte": 3}}}
                        ]
                    }
                },
                "size": 100
            }
            
            results = self.es.search(index="wazuh-alerts-*", body=query)
            
            for hit in results['hits']['hits']:
                event_id = hit['_id']
                if event_id not in [e['id'] for e in all_events]:
                    src = hit['_source']
                    level = src.get('rule', {}).get('level', 0)
                    
                    event = {
                        'id': event_id,
                        'timestamp': src.get('@timestamp'),
                        'level': level,
                        'rule': src.get('rule', {}).get('description'),
                        'agent': src.get('agent', {}).get('name')
                    }
                    all_events.append(event)
                    
                    if level >= 5:
                        print(f"⚠️  [{datetime.now().strftime('%H:%M:%S')}] Level {level}: {event['rule']}")
            
            time.sleep(5)
        
        # Final report
        self.generate_report(all_events)
        return all_events
    
    def generate_report(self, events):
        """Generate detection report"""
        print("\n" + "="*60)
        print("📊 DETECTION SUMMARY")
        print("="*60)
        print(f"Total Events Detected: {len(events)}")
        
        # Group by level
        by_level = {}
        for e in events:
            level = e['level']
            if level not in by_level:
                by_level[level] = 0
            by_level[level] += 1
        
        print("\nEvents by Severity:")
        for level in sorted(by_level.keys(), reverse=True):
            print(f"  Level {level}: {by_level[level]} events")
        
        # AI Analysis if high-level events exist
        high_events = [e for e in events if e['level'] >= 5]
        if high_events:
            print(f"\n🤖 Analyzing {len(high_events)} high-severity events with GPT-4...")
            
            analysis = self.analyze_with_ai(high_events[:20], """
            Analyze these security events and provide:
            1. Attack type identified
            2. Severity assessment
            3. Recommended response
            Be concise.
            """)
            
            print("\nAI Analysis:")
            print(analysis)
        
        # Save report
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "total_events": len(events),
            "events_by_level": by_level,
            "high_severity_events": high_events
        }
        
        with open("detection_report.json", "w") as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n✅ Report saved: detection_report.json")

if __name__ == "__main__":
    detector = KaliAttackDetector()
    print("▶️  Start the attack from Kali Linux now!")
    detector.detect_attacks(duration=120)  # 2 minutes
