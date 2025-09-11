#!/usr/bin/env python3
"""Live AI-Powered Attack Detection"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.agents.threat_hunter_v2 import ThreatHunter
from datetime import datetime, timedelta
import json
import time

class LiveAIDetector(ThreatHunter):
    def __init__(self):
        super().__init__()
        print("\n" + "="*60)
        print("🤖 GPT-4 AI THREAT DETECTION INITIALIZING")
        print("="*60)
        
    def monitor_with_ai(self, duration=120):
        """Monitor and analyze with GPT-4 in real-time"""
        print("✅ GPT-4 Connected and Ready")
        print("⏰ Monitoring for 2 minutes...")
        print("👀 Watching for attacks from Kali Linux")
        print("="*60 + "\n")
        
        end_time = datetime.now() + timedelta(seconds=duration)
        batch_counter = 0
        
        while datetime.now() < end_time:
            # Query for recent events
            query = {
                "query": {
                    "range": {"@timestamp": {"gte": "now-30s"}}
                },
                "size": 50
            }
            
            results = self.es.search(index="wazuh-alerts-*", body=query)
            
            if results['hits']['hits']:
                batch_counter += 1
                events = results['hits']['hits']
                
                print(f"\n[Batch {batch_counter}] Found {len(events)} new events")
                print("🤖 Sending to GPT-4 for analysis...")
                
                # Prepare events for AI
                event_summary = []
                for event in events[:10]:
                    src = event['_source']
                    event_summary.append({
                        'time': src.get('@timestamp'),
                        'rule': src.get('rule', {}).get('description'),
                        'level': src.get('rule', {}).get('level')
                    })
                
                # VISIBLE AI ANALYSIS
                ai_prompt = """Analyze these security events in real-time.
                Determine if this is an attack. Be specific and concise.
                Events: """ + json.dumps(event_summary, indent=2)
                
                print("📤 Sending to GPT-4...")
                ai_response = self.analyze_with_ai(event_summary, ai_prompt)
                
                print("📥 GPT-4 Analysis:")
                print("-" * 40)
                print(ai_response)
                print("-" * 40)
                
                # Check if attack detected
                if "attack" in str(ai_response).lower():
                    print("⚠️  ATTACK DETECTED BY AI!")
            
            time.sleep(10)  # Check every 10 seconds
        
        print("\n" + "="*60)
        print("✅ AI MONITORING COMPLETE")
        print("="*60)

if __name__ == "__main__":
    detector = LiveAIDetector()
    print("\n🚀 LAUNCH ATTACK FROM KALI NOW!\n")
    detector.monitor_with_ai(duration=120)
