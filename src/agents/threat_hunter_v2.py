#!/usr/bin/env python3
"""
AI-Powered Threat Hunter - Enhanced Version
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.agents.base_agent_v2 import SOCAgent
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json
import warnings
warnings.filterwarnings('ignore')

class ThreatHunter(SOCAgent):
    """Autonomous threat hunting agent"""
    
    def __init__(self):
        super().__init__(role="Threat Hunter")
        self.es = Elasticsearch(['http://localhost:9200'])
        self.check_elasticsearch_connection()
        
    def check_elasticsearch_connection(self):
        """Verify Elasticsearch connection and show available indices"""
        try:
            # Check connection
            if not self.es.ping():
                print("[!] Cannot connect to Elasticsearch")
                return False
                
            # Show Wazuh indices
            indices = self.es.indices.get_alias(index="wazuh-*")
            if indices:
                print(f"[+] Connected to Elasticsearch - Found {len(indices)} Wazuh indices:")
                for idx in list(indices.keys())[:5]:  # Show first 5
                    print(f"    - {idx}")
            else:
                print("[!] No Wazuh indices found in Elasticsearch")
                
            return True
        except Exception as e:
            print(f"[!] Elasticsearch error: {e}")
            return False
    
    def hunt_recent_alerts(self):
        """Hunt for threats in recent Wazuh alerts"""
        print("\n[*] Starting AI-powered threat hunt...")
        
        # Try different timestamp fields and index patterns
        timestamp_fields = ["@timestamp", "timestamp", "data.timestamp"]
        index_patterns = ["wazuh-alerts-4.x-*", "wazuh-alerts-*", "wazuh-*"]
        
        events = []
        
        for index_pattern in index_patterns:
            for ts_field in timestamp_fields:
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "range": {
                                        ts_field: {
                                            "gte": "now-24h",
                                            "lte": "now"
                                        }
                                    }
                                }
                            ],
                            "filter": [
                                {
                                    "range": {
                                        "rule.level": {
                                            "gte": 5  # Only get medium+ severity
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "sort": [{ts_field: {"order": "desc"}}],
                    "size": 50,
                    "_source": ["@timestamp", "timestamp", "rule", "agent", "data", "full_log"]
                }
                
                try:
                    print(f"[*] Trying index: {index_pattern} with field: {ts_field}")
                    result = self.es.search(index=index_pattern, body=query)
                    
                    if result['hits']['total']['value'] > 0:
                        print(f"[+] Found {result['hits']['total']['value']} events!")
                        events = result['hits']['hits']
                        break
                except Exception as e:
                    # Silent continue to try next combination
                    continue
            
            if events:
                break
        
        # If still no events, try without timestamp filter
        if not events:
            print("[*] Trying without timestamp filter...")
            try:
                query = {
                    "query": {"match_all": {}},
                    "size": 20,
                    "_source": ["@timestamp", "timestamp", "rule", "agent", "data", "full_log"]
                }
                
                for index_pattern in index_patterns:
                    try:
                        result = self.es.search(index=index_pattern, body=query)
                        if result['hits']['total']['value'] > 0:
                            print(f"[+] Found {result['hits']['total']['value']} total events in {index_pattern}")
                            events = result['hits']['hits']
                            break
                    except:
                        continue
                        
            except Exception as e:
                print(f"[!] Query error: {e}")
        
        # Process events or use test data
        if not events:
            print("[!] No events found in Elasticsearch. Running test scenario...")
            return self.analyze_test_scenario()
        
        # Prepare events for AI analysis
        print(f"[*] Processing {len(events)} events for AI analysis...")
        event_summary = []
        
        for event in events[:20]:  # Analyze top 20 events
            src = event['_source']
            
            # Extract relevant fields with multiple fallbacks
            timestamp = (src.get('@timestamp') or 
                        src.get('timestamp') or 
                        src.get('data', {}).get('timestamp') or 
                        'Unknown')
            
            rule_info = src.get('rule', {})
            agent_info = src.get('agent', {})
            data_info = src.get('data', {})
            
            event_data = {
                "timestamp": timestamp,
                "rule": rule_info.get('description', rule_info.get('id', 'Unknown')),
                "level": rule_info.get('level', 0),
                "agent": agent_info.get('name', agent_info.get('id', 'Unknown')),
                "groups": rule_info.get('groups', []),
                "mitre": rule_info.get('mitre', {})
            }
            
            # Add additional context if available
            if data_info:
                event_data["source_ip"] = data_info.get('srcip', data_info.get('src_ip'))
                event_data["dest_ip"] = data_info.get('dstip', data_info.get('dst_ip'))
                event_data["process"] = data_info.get('process', data_info.get('command'))
            
            event_summary.append(event_data)
        
        # AI Analysis
        print("[*] Sending to GPT-4 for threat analysis...")
        
        instructions = """
        Analyze these Wazuh security events for potential threats. 
        Look for patterns indicating attacks, lateral movement, persistence, or data exfiltration.
        
        Return JSON with:
        {
            "threat_detected": true/false,
            "confidence": 0-100,
            "attack_pattern": "detailed description of the attack chain",
            "mitre_techniques": ["T1003", "T1055", etc],
            "affected_hosts": ["list of affected agents/hosts"],
            "priority": "critical/high/medium/low",
            "timeline": "sequence of events if attack detected",
            "recommended_actions": ["specific response actions"],
            "iocs": ["any indicators of compromise found"]
        }
        """
        
        try:
            analysis = self.analyze_with_ai(event_summary, instructions)
            
            print("\n" + "="*60)
            print("🔍 AI THREAT ANALYSIS RESULTS")
            print("="*60)
            
            if isinstance(analysis, dict):
                print(json.dumps(analysis, indent=2))
                
                # Highlight critical findings
                if analysis.get('threat_detected'):
                    print("\n" + "!"*60)
                    print(f"⚠️  THREAT DETECTED - Confidence: {analysis.get('confidence')}%")
                    print(f"📊 Priority: {analysis.get('priority', 'Unknown').upper()}")
                    print(f"🎯 Attack Pattern: {analysis.get('attack_pattern', 'Unknown')}")
                    print("!"*60)
            else:
                print(analysis)
                
            return analysis
            
        except Exception as e:
            print(f"[!] AI analysis error: {e}")
            return {"error": str(e)}
    
    def analyze_test_scenario(self):
        """Analyze a test scenario when no real data available"""
        print("[*] Running test scenario analysis...")
        
        test_events = [
            {
                "timestamp": datetime.now().isoformat(),
                "rule": "Suspicious PowerShell command - Encoded command execution",
                "level": 12,
                "agent": "Windows-Server-01",
                "groups": ["windows", "powershell", "attack.execution"],
                "mitre": {"technique": ["T1059.001", "T1027"]}
            },
            {
                "timestamp": (datetime.now() + timedelta(minutes=1)).isoformat(),
                "rule": "Windows Defender disabled via Registry",
                "level": 13,
                "agent": "Windows-Server-01",
                "groups": ["windows", "defense_evasion"],
                "mitre": {"technique": ["T1562.001"]}
            },
            {
                "timestamp": (datetime.now() + timedelta(minutes=2)).isoformat(),
                "rule": "Scheduled task created for persistence",
                "level": 10,
                "agent": "Windows-Server-01",
                "groups": ["windows", "persistence"],
                "mitre": {"technique": ["T1053.005"]}
            },
            {
                "timestamp": (datetime.now() + timedelta(minutes=3)).isoformat(),
                "rule": "Unusual outbound connection to rare external IP",
                "level": 10,
                "agent": "Windows-Server-01",
                "source_ip": "192.168.1.100",
                "dest_ip": "185.220.101.45",
                "groups": ["network", "command_control"],
                "mitre": {"technique": ["T1071"]}
            },
            {
                "timestamp": (datetime.now() + timedelta(minutes=5)).isoformat(),
                "rule": "Sensitive file accessed - SAM database",
                "level": 14,
                "agent": "Windows-Server-01",
                "groups": ["windows", "credential_access"],
                "mitre": {"technique": ["T1003.002"]}
            }
        ]
        
        print(f"[*] Analyzing {len(test_events)} simulated attack events...")
        
        instructions = """
        These events show a clear attack progression. Analyze the kill chain and provide:
        {
            "threat_detected": true,
            "confidence": 85-95,
            "attack_pattern": "Describe the full attack chain from initial execution through credential theft",
            "mitre_techniques": ["List all MITRE ATT&CK techniques observed"],
            "affected_hosts": ["Windows-Server-01"],
            "priority": "critical",
            "timeline": "Show attack progression timeline",
            "recommended_actions": [
                "Isolate affected system",
                "Reset credentials",
                "Check for lateral movement",
                "Review PowerShell logs",
                "Hunt for similar patterns"
            ],
            "iocs": ["185.220.101.45", "Encoded PowerShell commands", "Registry modifications"]
        }
        """
        
        return self.analyze_with_ai(test_events, instructions)

if __name__ == "__main__":
    print("="*60)
    print("🛡️  WAZUH AI-POWERED THREAT HUNTER")
    print("="*60)
    
    hunter = ThreatHunter()
    result = hunter.hunt_recent_alerts()
    
    print("\n[*] Threat hunt complete!")
    print("="*60)
