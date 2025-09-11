#!/usr/bin/env python3
"""Monitor all Wazuh events"""

from elasticsearch import Elasticsearch
from datetime import datetime
import json

es = Elasticsearch(['http://localhost:9200'])

print("\nChecking last 10 minutes of activity...\n")

query = {
    "query": {
        "range": {
            "@timestamp": {
                "gte": "now-10m"
            }
        }
    },
    "size": 200,
    "sort": [{"@timestamp": {"order": "desc"}}]
}

results = es.search(index="wazuh-alerts-*", body=query)
events = results['hits']['hits']

print(f"Total events: {len(events)}\n")

# Group by severity
high_alerts = []
for event in events:
    src = event['_source']
    level = src.get('rule', {}).get('level', 0)
    
    if level >= 5:
        high_alerts.append({
            'level': level,
            'rule': src.get('rule', {}).get('description', 'Unknown'),
            'agent': src.get('agent', {}).get('name', 'Unknown'),
            'time': src.get('@timestamp')
        })

if high_alerts:
    print(f"Found {len(high_alerts)} significant events (level 5+):\n")
    for alert in high_alerts[:20]:
        print(f"[Level {alert['level']}] {alert['rule']}")
        print(f"  Agent: {alert['agent']} | Time: {alert['time']}\n")
else:
    print("No high-level alerts found")
    print("\nShowing last 10 events of ANY level:\n")
    for event in events[:10]:
        src = event['_source']
        print(f"- {src.get('rule', {}).get('description', 'Unknown')}")
