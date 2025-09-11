#!/usr/bin/env python3
"""Detect any suspicious activity"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json
import time

es = Elasticsearch(['http://localhost:9200'])

print("\n" + "="*60)
print("MONITORING ALL EVENTS")
print("="*60 + "\n")

# Get ALL recent events
query = {
    "query": {
        "range": {
            "@timestamp": {
                "gte": "now-5m"
            }
        }
    },
    "size": 100,
    "sort": [{"@timestamp": {"order": "desc"}}]
}

results = es.search(index="wazuh-alerts-*", body=query)
print(f"Found {len(results['hits']['hits'])} total events in last 5 minutes\n")

# Show high-level events
for hit in results['hits']['hits']:
    src = hit['_source']
    level = src.get('rule', {}).get('level', 0)
    if level >= 5:
        print(f"Level {level}: {src.get('rule', {}).get('description')}")
        print(f"  Agent: {src.get('agent', {}).get('name')}")
        print(f"  Time: {src.get('@timestamp')}\n")
