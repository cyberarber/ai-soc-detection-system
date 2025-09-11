#!/usr/bin/env python3
"""Detect ALL SSH-related events"""

from elasticsearch import Elasticsearch
from datetime import datetime
import json

es = Elasticsearch(['http://localhost:9200'])

print("\nSearching for SSH-related events...\n")

# Broader query for ANY SSH-related activity
query = {
    "query": {
        "bool": {
            "should": [
                {"match": {"full_log": "ssh"}},
                {"match": {"full_log": "Failed password"}},
                {"match": {"full_log": "authentication failure"}},
                {"match": {"data.srcip": "192.168"}},
                {"match": {"rule.groups": "sshd"}},
                {"match": {"decoder.name": "sshd"}}
            ],
            "filter": {
                "range": {"@timestamp": {"gte": "now-10m"}}
            }
        }
    },
    "size": 100
}

results = es.search(index="wazuh-alerts-*", body=query)

if results['hits']['hits']:
    print(f"Found {len(results['hits']['hits'])} SSH-related events!\n")
    
    # Group by rule level
    by_level = {}
    for hit in results['hits']['hits']:
        src = hit['_source']
        level = src.get('rule', {}).get('level', 0)
        desc = src.get('rule', {}).get('description', 'Unknown')
        
        if level not in by_level:
            by_level[level] = []
        by_level[level].append(desc)
    
    for level in sorted(by_level.keys(), reverse=True):
        print(f"\nLevel {level} alerts:")
        for desc in set(by_level[level]):
            count = by_level[level].count(desc)
            print(f"  [{count}x] {desc}")
    
    # Check for brute force pattern
    if len(results['hits']['hits']) > 10:
        print("\n⚠️  POSSIBLE BRUTE FORCE ATTACK DETECTED!")
        print(f"   {len(results['hits']['hits'])} SSH events in last 10 minutes")
else:
    print("No SSH events found. Checking if Wazuh is processing auth.log...")
    
    # Debug query - show ANY recent events
    query = {"query": {"match_all": {}}, "size": 10, "sort": [{"@timestamp": {"order": "desc"}}]}
    results = es.search(index="wazuh-alerts-*", body=query)
    
    print(f"\nLast 10 events of any type:")
    for hit in results['hits']['hits']:
        src = hit['_source']
        print(f"- {src.get('@timestamp')}: {src.get('rule', {}).get('description', 'Unknown')}")
