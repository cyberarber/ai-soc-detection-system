#!/usr/bin/env python3
"""Detect SSH brute force attacks"""

from elasticsearch import Elasticsearch
from datetime import datetime
import json

es = Elasticsearch(['http://localhost:9200'])

print("\nMonitoring for SSH attacks...\n")

# Query for authentication failures
query = {
    "query": {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": "now-5m"}}},
                {"terms": {"rule.groups": ["authentication_failed", "authentication_failures", "invalid_login", "syslog"]}}
            ]
        }
    },
    "size": 100
}

results = es.search(index="wazuh-alerts-*", body=query)

if results['hits']['hits']:
    print(f"DETECTED: {len(results['hits']['hits'])} authentication failures!\n")
    for hit in results['hits']['hits'][:10]:
        src = hit['_source']
        print(f"Alert: {src.get('rule', {}).get('description')}")
        print(f"Level: {src.get('rule', {}).get('level')}")
        print(f"Time: {src.get('@timestamp')}\n")
else:
    # Try broader query
    query = {
        "query": {"match_all": {}},
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    results = es.search(index="wazuh-alerts-*", body=query)
    print(f"Recent events: {len(results['hits']['hits'])}")
    for hit in results['hits']['hits'][:5]:
        src = hit['_source']
        print(f"- {src.get('rule', {}).get('description')}")
