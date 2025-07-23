# save as: extract_detections.py
from elasticsearch import Elasticsearch
import pandas as pd
import json

# Connect to Elasticsearch
es = Elasticsearch(['http://192.168.110.128:9200'])

# Get your whoami detections
query = {
    "query": {
        "bool": {
            "must": [
                {"match": {"winlog.event_id": "1"}},
                {"wildcard": {"winlog.event_data.CommandLine": "*whoami*"}}
            ]
        }
    },
    "size": 100,
    "_source": ["@timestamp", "winlog.event_data.CommandLine", "winlog.event_data.Image", 
                "agent.hostname", "winlog.event_data.User", "winlog.event_data.ProcessId"]
}

response = es.search(index="winlogbeat-*", body=query)

# Convert to DataFrame
detections = []
for hit in response['hits']['hits']:
    data = hit['_source']
    flat_data = {
        'timestamp': data.get('@timestamp'),
        'command_line': data.get('winlog', {}).get('event_data', {}).get('CommandLine'),
        'process_path': data.get('winlog', {}).get('event_data', {}).get('Image'),
        'hostname': data.get('agent', {}).get('hostname'),
        'user': data.get('winlog', {}).get('event_data', {}).get('User'),
        'process_id': data.get('winlog', {}).get('event_data', {}).get('ProcessId')
    }
    detections.append(flat_data)

df = pd.DataFrame(detections)
print(f"Extracted {len(df)} detections")
print(df.head())

# Save for AI training
df.to_csv('security_detections.csv', index=False)
