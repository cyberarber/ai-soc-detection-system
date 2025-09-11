#!/usr/bin/env python3
"""
Test connections with new OpenAI client
"""

import os
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from openai import OpenAI
import requests
import warnings
warnings.filterwarnings('ignore')

load_dotenv()

print("="*50)
print("TESTING CONNECTIONS")
print("="*50)

# Test Wazuh
try:
    response = requests.get(
        'https://localhost:55000/security/user/authenticate',
        auth=(os.getenv('WAZUH_USER'), os.getenv('WAZUH_PASSWORD')),
        verify=False
    )
    if response.status_code == 200:
        print("✓ Wazuh API: Connected")
except Exception as e:
    print(f"✗ Wazuh API: {e}")

# Test Elasticsearch
try:
    es = Elasticsearch(['http://localhost:9200'])
    info = es.info()
    print(f"✓ Elasticsearch: Connected (v{info['version']['number']})")
    indices = es.indices.get_alias(index="wazuh-alerts-*")
    print(f"  Found {len(indices)} Wazuh indices")
except Exception as e:
    print(f"✗ Elasticsearch: {e}")

# Test OpenAI with new client
try:
    client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Reply with: AI Agent Ready"}],
        max_tokens=10
    )
    print(f"✓ OpenAI GPT-4: {response.choices[0].message.content}")
except Exception as e:
    print(f"✗ OpenAI: {e}")

print("="*50)
