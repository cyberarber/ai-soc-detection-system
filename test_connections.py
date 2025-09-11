#!/usr/bin/env python3
"""
Test all connections before building agents
"""

import os
import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
import openai
import warnings
warnings.filterwarnings('ignore')

load_dotenv()

print("="*50)
print("TESTING CONNECTIONS")
print("="*50)

# Test Wazuh
try:
    wazuh_user = os.getenv('WAZUH_USER')
    wazuh_pass = os.getenv('WAZUH_PASSWORD')
    response = requests.get(
        'https://localhost:55000/security/user/authenticate',
        auth=(wazuh_user, wazuh_pass),
        verify=False
    )
    if response.status_code == 200:
        print("✓ Wazuh API: Connected")
        wazuh_token = response.json()['data']['token']
    else:
        print("✗ Wazuh API: Failed")
except Exception as e:
    print(f"✗ Wazuh API: {e}")

# Test Elasticsearch
try:
    es = Elasticsearch(['http://localhost:9200'])
    info = es.info()
    print(f"✓ Elasticsearch: Connected (v{info['version']['number']})")
    
    # Check for Wazuh indices
    indices = es.indices.get_alias(index="wazuh-alerts-*")
    print(f"  Found {len(indices)} Wazuh indices")
except Exception as e:
    print(f"✗ Elasticsearch: {e}")

# Test OpenAI
try:
    openai.api_key = os.getenv('OPENAI_API_KEY')
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Reply with: OK"}],
        max_tokens=5
    )
    print(f"✓ OpenAI GPT-4: {response.choices[0].message.content}")
except Exception as e:
    print(f"✗ OpenAI: {e}")
    print("  Make sure you added your API key to .env file")

print("="*50)
