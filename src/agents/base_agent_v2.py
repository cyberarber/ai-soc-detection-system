#!/usr/bin/env python3
"""
SOC AI Agent Framework - Updated for new OpenAI client
"""

import os
import json
import requests
from datetime import datetime
from typing import Dict, List
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

class SOCAgent:
    """Base class for AI-powered SOC agents"""
    
    def __init__(self, role: str):
        self.role = role
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.wazuh_token = self._get_wazuh_token()
        
    def _get_wazuh_token(self):
        """Get Wazuh authentication token"""
        try:
            response = requests.get(
                'https://localhost:55000/security/user/authenticate',
                auth=(os.getenv('WAZUH_USER'), os.getenv('WAZUH_PASSWORD')),
                verify=False
            )
            return response.json()['data']['token']
        except:
            return None
    
    def analyze_with_ai(self, data: Dict, instructions: str) -> Dict:
        """Send data to GPT-4 for analysis"""
        prompt = f"""
        You are a {self.role} following SANS incident response methodology.
        
        Instructions: {instructions}
        
        Data to analyze:
        {json.dumps(data, indent=2)}
        
        Provide response in JSON format only.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": f"You are a senior {self.role}. Always respond in valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            
            result = response.choices[0].message.content
            # Clean up markdown if present
            if "```json" in result:
                result = result.split("```json")[1].split("```")[0]
            elif "```" in result:
                result = result.split("```")[1].split("```")[0]
                
            return json.loads(result.strip())
                
        except Exception as e:
            return {"error": str(e)}
