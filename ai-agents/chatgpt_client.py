import os
import json

def analyze_with_ai(alert):
    # For now, return mock response
    # TODO: Integrate OpenAI API
    return {
        "verdict": "MONITOR",
        "confidence": 0.85,
        "reasoning": "Sdbinst.exe can be abused for persistence but is legitimate Windows component"
    }
