import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import re

class CommandLineAnomalyDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=50, ngram_range=(1,2))
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        
    def extract_features(self, df, training=False):
        """Extract ML features from command lines"""
        features = pd.DataFrame()
        
        # Behavioral features
        features['cmd_length'] = df['command_line'].fillna('').str.len()
        features['has_pipe'] = df['command_line'].fillna('').str.contains('|', regex=False).astype(int)
        features['has_redirect'] = df['command_line'].fillna('').str.contains('>', regex=False).astype(int)
        features['has_encoding'] = df['command_line'].fillna('').str.contains('-enc|-Enc', regex=True).astype(int)
        features['has_bypass'] = df['command_line'].fillna('').str.contains('bypass|Bypass', regex=True).astype(int)
        features['has_hidden'] = df['command_line'].fillna('').str.contains('hidden|Hidden', regex=True).astype(int)
        features['param_count'] = df['command_line'].fillna('').str.count('-')
        
        # Time features
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        features['is_afterhours'] = ((df['hour'] < 8) | (df['hour'] > 18)).astype(int)
        
        # Process all features as numpy array
        return features.values
    
    def train(self, df):
        """Train the anomaly detection model"""
        print("Training AI model on command line data...")
        
        # Extract features
        features = self.extract_features(df, training=True)
        
        # Train model
        self.model.fit(features)
        self.is_trained = True
        
        # Calculate training scores
        train_scores = self.model.score_samples(features)
        print(f"Training scores - Mean: {train_scores.mean():.3f}, Std: {train_scores.std():.3f}")
        
        # Save model
        joblib.dump(self.model, 'ai_anomaly_model.pkl')
        print("✅ AI Model trained and saved!")
        print(f"   Features used: {features.shape[1]}")
        print(f"   Samples trained on: {features.shape[0]}")
    
    def predict(self, new_commands):
        """Detect anomalies in new commands"""
        if not self.is_trained:
            self.model = joblib.load('ai_anomaly_model.pkl')
            
        # Extract same features
        features = self.extract_features(new_commands, training=False)
        
        # Predict
        predictions = self.model.predict(features)
        scores = self.model.score_samples(features)
        
        new_commands['is_anomaly'] = predictions == -1
        new_commands['anomaly_score'] = scores
        
        return new_commands

# Train the model
if __name__ == "__main__":
    # Load your detection data
    df = pd.read_csv('security_detections.csv')
    print(f"Loaded {len(df)} security events")
    
    # Initialize and train
    detector = CommandLineAnomalyDetector()
    detector.train(df)
    
    # Test on suspicious commands
    print("\n🔍 Testing AI detection on suspicious commands...")
    
    test_commands = pd.DataFrame({
        'timestamp': ['2025-07-21 13:00:00', '2025-07-21 03:00:00', '2025-07-21 14:00:00'],
        'command_line': [
            'powershell -enc SGVsbG8gV29ybGQ=',  # Encoded command (suspicious)
            'cmd.exe /c whoami && net user',      # Chained commands at 3 AM (suspicious)  
            'notepad.exe C:\\Users\\file.txt'      # Normal command
        ],
        'hostname': ['DESKTOP-TEST', 'DESKTOP-TEST', 'DESKTOP-TEST']
    })
    
    results = detector.predict(test_commands)
    
    print("\n📊 Detection Results:")
    for idx, row in results.iterrows():
        status = "🚨 ANOMALY" if row['is_anomaly'] else "✅ Normal"
        print(f"{status} | Score: {row['anomaly_score']:.3f} | Command: {row['command_line'][:50]}...")
