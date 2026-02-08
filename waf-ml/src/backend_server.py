from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from adaptive_waf import AdaptiveWAF
from datetime import datetime
import uvicorn

app = FastAPI(title="Adaptive WAF API")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load ML model
print("Loading WAF model...")
waf = AdaptiveWAF()
try:
    waf.load('models/adaptive_waf.pkl')
    print("✓ Model loaded")
except:
    print("Model not found. Training...")
    waf.train()
    waf.save('models/adaptive_waf.pkl')
    print("✓ Model trained and saved")

# Statistics tracking
stats = {
    'total_requests': 0,
    'blocked_requests': 0,
    'allowed_requests': 0,
    'attack_types': {
        'SQLi': 0,
        'XSS': 0,
        'Path Traversal': 0,
        'RCE': 0,
        'Unknown': 0
    },
    'recent_attacks': []
}

@app.post("/check")
async def check_request(request: Request):
    """Analyze incoming request for threats"""
    body = await request.body()
    payload = body.decode('utf-8')
    
    # ML prediction
    result = waf.predict(payload)
    
    # Update statistics
    stats['total_requests'] += 1
    
    if result['prediction'] == 'malicious':
        stats['blocked_requests'] += 1
        
        # Detect attack type
        attack_type = 'Unknown'
        payload_lower = payload.lower()
        if any(kw in payload_lower for kw in ['select', 'union', 'drop', 'insert']):
            attack_type = 'SQLi'
        elif any(kw in payload_lower for kw in ['<script', 'alert(', 'onerror']):
            attack_type = 'XSS'
        elif '../' in payload or '..\\' in payload:
            attack_type = 'Path Traversal'
        elif any(kw in payload_lower for kw in ['exec', 'eval', 'system', 'cmd']):
            attack_type = 'RCE'
        
        stats['attack_types'][attack_type] += 1
        
        # Add to recent attacks (keep last 10)
        stats['recent_attacks'].insert(0, {
            'timestamp': datetime.now().isoformat(),
            'payload': payload[:100],
            'type': attack_type,
            'confidence': result['confidence']
        })
        stats['recent_attacks'] = stats['recent_attacks'][:10]
    else:
        stats['allowed_requests'] += 1
    
    return {
        'prediction': result['prediction'],
        'confidence': result['confidence'],
        'latency_ms': result['latency_ms'],
        'timestamp': datetime.now().isoformat()
    }

@app.get("/stats")
async def get_stats():
    """Get real-time statistics for dashboard"""
    return {
        'total_requests': stats['total_requests'],
        'blocked_requests': stats['blocked_requests'],
        'allowed_requests': stats['allowed_requests'],
        'block_rate': round(stats['blocked_requests'] / max(stats['total_requests'], 1) * 100, 2),
        'attack_types': stats['attack_types'],
        'recent_attacks': stats['recent_attacks']
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {'status': 'healthy', 'model_loaded': True}

if __name__ == "__main__":
    print("\n=== Adaptive WAF Backend Server ===")
    print("Starting server on http://localhost:8000")
    print("Endpoints:")
    print("  POST /check  - Analyze request")
    print("  GET  /stats  - Get statistics")
    print("  GET  /health - Health check")
    print("\nPress Ctrl+C to stop\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
