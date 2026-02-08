import requests
import time
import random

# Test requests - mix of normal and attacks
test_requests = [
    # Normal requests
    {
        "method": "GET",
        "url": "/home",
        "headers": {},
        "body": "",
        "source_ip": "192.168.1.100"
    },
    # SQL Injection
    {
        "method": "POST",
        "url": "/login",
        "headers": {},
        "body": "username=admin' OR '1'='1",
        "source_ip": "203.0.113.45"
    },
    # XSS Attack
    {
        "method": "GET",
        "url": "/search?q=<script>alert('xss')</script>",
        "headers": {},
        "body": "",
        "source_ip": "198.51.100.23"
    },
    # Path Traversal
    {
        "method": "GET",
        "url": "/files?path=../../etc/passwd",
        "headers": {},
        "body": "",
        "source_ip": "203.0.113.67"
    },
]

print("Sending test requests to WAF API...")
print("Open dashboard.html in browser to see results\n")

for i in range(20):
    request = random.choice(test_requests)
    
    try:
        response = requests.post("http://localhost:8000/analyze", json=request)
        result = response.json()
        
        status = "🚨 BLOCKED" if result['is_attack'] else "✓ ALLOWED"
        print(f"{status} - {request['url'][:50]} - {result['attack_type']}")
        
    except Exception as e:
        print(f"Error: {e}")
    
    time.sleep(1)

print("\n✓ Test complete! Check dashboard for results")
