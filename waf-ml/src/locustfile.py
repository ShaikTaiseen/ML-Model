from locust import HttpUser, task, between
import random

class WAFUser(HttpUser):
    wait_time = between(0.1, 0.5)
    
    payloads = [
        "GET /index.html HTTP/1.1",
        "' OR '1'='1",
        "<script>alert('xss')</script>",
        "../../etc/passwd"
    ]
    
    @task
    def check_payload(self):
        payload = random.choice(self.payloads)
        self.client.post("/check", data=payload)

# Run: locust -f locustfile.py --host=http://localhost:8000
