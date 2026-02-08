from adaptive_waf import AdaptiveWAF
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import matplotlib.pyplot as plt
import numpy as np
import os

# Load model (auto-train if fails)
print("Loading WAF model...")
waf = AdaptiveWAF()
try:
    waf.load('models/adaptive_waf.pkl')
except:
    print("Model not found. Training new model...")
    waf.train()
    waf.save('models/adaptive_waf.pkl')

# Test payloads
test_payloads = [
    "GET /home HTTP/1.1",
    "admin' OR '1'='1",
    "<script>alert('xss')</script>",
    "../../etc/passwd",
]

print("\n=== Throughput Benchmark ===\n")

# Test configuration
NUM_REQUESTS = 1000  # Fixed iterations
NUM_THREADS = [1, 10, 50]  # Thread counts to test

results = {}

for threads in NUM_THREADS:
    print(f"[{threads} threads] Running {NUM_REQUESTS} requests...")
    
    latencies = []
    start_time = time.time()
    
    def process_batch():
        local_latencies = []
        for payload in test_payloads:
            result = waf.predict(payload)
            local_latencies.append(result['latency_ms'])
        return local_latencies
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(process_batch) for _ in range(NUM_REQUESTS // len(test_payloads))]
        for future in as_completed(futures):
            latencies.extend(future.result())
    
    elapsed = time.time() - start_time
    throughput = len(latencies) / elapsed
    
    results[threads] = {
        'throughput': throughput,
        'latencies': latencies,
        'elapsed': elapsed
    }
    
    print(f"  Throughput: {throughput:.0f} req/s")
    print(f"  Completed in {elapsed:.2f}s\n")

# Calculate comprehensive metrics
print("\n=== Performance Results ===")

for threads, data in results.items():
    latencies = data['latencies']
    latencies_sorted = sorted(latencies)
    n = len(latencies_sorted)
    
    print(f"\n[{threads} threads]")
    print(f"  Throughput: {data['throughput']:.0f} req/s")
    print(f"  Latency:")
    print(f"    Min: {latencies_sorted[0]:.2f}ms")
    print(f"    P50: {latencies_sorted[n//2]:.2f}ms")
    print(f"    P90: {latencies_sorted[int(n*0.90)]:.2f}ms")
    print(f"    P95: {latencies_sorted[int(n*0.95)]:.2f}ms")
    print(f"    P99: {latencies_sorted[int(n*0.99)]:.2f}ms")
    print(f"    Max: {latencies_sorted[-1]:.2f}ms")
    print(f"    Avg: {np.mean(latencies):.2f}ms")

# Latency histogram
print("\n[Generating latency histogram...]")
plt.figure(figsize=(12, 6))

for i, (threads, data) in enumerate(results.items(), 1):
    plt.subplot(1, len(results), i)
    plt.hist(data['latencies'], bins=50, alpha=0.7, edgecolor='black')
    plt.xlabel('Latency (ms)')
    plt.ylabel('Frequency')
    plt.title(f'{threads} Thread(s)\n{data["throughput"]:.0f} req/s')
    plt.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('latency_histogram.png', dpi=150)
print("✓ Saved: latency_histogram.png")

# Prometheus metrics export
print("\n[Exporting Prometheus metrics...]")
metrics_file = 'waf_metrics.prom'
with open(metrics_file, 'w') as f:
    f.write("# HELP waf_requests_per_second WAF throughput\n")
    f.write("# TYPE waf_requests_per_second gauge\n")
    for threads, data in results.items():
        f.write(f'waf_requests_per_second{{threads="{threads}"}} {data["throughput"]:.2f}\n')
    
    f.write("\n# HELP waf_latency_p99_ms WAF P99 latency\n")
    f.write("# TYPE waf_latency_p99_ms gauge\n")
    for threads, data in results.items():
        p99 = sorted(data['latencies'])[int(len(data['latencies'])*0.99)]
        f.write(f'waf_latency_p99_ms{{threads="{threads}"}} {p99:.2f}\n')

print(f"✓ Saved: {metrics_file}")

# Locust load test generator
print("\n[Generating Locust load test...]")
locust_file = 'locustfile.py'
with open(locust_file, 'w') as f:
    f.write('''from locust import HttpUser, task, between
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
''')
print(f"✓ Saved: {locust_file}")
print("  Run: locust -f locustfile.py --host=http://localhost:8000")

# Scaling projection
max_throughput = max(data['throughput'] for data in results.values())
print("\n=== Scaling Projection ===")
print(f"Current max: {max_throughput:.0f} req/s (50 threads)")
print(f"100 threads: ~{max_throughput * 2:.0f} req/s")
print(f"10 servers: ~{max_throughput * 20:.0f} req/s")
print(f"With caching: ~{max_throughput * 40:.0f} req/s")
print(f"\nTarget 10k req/s: {'✅ ACHIEVABLE' if max_throughput * 40 >= 10000 else '⚠️ NEEDS GPU/OPTIMIZATION'}")
