from adaptive_waf import AdaptiveWAF
import pandas as pd

waf = AdaptiveWAF()

# Load dataset
X, y = waf.load_dataset()

# Create DataFrame
df = pd.DataFrame({
    'Payload': X,
    'Label': y,
    'Type': ['Benign' if label == 0 else 'Malicious' for label in y]
})

print("="*80)
print("DATASET OVERVIEW")
print("="*80)

y_array = [label for label in y]
benign_count = sum(1 for label in y_array if label == 0)
malicious_count = sum(1 for label in y_array if label == 1)

print(f"\nTotal Samples: {len(df)}")
print(f"Benign: {benign_count} ({benign_count/len(y_array)*100:.1f}%)")
print(f"Malicious: {malicious_count} ({malicious_count/len(y_array)*100:.1f}%)")

print("\n" + "="*80)
print("BENIGN SAMPLES (First 10)")
print("="*80)
benign = df[df['Label'] == 0].head(10)
for i, row in benign.iterrows():
    print(f"{i+1}. {row['Payload']}")

print("\n" + "="*80)
print("MALICIOUS SAMPLES (First 20)")
print("="*80)
malicious = df[df['Label'] == 1].head(20)
for i, row in malicious.iterrows():
    print(f"{i+1}. {row['Payload']}")

print("\n" + "="*80)
print("ATTACK TYPE BREAKDOWN")
print("="*80)

attack_types = {
    'SQL Injection': ["' OR", "UNION", "SELECT", "DROP", "--", "admin'"],
    'XSS': ["<script>", "alert", "onerror", "javascript:", "<img", "<svg"],
    'Path Traversal': ["../", "..\\", "/etc/passwd", "windows/system32"],
    'RCE': ["; cat", "| ls", "; DROP", "exec"]
}

for attack_type, keywords in attack_types.items():
    count = sum(1 for payload in X if any(kw.lower() in payload.lower() for kw in keywords))
    print(f"{attack_type}: {count} samples")

print("\n" + "="*80)
print("PAYLOAD LENGTH STATISTICS")
print("="*80)

lengths = [len(p) for p in X]
print(f"Min length: {min(lengths)} characters")
print(f"Max length: {max(lengths)} characters")
print(f"Average length: {sum(lengths)/len(lengths):.1f} characters")

print("\n" + "="*80)
print("SAMPLE DISTRIBUTION")
print("="*80)
print(df['Type'].value_counts())

# Export to CSV
csv_file = 'dataset_overview.csv'
df.to_csv(csv_file, index=False)
print(f"\n✓ Full dataset exported to: {csv_file}")
