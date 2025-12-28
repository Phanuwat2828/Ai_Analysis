import json
import sys
from classification.features import extract_features_001 as extract_features_classification
from regression.features import extract_features_001 as extract_features_regression

# ทดสอบกับไฟล์ malware
malware_file = 'Data/malware/16_25_独角兽号的秘密_下集.json'
benign_file = 'Data/benign/SAFE_40_25_(V3)_Hoy_b.json'

print("=" * 100)
print("TESTING NEW FEATURES EXTRACTION")
print("=" * 100)

# Test Classification Features
print("\n1. CLASSIFICATION FEATURES:")
print("-" * 100)
with open(malware_file, 'r', encoding='utf-8') as f:
    malware_data = json.load(f)

features_class = extract_features_classification(malware_data)
print(f"Total features extracted: {len(features_class)}")
print("\nNew features added:")

new_features = [
    'tracker_count', 'secrets_count', 'average_cvss', 'malware_permission_count',
    'min_sdk', 'target_sdk', 'appsec_high', 'appsec_warning',
    'email_count', 'binary_analysis_count', 'has_code_warning', 'has_manifest_info'
]

for feat in new_features:
    if feat in features_class:
        print(f"  {feat:30} = {features_class[feat]}")
    else:
        print(f"  {feat:30} = [NOT FOUND]")

# Test Regression Features
print("\n2. REGRESSION FEATURES:")
print("-" * 100)
features_reg = extract_features_regression(malware_data)
print(f"Total features extracted: {len(features_reg)}")
print("\nNew features added:")

for feat in new_features:
    if feat in features_reg:
        print(f"  {feat:30} = {features_reg[feat]}")
    else:
        print(f"  {feat:30} = [NOT FOUND]")

# Compare Benign vs Malware
print("\n3. COMPARISON: BENIGN vs MALWARE")
print("-" * 100)
with open(benign_file, 'r', encoding='utf-8') as f:
    benign_data = json.load(f)

benign_feat = extract_features_classification(benign_data)

print(f"{'Feature':30} | {'Benign':10} | {'Malware':10} | Difference")
print("-" * 70)
for feat in new_features:
    b_val = benign_feat.get(feat, 0)
    m_val = features_class.get(feat, 0)
    diff = m_val - b_val
    print(f"{feat:30} | {b_val:10} | {m_val:10} | {diff:+10}")

print("\n" + "=" * 100)
print("TESTING COMPLETE!")
print("=" * 100)
print(f"\nClassification Features: {len(features_class)} total")
print(f"Regression Features: {len(features_reg)} total")
print(f"New Features Added: {len(new_features)}")
