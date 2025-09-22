import os
import json
import pandas as pd
folders = ['Banker', 'Spyware', 'Trojan','Safe']
from feature import extract_features_from_json as feature
import json

# Dangerous Permissions
# High & Medium Severity Vulnerabilities (จาก manifest และ certificate)
# AllowBackup & Debuggable
# Obfuscation & Reflection
# VirusTotal Summary
# Binary Flags (Native, Java Debug, Cleartext)
# Suspicious URLs
# Exported Components (activities, services, receivers, providers)
# Dangerous API Calls (เช่น exec(), system.exit)
# Crypto API (เช่น MD5, DES)
# Suspicious Strings (เช่น root, shell, inject)
# Dynamic Behavior Features (การเรียกใช้ API อันตรายและการตรวจจับพฤติกรรมที่น่าสงสัย)
# Rooting Detection (การตรวจจับการติดตั้งแอปบนอุปกรณ์ที่ rooted)

data = []
for folder in folders:
    folder_path = os.path.join("./Data/", folder)
    files = [f for f in os.listdir(folder_path) if f.endswith('.json')]
    if(folder=="Safe"):
        label = folder
    else:
        label = "Malware"
    
    for file in files:
        with open(os.path.join(folder_path, file), 'r', encoding='utf-8') as f:
            json_data = json.load(f)
            features = feature(json_data)
            features['label'] = label
            data.append(features)

df = pd.DataFrame(data)
output_file = "./Dataset/apk_analysis_dataset.csv"
df.to_csv(output_file, index=False)