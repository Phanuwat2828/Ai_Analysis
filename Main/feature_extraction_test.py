import glob
import json
import os
from Regressionfeature import extract_features_001 as extract_features

BASE_PATH = os.path.abspath(os.path.join(os.getcwd(), "."))

malware_files = glob.glob(os.path.join(BASE_PATH, "Data", "malware", "*.json"))
benign_files  = glob.glob(os.path.join(BASE_PATH, "Data", "benign", "*.json"))



def debug(json_path, label):
    print("\n==============================")
    print(f"FILE: {os.path.basename(json_path)} ({label})")
    print("==============================")

    with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
        data = json.load(f)

    features = extract_features(data)

    print(f"\nจำนวน feature: {len(features)}\n")
    total = 0;
    # Loop ตามลำดับ feature ที่กำหนด
    for idx, feat in enumerate(feature_order, start=1):
        value = features.get(feat, None)
        print(value)
        total+=int(value)
        print(f"{idx:02d}| {feat:35} : {value}")
        # print(value)
    print("Score : ",total)
# ใช้แค่ไฟล์แรกของแต่ละโฟลเดอร์
debug(malware_files[0], "malware")
debug(benign_files[0], "benign")


