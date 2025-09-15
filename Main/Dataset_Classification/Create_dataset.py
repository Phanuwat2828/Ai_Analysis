import pandas as pd
import json
import os
import Fetures as fe  # หรือ Features ถ้าสะกดชื่อไฟล์ใหม่

all_features = []
all_labels = []

# ใช้ path แบบ raw string ป้องกัน \r \t
REPORTS_DIR = r'C:\github_\Ai_Analysis\Main\Data'

print("\n--- กำลังโหลดข้อมูลจากโฟลเดอร์ JSON ---")
if os.path.isdir(REPORTS_DIR):
    for fname in os.listdir(REPORTS_DIR):
        if fname.endswith('.json'):
            label = 0 if fname.startswith('good_') else 1
            file_path = os.path.join(REPORTS_DIR, fname)

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)  # ❗ใช้ชื่อว่า report_data ไม่ใช่ fname

                features = fe.extract_features_mobsf(report_data)
                all_features.append(features)
                all_labels.append(label)

            except Exception as e:
                print(f"[ผิดพลาด] ไฟล์ {fname}: {e}")
else:
    print(f"ไม่พบโฟลเดอร์ '{REPORTS_DIR}'")

# รวมข้อมูล
if all_features:
    df = pd.DataFrame(all_features)
    df['label'] = all_labels
    print("✔ ได้ข้อมูลทั้งหมด:", len(df))
    print(df.head())
    output_dir = os.path.join("Main", "Dataset")
    output_path = os.path.join(output_dir, "all_features_df.csv")

    # ✅ สร้างโฟลเดอร์ถ้ายังไม่มี
    os.makedirs(output_dir, exist_ok=True)

    # ✅ บันทึก DataFrame เป็น .csv
    df.to_csv(output_path, index=False)
    print(f"✔ บันทึกไฟล์ CSV แล้วที่: {output_path}")
else:
    print("❌ ไม่มีข้อมูลที่ใช้ได้")

