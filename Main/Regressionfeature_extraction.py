import glob
import pandas as pd
import json
import os
import math
from tqdm import tqdm
from Regressionfeature import extract_features_001 as extract_features

MAX_CAP = 50  # cap สำหรับ feature ที่เป็น count


def compute_feature_score(v, max_cap=MAX_CAP):
    """
    Generic scoring for all features
    """
    # boolean
    if isinstance(v, bool):
        return 1.0 if v else 0.0

    # numeric (count-based)
    if isinstance(v, (int, float)):
        if v <= 0:
            return 0.0
        if v <= 1:
            return 1.0
        v = min(v, max_cap)
        return math.log1p(v) / math.log1p(max_cap)

    # others
    return 0.0


def process_malware_dataset(max_files_per_folder=8000):
    BASE_PATH = os.path.abspath(os.getcwd())
    folder_path = os.path.join(BASE_PATH, "Data", "regression")

    dataset = []

    json_files = glob.glob(os.path.join(folder_path, "*.json"))
    json_files = json_files[:max_files_per_folder]

    print(f"📂 Found {len(json_files)} JSON files")

    for json_file in tqdm(json_files, desc="Processing MobSF reports", unit="file"):
        try:
            with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)

            raw_features = extract_features(data)

            feature_row = {}
            risk_sum = 0.0
            total_features = 0

            for k, v in raw_features.items():
                score = compute_feature_score(v)

                # เก็บค่า feature ดิบ (ไว้ train ML)
                feature_row[k] = v

                risk_sum += score
                total_features += 1

            # 🎯 regression label (0–1)
            risk_score = risk_sum / total_features if total_features > 0 else 0
            feature_row["label"] = risk_score

            dataset.append(feature_row)

        except Exception as e:
            print(f"\n❌ Error processing {json_file}: {e}")

    return pd.DataFrame(dataset)


if __name__ == "__main__":
    df = process_malware_dataset()
    print(f"\n📊 Dataset shape: {df.shape}")

    if not df.empty:
        output_dir = os.path.join(os.getcwd(), "Dataset")
        os.makedirs(output_dir, exist_ok=True)

        output_file = os.path.join(output_dir, "malware_dataset_regression.csv")
        df.to_csv(output_file, index=False, encoding="utf-8")

        print(f"✅ Dataset saved to {output_file}")
