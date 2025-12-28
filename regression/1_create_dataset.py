import glob
import pandas as pd
import json
import os
from tqdm import tqdm
from features import extract_features_001 as extract_features


def binarize(v):
    """
    Convert all features to 0 / 1
    """
    if isinstance(v, bool):
        return 1 if v else 0

    if isinstance(v, (int, float)):
        return 1 if v > 0 else 0

    if isinstance(v, (list, dict, set, tuple)):
        return 1 if len(v) > 0 else 0

    return 0


def process_malware_dataset(max_files_per_folder=8000):
    BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
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
            risk_sum = 0
            total_features = 0

            for k, v in raw_features.items():
                val = binarize(v)

                feature_row[k] = val
                risk_sum += val
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
        output_dir = os.path.join(os.path.dirname(__file__), "..", "Dataset")
        output_dir = os.path.abspath(output_dir)
        os.makedirs(output_dir, exist_ok=True)

        output_file = os.path.join(output_dir, "malware_dataset_regression.csv")
        df.to_csv(output_file, index=False, encoding="utf-8")

        print(f"✅ Dataset saved to {output_file}")
