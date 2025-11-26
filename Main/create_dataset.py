import glob
import pandas as pd
import json
import os
from feature import extract_features_002 as extract_features
import matplotlib.pyplot as plt
import seaborn as sns

def process_malware_dataset(max_files_per_folder=6000):
    BASE_PATH = os.path.abspath(os.path.join(os.getcwd(), "."))  
    folders = ['malware', 'benign']
    dataset = []
    
    for folder in folders:
        folder_path = os.path.join(BASE_PATH, "Data", folder)
        print("===========> " + folder_path)

        json_files = glob.glob(os.path.join(folder_path, "*.json"))
        print(f"{folder}: found {len(json_files)} JSON files")

        if len(json_files) > max_files_per_folder:
            json_files = json_files[:max_files_per_folder] 

        print(f"{folder}: using {len(json_files)} files")

        label = 0 if folder == 'benign' else 1 
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                
                features = extract_features(data)
                features['label'] = label
                features['family'] = folder
                features['filename'] = os.path.basename(json_file)
                
                dataset.append(features)
                
            except Exception as e:
                print(f"Error processing {json_file}: {e}")
    
    return pd.DataFrame(dataset)



if __name__ == "__main__":
    df = process_malware_dataset()
    print(f"Dataset shape: {df.shape}")

    if not df.empty and 'label' in df.columns:
        print(f"Malware samples: {df['label'].sum()}")
        print(f"Safe samples: {len(df) - df['label'].sum()}")

        # ===== Export as CSV =====
        output_dir = os.path.join(os.getcwd(), "Dataset")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "malware_dataset.csv")
        df.to_csv(output_file, index=False, encoding='utf-8')
        print(f"✅ Dataset saved to {output_file}")

        # ===== Visualization of 5 key features =====
        key_features = [
            "dangerous_permissions",
            "uses_dexloading",
            "uses_reflection",
            "uses_os_command",
            "has_record_audio"
        ]

        plt.figure(figsize=(15, 8))
        for i, feat in enumerate(key_features, 1):
            plt.subplot(2, 3, i)
            if df[feat].nunique() <= 2:  
                sns.countplot(data=df, x=feat, hue="label", palette="husl")
                plt.title(f"{feat} (Binary)")
            else:
                sns.boxplot(data=df, x="label", y=feat, palette="husl")
                plt.title(f"{feat} (Numeric)")
            plt.xlabel("Label (0=Safe, 1=Malware)")
        
        plt.tight_layout()
        plt.show()

    else:
        print("⚠️ Dataset ว่างหรือไม่มีคอลัมน์ 'label'")
