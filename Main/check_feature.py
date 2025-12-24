import pandas as pd

def analyze_feature_difference(csv_path):
    df = pd.read_csv(csv_path)

    benign = df[df["label"] == 0]
    malware = df[df["label"] == 1]

    feature_cols = [c for c in df.columns if c != "label"]

    results = []

    for feature in feature_cols:

        # ข้ามคอลัมน์ที่ไม่ใช่ตัวเลข
        if not pd.api.types.is_numeric_dtype(df[feature]):
            print(f"Skipping non-numeric feature: {feature}")
            continue

        benign_mean = benign[feature].mean()
        malware_mean = malware[feature].mean()

        # ความต่าง %
        if benign_mean == 0 and malware_mean == 0:
            diff_percent = 0
        else:
            diff_percent = abs(malware_mean - benign_mean) / (max(benign_mean, malware_mean) + 1e-9) * 100

        results.append({
            "feature": feature,
            "benign_mean": benign_mean,
            "malware_mean": malware_mean,
            "difference_percent": diff_percent
        })

    result_df = pd.DataFrame(results)
    result_df = result_df.sort_values(by="difference_percent", ascending=False)

    return result_df


# Run
df_result = analyze_feature_difference("./Dataset/malware_dataset_regression.csv")

# ให้ Pandas แสดงผลทั้งหมดแบบไม่ตัด
import pandas as pd
pd.set_option("display.max_rows", None)
pd.set_option("display.max_columns", None)
pd.set_option("display.width", None)

print(df_result)

