import pandas as pd
import os

# ==============================
# CONFIG
# ==============================
CSV_PATH = "./results/rf_xgb_hyperparameter_results.csv"
SAVE_DIR = "./results"
EXCLUDE_PERFECT = True   # ตั้งเป็น False ถ้าอยากรวมเคส 1.000

os.makedirs(SAVE_DIR, exist_ok=True)

# ==============================
# LOAD CSV
# ==============================
df = pd.read_csv(CSV_PATH)

print("\n=== CSV LOADED ===")
print("Shape:", df.shape)
print("Models:", df["model"].unique().tolist())

# ==============================
# SELECT BEST PARAMETERS
# ==============================
best_rows = []

print("\n================ BEST PARAMETERS (ALL MODELS) ================\n")

for model_name in df["model"].unique():

    sub = df[df["model"] == model_name].copy()

    # ---- optional: exclude perfect cases ----
    if EXCLUDE_PERFECT:
        sub = sub[sub["f1"] < 0.999]

    # ---- compute weighted score ----
    sub["score"] = (
        0.2 * sub["accuracy"] +
        0.2 * sub["precision"] +
        0.2 * sub["recall"] +
        0.3 * sub["f1"] +
        0.1 * sub["roc_auc"]
    )

    best = sub.sort_values("score", ascending=False).iloc[0]
    best_rows.append(best)

    # ---- PRINT RESULT ----
    print(f"🔹 Model: {model_name}")
    print("-" * 60)
    print(f"🏆 Best param_id : {int(best['param_id'])}")
    print(f"📊 Dataset size : {best['dataset_size']}")
    print(f"📊 Test split   : {best['test_size']}\n")

    print("📈 Metrics")
    print(
        f"  Accuracy : {best['accuracy']:.4f}\n"
        f"  Precision: {best['precision']:.4f}\n"
        f"  Recall   : {best['recall']:.4f}\n"
        f"  F1-score : {best['f1']:.4f}\n"
        f"  ROC-AUC  : {best['roc_auc']:.4f}\n"
    )

    print("⚙️ Parameters")
    param_cols = [
        c for c in sub.columns
        if c not in [
            "model","dataset_size","test_size","param_id",
            "accuracy","precision","recall","f1","roc_auc","score"
        ]
    ]

    for p in param_cols:
        if pd.notna(best[p]):
            print(f"  - {p}: {best[p]}")

    print("=" * 60 + "\n")

# ==============================
# SAVE SUMMARY CSV
# ==============================
best_df = pd.DataFrame(best_rows)

out_path = os.path.join(SAVE_DIR, "best_parameters_all_models.csv")
best_df.to_csv(out_path, index=False)

print(f"💾 Saved summary → {out_path}")
