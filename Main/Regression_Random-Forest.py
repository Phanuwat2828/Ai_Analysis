import pandas as pd
import joblib
import os
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score

def train_risk_regressor_from_csv(
    csv_path="Main/Dataset_Regression/all_features_df.csv",
    model_output_path="Main/Dataset_Regression/Model.joblib",
    plot_output_path="Main/Dataset_Regression/regression_scatter_plot.png"
):
    """
    ฝึกโมเดล RandomForestRegressor โดยโหลดจาก .csv และแปลง label เป็น risk_score
    """
    # โหลด dataset
    df = pd.read_csv(csv_path)

    # แปลง label เป็น risk score
    df['risk_score'] = df['label'].map({0: 0.1, 1: 0.9})

    # แยก features และ target
    X = df.drop(columns=["label", "risk_score"])
    y = df["risk_score"]

    # แบ่ง train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )

    # ฝึกโมเดล
    model = RandomForestRegressor(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # ทำนายและประเมิน
    y_pred = model.predict(X_test)
    mse = mean_squared_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)

    # วาดกราฟ scatter
    plt.figure(figsize=(8, 5))
    plt.scatter(y_test, y_pred, alpha=0.6)
    plt.xlabel("True Risk Score (from label)")
    plt.ylabel("Predicted Risk Score")
    plt.title("Regression: Predicted vs Actual Risk")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(plot_output_path)

    # บันทึกโมเดล
    joblib.dump(model, model_output_path)

    return {
        "model_path": model_output_path,
        "plot_path": plot_output_path,
        "mse": mse,
        "r2_score": r2
    }

train_risk_regressor_from_csv()