import joblib
import pandas as pd
import json
from Fetures import extract_features_mobsf

def predict_risk_from_json(json_path, model_path="Main/Dataset_Regression/Random_Forest/Model_001/Model.joblib"):
    # โหลดโมเดล Regression
    model = joblib.load(model_path)

    # โหลดไฟล์รายงาน MobSF
    with open(json_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    # Extract features
    features = extract_features_mobsf(report_data)
    X = pd.DataFrame([features])

    # พยากรณ์ระดับความเสี่ยง
    risk_score = model.predict(X)[0]

    return {
        "risk_score": round(float(risk_score), 4),
        "risk_level": "⚠️ HIGH" if risk_score > 0.7 else "🟡 MEDIUM" if risk_score > 0.4 else "🟢 LOW"
    }


result = predict_risk_from_json("Main/Test/malware/report_28ac5460e68eb83737ae2d3cd4f1d49f.json")
print("ค่าความเสี่ยงที่ทำนายได้:", result["risk_score"])
print("ระดับความเสี่ยง:", result["risk_level"])
