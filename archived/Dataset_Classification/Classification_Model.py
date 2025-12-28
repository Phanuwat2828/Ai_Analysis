import joblib
import json
import pandas as pd
from Fetures import extract_features_mobsf  # ใช้ฟังก์ชัน feature extraction ของคุณ

def predict_from_json(json_path, model_path="Main/Dataset_Classification/Random_Forest/Model_004/Model.joblib"):
    model = joblib.load(model_path)

    with open(json_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)
    features = extract_features_mobsf(report_data)
    X = pd.DataFrame([features])
    
    prediction = model.predict(X)[0]
    proba = model.predict_proba(X)[0]  
    
    return {
        "prediction": int(prediction), 
        "confidence": round(float(max(proba)), 4),
        "prob_safe": round(float(proba[0]), 4),
        "prob_risky": round(float(proba[1]), 4)
    }

result = predict_from_json("Main/Test/malware/report_28ac5460e68eb83737ae2d3cd4f1d49f.json")
print("✅ ผลการทำนาย:", "มัลแวร์" if result["prediction"] == 1 else "ปลอดภัย")
print("ความมั่นใจ:", result["confidence"])

