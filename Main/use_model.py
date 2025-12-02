import joblib
import json
import pandas as pd
from feature import extract_features_001 as extract_features
import os

class MalwareDetector:
    
    def __init__(self, model_dir="./Model"):
        self.xgb_model = joblib.load(f"{model_dir}/XGBoost_final.pkl")
        self.rf_model = joblib.load(f"{model_dir}/Random_Forest_final.pkl")
        
        with open(f"{model_dir}/feature_names.json", 'r', encoding='utf-8') as f:
            self.feature_names = json.load(f)
    
    def extract_features_from_json(self, json_path):
        with open(json_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        features = extract_features(json_data)
        return features
    
    def predict(self, features_dict, use_ensemble=True):
        df = pd.DataFrame([features_dict])
        
        # เติม feature ที่หายไป
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0
        
        X = df[self.feature_names]
        
        # คำนวณ probability
        xgb_prob = self.xgb_model.predict_proba(X)[0][1]
        rf_prob = self.rf_model.predict_proba(X)[0][1]
        avg_prob = (xgb_prob + rf_prob) / 2
        
        prediction = 'Malware' if avg_prob > 0.5 else 'Benign'
        
        return {
            "prediction": prediction,
            "XGBoost_prob": xgb_prob,
            "RandomForest_prob": rf_prob,
            "ensemble_prob": avg_prob
        }

# -------------------------
# ตัวอย่างการทดสอบทีละไฟล์
detector = MalwareDetector()

# กำหนด path ของไฟล์ JSON ที่ต้องการทดสอบ
json_file_path = "./Data_test/x.json"  # <-- เปลี่ยน path ให้ตรงไฟล์ของคุณ

try:
    features = detector.extract_features_from_json(json_file_path)
    result = detector.predict(features)
    print(f"File: {os.path.basename(json_file_path)}")
    print(f"Prediction: {result['prediction']}")
    print(f"XGBoost probability: {result['XGBoost_prob']:.4f}")
    print(f"Random Forest probability: {result['RandomForest_prob']:.4f}")
    print(f"Ensemble probability: {result['ensemble_prob']:.4f}")
except Exception as e:
    print(f"❌ Error processing {json_file_path}: {e}")
