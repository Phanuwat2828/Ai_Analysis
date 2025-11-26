import joblib
import json
import pandas as pd
from feature import extract_features_001 as extract_features
import os
class MalwareDetector:
    def __init__(self, model_dir="./Model"):
        self.xgb_model = joblib.load(f"{model_dir}/XGBoost_final.pkl")
        self.rf_model = joblib.load(f"{model_dir}/Random_Forest_final.pkl")
        
        with open(f"{model_dir}/feature_names.json", 'r', encoding='utf-8',) as f:
            self.feature_names = json.load(f)
    
    def extract_features_from_json(self, json_path):
        with open(json_path, 'r', encoding='utf-8',) as f:
            json_data = json.load(f)
        features = extract_features(json_data)
        return features
    
    def predict_from_file(self, json_file_path, use_ensemble=True):
        features = self.extract_features_from_json(json_file_path)
        return self.predict(features, use_ensemble)
    
    # def predict(self, features_dict, use_ensemble=True):
    #     df = pd.DataFrame([features_dict])
        
    #     # Fill missing features
    #     for feature in self.feature_names:
    #         if feature not in df.columns:
    #             df[feature] = 0
        
    #     X = df[self.feature_names]
        
    #     if use_ensemble:
    #         xgb_prob = self.xgb_model.predict_proba(X)[0][1]
    #         rf_prob = self.rf_model.predict_proba(X)[0][1]
    #         avg_prob = (xgb_prob + rf_prob) / 2
    #         prediction = 'Malware' if avg_prob > 0.5 else 'Safe'
    #         return {'prediction': prediction, 'probability': avg_prob}
    #     else:
    #         pred = self.xgb_model.predict(X)[0]
    #         prob = self.xgb_model.predict_proba(X)[0]
    #         return {
    #             'prediction': 'Malware' if pred == 1 else 'Safe',
    #             'probability': prob[1]
    #         }
detector = MalwareDetector()

folders = {
    "malware": "./Data_test/malware",
    "benign": "./Data_test/benign"
}

results = []

# Counters
counters = {
    "malware": {"XGBoost": 0, "Random Forest": 0, "total": 0},
    "benign": {"XGBoost": 0, "Random Forest": 0, "total": 0}
}

for label, folder in folders.items():
    for file_name in os.listdir(folder):
        if file_name.endswith(".json"):
            file_path = os.path.join(folder, file_name)
            
            try:
                # ดึง features
                features = detector.extract_features_from_json(file_path)
                df = pd.DataFrame([features])
                
                # เติม feature ที่หายไป
                for feature in detector.feature_names:
                    if feature not in df.columns:
                        df[feature] = 0
                
                X = df[detector.feature_names]
                
                # ทำนายด้วย XGBoost
                xgb_pred = detector.xgb_model.predict(X)[0]
                xgb_result = 'Malware' if xgb_pred == 1 else 'Benign'
                
                # ทำนายด้วย Random Forest
                rf_pred = detector.rf_model.predict(X)[0]
                rf_result = 'Malware' if rf_pred == 1 else 'Benign'
                
                # เก็บผล
                results.append({
                    "file": file_name,
                    "folder": label,
                    "XGBoost": xgb_result,
                    "Random Forest": rf_result
                })
                
                # อัปเดต counters
                counters[label]["total"] += 1
                if label == "malware":
                    if xgb_result == "Malware":
                        counters[label]["XGBoost"] += 1
                    if rf_result == "Malware":
                        counters[label]["Random Forest"] += 1
                else:  # benign
                    if xgb_result == "Safe":
                        counters[label]["XGBoost"] += 1
                    if rf_result == "Safe":
                        counters[label]["Random Forest"] += 1
                
                print(f"[{label}] {file_name} -> XGB: {xgb_result}, RF: {rf_result}")
                
            except Exception as e:
                print(f"❌ Error processing {file_name}: {e}")

# สรุปผล
print("\n===== SUMMARY =====")
for label in ["malware", "benign"]:
    print(f"\n{label.upper()} ({counters[label]['total']} files):")
    print(f"  XGBoost correct: {counters[label]['XGBoost']}/{counters[label]['total']}")
    print(f"  Random Forest correct: {counters[label]['Random Forest']}/{counters[label]['total']}")
