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
    
    def predict(self, features_dict, use_ensemble=True):
        df = pd.DataFrame([features_dict])
        
        # Fill missing features
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0
        
        X = df[self.feature_names]
        
        if use_ensemble:
            xgb_prob = self.xgb_model.predict_proba(X)[0][1]
            rf_prob = self.rf_model.predict_proba(X)[0][1]
            avg_prob = (xgb_prob + rf_prob) / 2
            prediction = 'Malware' if avg_prob > 0.5 else 'Safe'
            return {'prediction': prediction, 'probability': avg_prob}
        else:
            pred = self.xgb_model.predict(X)[0]
            prob = self.xgb_model.predict_proba(X)[0]
            return {
                'prediction': 'Malware' if pred == 1 else 'Safe',
                'probability': prob[1]
            }
detector = MalwareDetector()

# โฟลเดอร์ที่ต้องการทดสอบ
folders = {
    "malware": "./Data_test/malware",
    "benign": "./Data_test/benign"
}

results = []

for label, folder in folders.items():
    for file_name in os.listdir(folder):
        if file_name.endswith(".json"):
            file_path = os.path.join(folder, file_name)
            
            try:
                result = detector.predict_from_file(file_path, use_ensemble=True)
                results.append({
                    "file": file_name,
                    "folder": label,
                    "prediction": result["prediction"],
                    "probability": result["probability"]
                })
                
                print(f"[{label}] {file_name} -> {result}")
            
            except Exception as e:
                print(f"❌ Error processing {file_name}: {e}")

# สรุปผล cuối
print("\n===== SUMMARY =====")
malware_correct = 0
benign_correct = 0

for r in results:
    if r["folder"] == "malware" and r["prediction"] == "Malware":
        malware_correct += 1
    if r["folder"] == "benign" and r["prediction"] == "Safe":
        benign_correct += 1

print(f"Malware Correct: {malware_correct}/{len([x for x in results if x['folder']=='malware'])}")
print(f"Benign Correct: {benign_correct}/{len([x for x in results if x['folder']=='benign'])}")