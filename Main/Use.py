import joblib
import json
import pandas as pd
from feature import extract_permission_features
class MalwareDetector:
    def __init__(self, model_dir="./Model"):
        self.xgb_model = joblib.load(f"{model_dir}/XGBoost_final.pkl")
        self.rf_model = joblib.load(f"{model_dir}/Random_Forest_final.pkl")
        
        with open(f"{model_dir}/feature_names.json", 'r', encoding='utf-8',) as f:
            self.feature_names = json.load(f)
    
    def extract_features_from_json(self, json_path):
        """Extract features from MobSF JSON file"""
        with open(json_path, 'r', encoding='utf-8',) as f:
            json_data = json.load(f)
        
        # ใช้ฟังก์ชัน extract_permission_features ที่เขียนไว้ก่อนหน้า
        features = extract_permission_features(json_data)
        return features
    
    def predict_from_file(self, json_file_path, use_ensemble=True):
        """Predict directly from JSON file"""
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

# ใช้งาน
detector = MalwareDetector()
result = detector.predict_from_file("./Data/Test/Test_fd0b81f3219af435570d2cc87e7022aa.json", use_ensemble=True)

print(result)