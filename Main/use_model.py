

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
    
        # malware and benign
        xgb_prob_malware = self.xgb_model.predict_proba(X)[0][1]  # probability เป็น Malware
        rf_prob_malware = self.rf_model.predict_proba(X)[0][1]
        xgb_prob_benign = self.xgb_model.predict_proba(X)[0][0]  # probability เป็น Benign
        rf_prob_benign = self.rf_model.predict_proba(X)[0][0]

        if xgb_prob_malware > xgb_prob_benign:
            print("Malware XGBoost : {:.3f}%".format(self.xgb_model.predict_proba(X)[0][1]*100))
        else:
            print("Benign XGBoost : {:.3f}%".format(self.xgb_model.predict_proba(X)[0][0]*100))

        if rf_prob_malware > rf_prob_benign:
            print("Malware Random Forest : {:.3f}%".format(self.rf_model.predict_proba(X)[0][1]*100))
        else:
            print("Benign Random Forest : {:.3f}%".format(self.rf_model.predict_proba(X)[0][0]*100))

       

# -------------------------
detector = MalwareDetector()

json_file_path_benign = "./Data_test/benign/0543752128630452470A69504F889EC22CDBA93CAF84C2428514E121DE5F2DC4.json"
json_file_path_malware = "./Data_test/malware/00A03FB63CAF7B03568586150E3F2F9164EB0AE8CAC9F921DE789AA687DF4E24.json"


def use_model(json_file_path):
    try:
        features = detector.extract_features_from_json(json_file_path)
        result = detector.predict(features)

    except Exception as e:
        print(f"❌ Error processing {json_file_path}: {e}")

use_model(json_file_path_malware)

