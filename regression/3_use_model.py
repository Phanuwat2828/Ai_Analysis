import joblib
import json
import os
import pandas as pd
from features import extract_features_001 as extract_features


class MalwareDetector:

    def __init__(self, model_dir=None, threshold=0.6):
        if model_dir is None:
            model_dir = os.path.join(os.path.dirname(__file__), "..", "Model_Regression")
        self.xgb_model = joblib.load(f"{model_dir}/XGBoost_risk_regressor.pkl")
        self.rf_model  = joblib.load(f"{model_dir}/Random_Forest_risk_regressor.pkl")

        with open(f"{model_dir}/feature_names.json", 'r', encoding='utf-8') as f:
            self.feature_names = json.load(f)

        self.threshold = threshold

    # -------------------------------------------------
    def extract_features_from_json(self, json_path):
        with open(json_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)

        features = extract_features(json_data)
        return features

    # -------------------------------------------------
    def _prepare_dataframe(self, features_dict):
        """Ensure feature alignment with training"""
        row = {f: features_dict.get(f, 0) for f in self.feature_names}
        return pd.DataFrame([row])

    # -------------------------------------------------
    def predict(self, features_dict, use_ensemble=True):
        X = self._prepare_dataframe(features_dict)

        # 🔹 Regression prediction (risk score)
        xgb_score = float(self.xgb_model.predict(X)[0])
        rf_score  = float(self.rf_model.predict(X)[0])

        if use_ensemble:
            final_score = (xgb_score + rf_score) / 2
            model_name = "Ensemble (XGB + RF)"
        else:
            final_score = xgb_score
            model_name = "XGBoost"

        # label = "Malware" if final_score >= self.threshold else "Benign"

        print("\n=== 🔍 Malware Risk Assessment ===")
        print(f"XGBoost Risk Score       : {xgb_score:.4f}")
        print(f"Random Forest Risk Score : {rf_score:.4f}")
        print(f"---------------------------------")
        print(f"Final Risk Score ({model_name}) : {final_score:.4f}")

        return {
            "xgb_score": xgb_score,
            "rf_score": rf_score,
            "final_score": final_score,
        }

detector = MalwareDetector(threshold=0.6)

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
json_file_path_benign = os.path.join(BASE_DIR, "Data_test", "benign", "0543752128630452470A69504F889EC22CDBA93CAF84C2428514E121DE5F2DC4.json")
json_file_path_malware = os.path.join(BASE_DIR, "Data_test", "malware", "00A03FB63CAF7B03568586150E3F2F9164EB0AE8CAC9F921DE789AA687DF4E24.json")

def use_model(json_file_path):
    try:
        features = detector.extract_features_from_json(json_file_path)
        result = detector.predict(features)

    except Exception as e:
        print(f"❌ Error processing {json_file_path}: {e}")

use_model(json_file_path_benign)
