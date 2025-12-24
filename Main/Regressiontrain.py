import pandas as pd
import numpy as np
from sklearn.model_selection import KFold, cross_validate, train_test_split
from sklearn.ensemble import RandomForestRegressor
import xgboost as xgb
import warnings
import joblib
import os
import json
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

warnings.filterwarnings('ignore')

class MalwareRiskRegressionComparison:

    def __init__(self, data_path):
        self.data_path = data_path
        self.data = None
        self.X = None
        self.y = None
        self.feature_names = None
        self.results = {}
        self.final_models = {}

    # ---------------------------------------------------------
    def load_and_prepare_data(self):
        print("\n=== 📌 Loading Dataset ===")
        self.data = pd.read_csv(self.data_path)
        print(f"Dataset shape: {self.data.shape}")
        print(self.data['label'].describe())
        return self.data

    # ---------------------------------------------------------
    def select_features(self):
        print("\n=== 📌 Selecting Features ===")

        exclude_cols = ['label', 'family', 'filename']
        self.feature_names = [
            c for c in self.data.columns
            if c not in exclude_cols and self.data[c].dtype in ['int64','float64']
        ]

        self.X = self.data[self.feature_names]
        self.y = self.data['label']

        self.train_x, self.test_x, self.train_y, self.test_y = train_test_split(
            self.X, self.y, test_size=0.2, random_state=42
        )

        print(f"Selected {len(self.feature_names)} features")
        return self.X, self.y

    # ---------------------------------------------------------
    def train_and_evaluate_models(self, cv_folds=5):
        print("\n=== 📌 Cross Validation (Regression) ===")

        models = {
            "Random Forest": RandomForestRegressor(
                n_estimators=300, max_depth=12,
                min_samples_leaf=2, random_state=42
            ),
            "XGBoost": xgb.XGBRegressor(
                n_estimators=300, max_depth=6,
                learning_rate=0.1, subsample=0.8,
                colsample_bytree=0.8, random_state=42
            )
        }

        scoring = {
            'MAE': 'neg_mean_absolute_error',
            'MSE': 'neg_mean_squared_error',
            'R2': 'r2'
        }

        cv = KFold(n_splits=cv_folds, shuffle=True, random_state=42)

        for name, model in models.items():
            print(f"\n--- {name} ---")

            cv_result = cross_validate(
                model, self.train_x, self.train_y,
                cv=cv, scoring=scoring
            )

            self.results[name] = {
                "MAE": -cv_result['test_MAE'].mean(),
                "MSE": -cv_result['test_MSE'].mean(),
                "R2": cv_result['test_R2'].mean()
            }

            for m, v in self.results[name].items():
                print(f"{m:5}: {v:.4f}")

        return self.results

    # ---------------------------------------------------------
    def train_final_models(self):
        print("\n=== 📌 Training Final Models ===")

        models = {
            "Random Forest": RandomForestRegressor(
                n_estimators=300, max_depth=12,
                min_samples_leaf=2, random_state=42
            ),
            "XGBoost": xgb.XGBRegressor(
                n_estimators=300, max_depth=6,
                learning_rate=0.1, subsample=0.8,
                colsample_bytree=0.8, random_state=42
            )
        }

        for name, model in models.items():
            model.fit(self.train_x, self.train_y)
            pred_tr = model.predict(self.train_x)
            pred_ts = model.predict(self.test_x)
            print(f"\n🏆 {name}")
            print(f"Train MAE: {mean_absolute_error(self.train_y, pred_tr):.4f}")
            print(f"Test  MAE: {mean_absolute_error(self.test_y, pred_ts):.4f}")
            print(f"Test  R² : {r2_score(self.test_y, pred_ts):.4f}")
            self.final_models[name] = model

        return self.final_models

    # ---------------------------------------------------------
    def save_models(self, output_dir="./Model_Regression"):
        os.makedirs(output_dir, exist_ok=True)

        for name, model in self.final_models.items():
            path = f"{output_dir}/{name.replace(' ','_')}_risk_regressor.pkl"
            joblib.dump(model, path)
            print(f"Saved {name} → {path}")

        with open(f"{output_dir}/feature_names.json","w") as f:
            json.dump(self.feature_names, f)

# ---------------------------------------------------------
if __name__ == "__main__":

    CSV_FILE = "./Dataset/malware_dataset_regression.csv"

    runner = MalwareRiskRegressionComparison(CSV_FILE)
    runner.load_and_prepare_data()
    runner.select_features()
    runner.train_and_evaluate_models()
    runner.train_final_models()
    runner.save_models()

    print("\n🎉 Regression Training Completed")
