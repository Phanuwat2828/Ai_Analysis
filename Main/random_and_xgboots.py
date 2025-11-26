import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
import warnings
import joblib
import os
import json
from datetime import datetime
warnings.filterwarnings('ignore')

class MalwareModelComparison:
    def __init__(self, data_path):
        """Initialize with dataset path"""
        self.data_path = data_path
        self.data = None
        self.X = None
        self.y = None
        self.feature_names = None
        self.results = {}
        self.final_models = {}
        
    def load_and_prepare_data(self):
        """Load and prepare the dataset"""
        print("Loading dataset...")
        self.data = pd.read_csv(self.data_path)
        print(f"Dataset shape: {self.data.shape}")
        
        if "total_permissions" not in self.data.columns:
            self.data["total_permissions"] = (
                self.data.get("dangerous_permissions", 0) +
                self.data.get("normal_permissions", 0) +
                self.data.get("unknown_permissions", 0)
            )
        self.data = self.data[self.data['total_permissions'] > 0]
        print(f"Cleaned dataset shape: {self.data.shape}")

        label_counts = self.data['label'].value_counts()
        print(f"Class distribution: Safe(0): {label_counts.get(0,0)}, Malware(1): {label_counts.get(1,0)}")
        if len(self.data) > 0:
            print(f"Malware ratio: {label_counts.get(1,0)/len(self.data):.2%}")
        return self.data
    
    def select_features(self):
        """Select relevant features for modeling"""
        exclude_cols = ['label', 'family', 'filename']
        feature_cols = [
            col for col in self.data.columns
            if col not in exclude_cols and self.data[col].dtype in ['int64', 'float64']
        ]
        self.X = self.data[feature_cols]
        self.y = self.data['label']
        self.feature_names = feature_cols
        print(f"Selected {len(feature_cols)} features for modeling")
        return self.X, self.y
    
    def train_and_evaluate_models(self, cv_folds=5):
        """Train and evaluate models using cross-validation"""
        models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                scale_pos_weight=len(self.y[self.y==0])/len(self.y[self.y==1])
            )
        }

        scoring = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        results = {}
        
        for model_name, model in models.items():
            print(f"\nTraining {model_name}...")
            cv_results = cross_validate(
                model, self.X, self.y,
                cv=cv, scoring=scoring, return_train_score=True
            )
            results[model_name] = {}
            for metric in scoring:
                results[model_name][f'{metric}_test'] = {
                    'mean': np.mean(cv_results[f'test_{metric}']),
                    'std': np.std(cv_results[f'test_{metric}']),
                    'scores': cv_results[f'test_{metric}']
                }
                results[model_name][f'{metric}_train'] = {
                    'mean': np.mean(cv_results[f'train_{metric}']),
                    'std': np.std(cv_results[f'train_{metric}']),
                    'scores': cv_results[f'train_{metric}']
                }
                print(f"{metric.upper():8} | Test: {results[model_name][f'{metric}_test']['mean']:.3f} ± {results[model_name][f'{metric}_test']['std']:.3f}")
        self.results = results
        return results
    
    def print_final_recommendation(self):
        """Print final model recommendation"""
        if not self.results:
            print("No results available.")
            return None, None

        models = list(self.results.keys())
        overall_scores = {}
        weights = {'accuracy':0.2, 'precision':0.2, 'recall':0.2, 'f1':0.3, 'roc_auc':0.1}

        for model in models:
            score = 0
            for metric, w in weights.items():
                score += self.results[model][f'{metric}_test']['mean'] * w
            overall_scores[model] = score
        
        best_model = max(overall_scores, key=overall_scores.get)
        best_score = overall_scores[best_model]
        print(f"\nBest Model: {best_model} | Overall Score: {best_score:.3f}")
        
        print("\nDetailed metrics per model:")
        for model in models:
            print(f"\n{model}:")
            for metric in ['accuracy','precision','recall','f1','roc_auc']:
                print(f"  {metric.upper():8}: {self.results[model][f'{metric}_test']['mean']:.3f} ± {self.results[model][f'{metric}_test']['std']:.3f}")
            print(f"  Weighted Overall Score: {overall_scores[model]:.3f}")
        
        return best_model, best_score
    
    def train_final_models(self):
        """Train both models on full dataset"""
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced'
        )
        xgb_model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            scale_pos_weight=len(self.y[self.y==0])/len(self.y[self.y==1])
        )
        rf_model.fit(self.X, self.y)
        xgb_model.fit(self.X, self.y)
        self.final_models = {"Random Forest": rf_model, "XGBoost": xgb_model}
        print("Final models trained.")
        return self.final_models
    
    def save_models(self, output_dir="./Model"):
        """Save models and feature names"""
        os.makedirs(output_dir, exist_ok=True)
        for name, model in self.final_models.items():
            path = f"{output_dir}/{name.replace(' ','_')}_final.pkl"
            joblib.dump(model, path)
            print(f"Saved {name} model to {path}")
        feature_file = f"{output_dir}/feature_names.json"
        with open(feature_file, 'w') as f:
            json.dump(self.feature_names, f)
        print(f"Saved feature names to {feature_file}")

if __name__ == "__main__":
    CSV_FILE = "./Dataset/malware_dataset.csv" 
    try:
        comparison = MalwareModelComparison(CSV_FILE)
        comparison.load_and_prepare_data()
        comparison.select_features()
        comparison.train_and_evaluate_models(cv_folds=5) # <-- Cross-validation testing
        comparison.print_final_recommendation() # <-- Final model recommendation
        comparison.train_final_models()
        comparison.save_models("./Model")
        print("\n🎉 Malware analysis completed successfully!")
    except FileNotFoundError:
        print(f"❌ CSV file not found: {CSV_FILE}")
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
