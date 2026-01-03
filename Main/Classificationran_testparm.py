import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
import warnings
import joblib
import os
import json
from datetime import datetime
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score
)
from sklearn.model_selection import ParameterGrid
from tqdm import tqdm

from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import GridSearchCV
import matplotlib.pyplot as plt

warnings.filterwarnings('ignore')

RF_PARAM_GRID = {
    "n_estimators": [100, 300, 500],
    "max_depth": [None, 10, 20],
    "min_samples_split": [2, 5],
    "min_samples_leaf": [1, 2],
    "max_features": ["sqrt"]
}

XGB_PARAM_GRID = {
    "n_estimators": [100, 300, 500],
    "max_depth": [4, 6, 8],
    "learning_rate": [0.05, 0.1],
    "subsample": [0.8, 1.0],
    "colsample_bytree": [0.8, 1.0]
}


class MalwareModelComparison:

    def __init__(self, data_path):
        self.data_path = data_path
        self.data = None
        self.X = None
        self.y = None
        self.feature_names = None
        self.results = {}
        self.final_models = {}
        self.train_x = None
        self.train_y = None
        self.test_x = None
        self.test_y = None

    # ---------------------------------------------------------
    def load_and_prepare_data(self):
        print("\n=== 📌 Loading Dataset ===")
        self.data = pd.read_csv(self.data_path)
        print(f"Dataset shape: {self.data.shape}")

        label_counts = self.data['label'].value_counts()
        total = len(self.data)

        print(f"Safe (0): {label_counts.get(0,0)}")
        print(f"Malware (1): {label_counts.get(1,0)}")
        print(f"Malware Ratio: {label_counts.get(1,0) / total:.2%}")

        return self.data
    
    # ---------------------------------------------------------
    def select_features(self):
        print("\n=== 📌 Selecting Features ===")

        exclude_cols = ['label', 'family', 'filename']
        feature_cols = [
            col for col in self.data.columns
            if col not in exclude_cols and self.data[col].dtype in ['int64', 'float64']
        ]
        self.X = self.data[feature_cols]
        self.y = self.data['label']
        self.train_x, self.test_x, self.train_y, self.test_y = train_test_split(
            self.X, self.y, test_size=0.2, random_state=42, stratify=self.y
        )
        self.feature_names = feature_cols
        print(f"Selected {len(feature_cols)} numerical features")
        return self.X, self.y
    
    # ---------------------------------------------------------
    def train_and_evaluate_models(self, cv_folds=5):
        print("\n=== 📌 Cross Validation Training ===")
        models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=12,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42
                
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42
            )
        }

        scoring = ['accuracy','precision','recall','f1','roc_auc']
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        results = {}

        for model_name, model in models.items():
            print(f"\n----- Training {model_name} -----")

            # ⭐ ไม่เก็บ train score
            cv_results = cross_validate(
                model, self.train_x, self.train_y,
                cv=cv,
                scoring=scoring,
                return_train_score=False
            )

            results[model_name] = {}

            print(f"{'METRIC':10} | {'TEST (mean±std)':25} |")
            print("-" * 75)

            for metric in scoring:

                test_mean = np.mean(cv_results[f'test_{metric}'])
                test_std  = np.std(cv_results[f'test_{metric}'])

                results[model_name][f"{metric}_test"] = {
                    'mean': test_mean, 'std': test_std
                }

                print(
                    f"{metric.upper():10} | "
                    f"{test_mean:.3f} ± {test_std:.3f} |"
                )

        self.results = results
        return results

    
    # ---------------------------------------------------------
    def print_final_recommendation(self):
        """Pick best model based only on TRAIN CV score"""
        print("\n=== 📌 Model Ranking (Based on CV Train Score) ===")

        if not self.results:
            print("No evaluation results found!")
            return None, None

        weights = {
            'accuracy':0.2, 'precision':0.2, 'recall':0.2, 'f1':0.3, 'roc_auc':0.1
        }

        overall_scores = {}

        for model in self.results.keys():
            score = 0
            for metric, w in weights.items():
                score += self.results[model][f"{metric}_test"]['mean'] * w
            overall_scores[model] = score

        print("\nModel Train CV Weighted Scores:")
        for model, score in overall_scores.items():
            print(f"- {model:15}: {score:.4f}")

        best_model = max(overall_scores, key=overall_scores.get)
        best_score = overall_scores[best_model]

        print(f"\n🏆 Best Model (CV-based): **{best_model}** (Score: {best_score:.4f})")

        return best_model, best_score

    # ---------------------------------------------------------
    def train_final_models(self):
        print("\n=== 📌 Training Final Models ===")

        rf = RandomForestClassifier(
            n_estimators=100, max_depth=12,
            min_samples_split=5, min_samples_leaf=2,
            random_state=42,oob_score=True,
                warm_start=True,
                max_features='sqrt'
        ).fit(self.train_x, self.train_y)

        xgb_ = xgb.XGBClassifier(
            n_estimators=100, max_depth=6,
            learning_rate=0.1, subsample=0.8,
            colsample_bytree=0.8, random_state=42
        ).fit(self.train_x, self.train_y)

        models = {"Random Forest": rf, "XGBoost": xgb_}

        metrics_fn = {
            "Accuracy": accuracy_score,
            "Precision": precision_score,
            "Recall": recall_score,
            "F1": f1_score,
        }

        def evaluate(model):
            ytr, yts = model.predict(self.train_x), model.predict(self.test_x)

            rows = []
            for name, fn in metrics_fn.items():
                tr = fn(self.train_y, ytr)
                ts = fn(self.test_y, yts)
                rows.append([name, tr, ts, (tr - ts) * 100])

            # ROC AUC
            try:
                ptr = model.predict_proba(self.train_x)[:, 1]
                pts = model.predict_proba(self.test_x)[:, 1]
                tr = roc_auc_score(self.train_y, ptr)
                ts = roc_auc_score(self.test_y, pts)
                rows.append(["ROC_AUC", tr, ts, (tr - ts) * 100])
            except:
                rows.append(["ROC_AUC", "-", "-", "-"])

            return pd.DataFrame(rows, columns=["Metric", "Train", "Test", "GAP %"])

        # ---- Show Results ----
        for name, model in models.items():
            print(f"\n=== 🏆 Final Evaluation: {name} ===")
            print(evaluate(model))

        self.final_models = models
        return models

    # ---------------------------------------------------------
    def save_models(self, output_dir="./Model"):
        print("\n=== 📌 Saving Models ===")

        os.makedirs(output_dir, exist_ok=True)

        for name, model in self.final_models.items():
            path = f"{output_dir}/{name.replace(' ','_')}_final.pkl"
            joblib.dump(model, path)
            print(f"Saved {name} → {path}")

        with open(f"{output_dir}/feature_names.json","w") as f:
            json.dump(self.feature_names, f)

        print("Saved feature list.")

    def run_full_hyperparameter_experiments_all_models(self, save_dir="./results"):
        print("\n=== 🔬 Full Hyperparameter Experiments: RF + XGBoost ===")

        os.makedirs(save_dir, exist_ok=True)

        dataset_sizes = [500, 1000, 2000, "full"]
        test_sizes = [0.2, 0.3]

        experiments = {
            "RandomForest": (
                RandomForestClassifier(random_state=42, n_jobs=-1),
                list(ParameterGrid(RF_PARAM_GRID))
            ),
            "XGBoost": (
                xgb.XGBClassifier(
                    eval_metric="logloss",
                    random_state=42
                ),
                list(ParameterGrid(XGB_PARAM_GRID))
            )
        }

        total_steps = sum(
            len(dataset_sizes) * len(test_sizes) * len(pgrid)
            for _, pgrid in experiments.values()
        )

        all_results = []

        with tqdm(total=total_steps, desc="🧪 Experiments", ncols=110) as pbar:

            for size in dataset_sizes:
                if size == "full":
                    X_sub, y_sub = self.X, self.y
                else:
                    X_sub, _, y_sub, _ = train_test_split(
                        self.X, self.y,
                        train_size=size,
                        stratify=self.y,
                        random_state=42
                    )

                for test_size in test_sizes:
                    X_train, X_test, y_train, y_test = train_test_split(
                        X_sub, y_sub,
                        test_size=test_size,
                        stratify=y_sub,
                        random_state=42
                    )

                    for model_name, (base_model, param_list) in experiments.items():

                        for pid, params in enumerate(param_list):
                            model = base_model.__class__(**base_model.get_params())
                            model.set_params(**params)

                            model.fit(X_train, y_train)

                            y_pred = model.predict(X_test)

                            if hasattr(model, "predict_proba"):
                                y_prob = model.predict_proba(X_test)[:, 1]
                                roc = roc_auc_score(y_test, y_prob)
                            else:
                                roc = None

                            all_results.append({
                                "model": model_name,
                                "dataset_size": size,
                                "test_size": test_size,
                                "param_id": pid,
                                **params,
                                "accuracy": accuracy_score(y_test, y_pred),
                                "precision": precision_score(y_test, y_pred),
                                "recall": recall_score(y_test, y_pred),
                                "f1": f1_score(y_test, y_pred),
                                "roc_auc": roc
                            })

                            pbar.set_postfix({
                                "model": model_name,
                                "size": size,
                                "test": test_size,
                                "param": pid
                            })
                            pbar.update(1)

        df = pd.DataFrame(all_results)

        # 🔽 Save CSV (รวมทุก model)
        full_path = os.path.join(save_dir, "rf_xgb_hyperparameter_results.csv")
        df.to_csv(full_path, index=False)

        # 🔽 แยก CSV ต่อ model
        for m in df["model"].unique():
            path = os.path.join(save_dir, f"{m.lower()}_results.csv")
            df[df["model"] == m].to_csv(path, index=False)

        print(f"\n📄 Saved results → {full_path}")

        self.hyper_results = df
        return df


    def plot_metrics_vs_params_subplot(self):
        metrics = ["accuracy", "precision", "recall", "f1", "roc_auc"]
        models = self.hyper_results["model"].unique()

        fig, axes = plt.subplots(1, len(models), figsize=(14,5), sharey=True)

        for ax, model_name in zip(axes, models):
            subset = self.hyper_results[
                self.hyper_results["model"] == model_name
            ]

            for m in metrics:
                mean_scores = subset.groupby("param_id")[m].mean()
                ax.plot(mean_scores.index, mean_scores.values, label=m)

            ax.set_title(model_name)
            ax.set_xlabel("Parameter Set ID")
            ax.grid(True)

        axes[0].set_ylabel("Score")
        axes[0].legend(loc="lower right")

        plt.suptitle("Performance Metrics across Hyperparameter Configurations")
        plt.show()


    def plot_f1_vs_roc_auc(self):
        plt.figure()
        plt.scatter(
            self.hyper_results["roc_auc"],
            self.hyper_results["f1"],
            alpha=0.7
        )
        plt.xlabel("ROC-AUC")
        plt.ylabel("F1-score")
        plt.title("F1 vs ROC-AUC Trade-off across Hyperparameters")
        plt.grid(True)
        plt.show()
    def plot_metrics_vs_dataset_size(self):
        metrics = ["accuracy", "precision", "recall", "f1", "roc_auc"]

        for m in metrics:
            plt.figure()
            mean_scores = self.hyper_results.groupby("dataset_size")[m].mean()
            std_scores  = self.hyper_results.groupby("dataset_size")[m].std()

            plt.errorbar(
                mean_scores.index,
                mean_scores.values,
                yerr=std_scores.values,
                marker='o',
                capsize=5
            )

            plt.xlabel("Dataset Size")
            plt.ylabel(m)
            plt.title(f"{m.upper()} vs Dataset Size")
            plt.grid(True)
            plt.show()
    def show_best_parameters(self):
        best = (
            self.hyper_results
            .assign(score=lambda df:
                0.2*df["accuracy"] +
                0.2*df["precision"] +
                0.2*df["recall"] +
                0.3*df["f1"] +
                0.1*df["roc_auc"]
            )
            .sort_values("score", ascending=False)
            .iloc[0]
        )

        print("\n🏆 Best Hyperparameter Configuration")
        print(best)

# ---------------------------------------------------------
if __name__ == "__main__":

    CSV_FILE = "./Dataset/malware_dataset_4000.csv"

    try:
        
        comparison = MalwareModelComparison(CSV_FILE)
        comparison.load_and_prepare_data()
        comparison.select_features()
        comparison.run_full_hyperparameter_experiments_all_models()
        comparison.plot_metrics_vs_params_subplot()


        

        print("\n🎉 Completed Successfully!")

    except FileNotFoundError:
        print(f"❌ CSV not found: {CSV_FILE}")

    except Exception as e:
        print(f"❌ Error: {e}")
