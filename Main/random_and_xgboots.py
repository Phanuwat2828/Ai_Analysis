import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import StratifiedKFold, cross_val_score, cross_validate
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import xgboost as xgb
import warnings
import joblib
import os
import json
from datetime import datetime
warnings.filterwarnings('ignore')

# Set style for better plots
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

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
        print(f"Columns: {len(self.data.columns)}")
        
        # ✅ สร้าง total_permissions เอง
        if "total_permissions" not in self.data.columns:
            self.data["total_permissions"] = (
                self.data.get("dangerous_permissions", 0) +
                self.data.get("normal_permissions", 0) +
                self.data.get("unknown_permissions", 0)
            )
        
        # Missing values check
        print(f"Missing values: {self.data.isnull().sum().sum()}")
        print(f"Zero permission samples: {sum(self.data['total_permissions'] == 0)}")
        
        # Remove samples with 0 permissions (data quality issue)
        self.data = self.data[self.data['total_permissions'] > 0]
        print(f"Cleaned dataset shape: {self.data.shape}")
        
        # Class distribution
        label_counts = self.data['label'].value_counts()
        print(f"\nClass distribution:")
        print(f"Safe (0): {label_counts.get(0, 0)} samples")
        print(f"Malware (1): {label_counts.get(1, 0)} samples")
        if len(self.data) > 0:
            print(f"Imbalance ratio: {label_counts.get(1, 0) / len(self.data):.2%} malware")
        
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
        
        print(f"\nSelected {len(feature_cols)} features for modeling")
        print("Top 10 features:")
        for i, col in enumerate(feature_cols[:10]):
            print(f"  {i+1}. {col}")
        
        print(f"Features shape: {self.X.shape}")
        print(f"Target shape: {self.y.shape}")
        
        return self.X, self.y

    
    def train_and_evaluate_models(self, cv_folds=5):
        """Train and evaluate both models using cross-validation"""
        print(f"\n{'='*50}")
        print("TRAINING AND EVALUATION")
        print(f"{'='*50}")


        # Define models
        models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'  # Handle class imbalance
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                scale_pos_weight=len(self.y[self.y==0])/len(self.y[self.y==1])  # Handle imbalance
            )
        }
        
        # Define scoring metrics
        scoring = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
        
        # Use StratifiedKFold to maintain class distribution
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        
        results = {}
        
        for model_name, model in models.items():
            print(f"\nTraining {model_name}...")
            # Perform cross-validation
            cv_results = cross_validate(
                model, self.X, self.y, 
                cv=cv, 
                scoring=scoring,
                return_train_score=True
            )
            
            # Store results
            results[model_name] = {}
            for metric in scoring:
                test_scores = cv_results[f'test_{metric}']
                train_scores = cv_results[f'train_{metric}']
                
                results[model_name][f'{metric}_test'] = {
                    'mean': np.mean(test_scores),
                    'std': np.std(test_scores),
                    'scores': test_scores
                }
                results[model_name][f'{metric}_train'] = {
                    'mean': np.mean(train_scores),
                    'std': np.std(train_scores),
                    'scores': train_scores
                }
            
            # Print results
            print(f"\n{model_name} Results (5-Fold CV):")
            print("-" * 40)
            for metric in scoring:
                test_mean = results[model_name][f'{metric}_test']['mean']
                test_std = results[model_name][f'{metric}_test']['std']
                train_mean = results[model_name][f'{metric}_train']['mean']
                
                print(f"{metric.upper():12} | Test: {test_mean:.3f} (±{test_std:.3f}) | Train: {train_mean:.3f}")
        
        self.results = results
        return results
    
    def plot_comparison(self):
        """Create comprehensive comparison plots"""
        if not self.results:
            print("No results to plot. Run train_and_evaluate_models first.")
            return
        
        # Create figure with subplots
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('Malware Detection Model Comparison\n(Random Forest vs XGBoost)', 
                     fontsize=16, fontweight='bold')
        
        metrics = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
        models = list(self.results.keys())
        
        # 1. Bar plot comparing test performance
        ax1 = axes[0, 0]
        x = np.arange(len(metrics))
        width = 0.35
        
        rf_scores = [self.results['Random Forest'][f'{m}_test']['mean'] for m in metrics]
        xgb_scores = [self.results['XGBoost'][f'{m}_test']['mean'] for m in metrics]
        rf_stds = [self.results['Random Forest'][f'{m}_test']['std'] for m in metrics]
        xgb_stds = [self.results['XGBoost'][f'{m}_test']['std'] for m in metrics]
        
        bars1 = ax1.bar(x - width/2, rf_scores, width, label='Random Forest', 
                       yerr=rf_stds, capsize=5, alpha=0.8)
        bars2 = ax1.bar(x + width/2, xgb_scores, width, label='XGBoost', 
                       yerr=xgb_stds, capsize=5, alpha=0.8)
        
        ax1.set_xlabel('Metrics')
        ax1.set_ylabel('Score')
        ax1.set_title('Test Performance Comparison')
        ax1.set_xticks(x)
        ax1.set_xticklabels([m.upper() for m in metrics], rotation=45)
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        ax1.set_ylim(0, 1.05)
        
        # Add value labels on bars
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax1.annotate(f'{height:.3f}',
                           xy=(bar.get_x() + bar.get_width() / 2, height),
                           xytext=(0, 3), textcoords="offset points",
                           ha='center', va='bottom', fontsize=8)
        
        # 2. Box plot for F1 scores distribution
        ax2 = axes[0, 1]
        f1_data = []
        labels = []
        for model in models:
            f1_data.append(self.results[model]['f1_test']['scores'])
            labels.append(model)
        
        box_plot = ax2.boxplot(f1_data, labels=labels, patch_artist=True)
        ax2.set_title('F1 Score Distribution (5-Fold CV)')
        ax2.set_ylabel('F1 Score')
        ax2.grid(True, alpha=0.3)
        
        # Color the boxes
        colors = ['lightblue', 'lightgreen']
        for patch, color in zip(box_plot['boxes'], colors):
            patch.set_facecolor(color)
        
        # 3. Accuracy vs F1 scatter plot
        ax3 = axes[0, 2]
        for i, model in enumerate(models):
            acc_scores = self.results[model]['accuracy_test']['scores']
            f1_scores = self.results[model]['f1_test']['scores']
            ax3.scatter(acc_scores, f1_scores, label=model, s=100, alpha=0.7)
        
        ax3.set_xlabel('Accuracy')
        ax3.set_ylabel('F1 Score')
        ax3.set_title('Accuracy vs F1 Score')
        ax3.legend()
        ax3.grid(True, alpha=0.3)
        
        # Add diagonal line for reference
        ax3.plot([0, 1], [0, 1], 'k--', alpha=0.5)
        
        # 4. Training vs Test performance
        ax4 = axes[1, 0]
        for i, model in enumerate(models):
            train_f1 = self.results[model]['f1_train']['mean']
            test_f1 = self.results[model]['f1_test']['mean']
            train_acc = self.results[model]['accuracy_train']['mean']
            test_acc = self.results[model]['accuracy_test']['mean']
            
            ax4.scatter(train_f1, test_f1, label=f'{model} (F1)', s=100, alpha=0.7)
            ax4.scatter(train_acc, test_acc, label=f'{model} (Acc)', s=100, alpha=0.7, marker='s')
        
        ax4.set_xlabel('Training Score')
        ax4.set_ylabel('Test Score')
        ax4.set_title('Training vs Test Performance')
        ax4.legend()
        ax4.grid(True, alpha=0.3)
        ax4.plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Perfect Fit')
        
        # 5. Detailed metrics heatmap
        ax5 = axes[1, 1]
        metrics_matrix = []
        for model in models:
            row = []
            for metric in metrics:
                row.append(self.results[model][f'{metric}_test']['mean'])
            metrics_matrix.append(row)
        
        im = ax5.imshow(metrics_matrix, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)
        ax5.set_xticks(range(len(metrics)))
        ax5.set_xticklabels([m.upper() for m in metrics])
        ax5.set_yticks(range(len(models)))
        ax5.set_yticklabels(models)
        ax5.set_title('Performance Heatmap')
        
        # Add text annotations
        for i in range(len(models)):
            for j in range(len(metrics)):
                text = ax5.text(j, i, f'{metrics_matrix[i][j]:.3f}',
                              ha="center", va="center", color="black", fontweight='bold')
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax5)
        cbar.set_label('Score')
        
        # 6. Model summary table
        ax6 = axes[1, 2]
        ax6.axis('tight')
        ax6.axis('off')
        
        # Create summary table
        table_data = []
        table_data.append(['Metric', 'Random Forest', 'XGBoost', 'Winner'])
        
        for metric in metrics:
            rf_score = self.results['Random Forest'][f'{metric}_test']['mean']
            xgb_score = self.results['XGBoost'][f'{metric}_test']['mean']
            winner = 'RF' if rf_score > xgb_score else 'XGB' if xgb_score > rf_score else 'Tie'
            
            table_data.append([
                metric.upper(),
                f'{rf_score:.3f}',
                f'{xgb_score:.3f}',
                winner
            ])
        
        table = ax6.table(cellText=table_data[1:], colLabels=table_data[0],
                         cellLoc='center', loc='center')
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1.2, 1.5)
        
        # Style the table
        for i in range(len(table_data)):
            for j in range(len(table_data[0])):
                cell = table[(i, j)]
                if i == 0:  # Header row
                    cell.set_facecolor('#4CAF50')
                    cell.set_text_props(weight='bold', color='white')
                elif j == 3 and i > 0:  # Winner column
                    if table_data[i][j] == 'RF':
                        cell.set_facecolor('#E3F2FD')
                    elif table_data[i][j] == 'XGB':
                        cell.set_facecolor('#E8F5E8')
        
        ax6.set_title('Performance Summary', fontweight='bold', pad=20)
        
        plt.tight_layout()
        plt.show()
        
        return fig
    
    def print_final_recommendation(self):
        """Print final model recommendation"""
        if not self.results:
            print("No results available for recommendation.")
            return
        
        print(f"\n{'='*60}")
        print("FINAL MODEL RECOMMENDATION")
        print(f"{'='*60}")
        
        # Calculate overall performance scores
        models = list(self.results.keys())
        overall_scores = {}
        
        for model in models:
            # Weight different metrics
            weights = {'accuracy': 0.2, 'precision': 0.2, 'recall': 0.2, 'f1': 0.3, 'roc_auc': 0.1}
            weighted_score = 0
            
            for metric, weight in weights.items():
                score = self.results[model][f'{metric}_test']['mean']
                weighted_score += score * weight
            
            overall_scores[model] = weighted_score
        
        # Find best model
        best_model = max(overall_scores, key=overall_scores.get)
        best_score = overall_scores[best_model]
        
        print(f"Best Model: {best_model}")
        print(f"Overall Score: {best_score:.3f}")
        
        print(f"\nDetailed Analysis:")
        for model in models:
            print(f"\n{model}:")
            f1_mean = self.results[model]['f1_test']['mean']
            f1_std = self.results[model]['f1_test']['std']
            acc_mean = self.results[model]['accuracy_test']['mean']
            prec_mean = self.results[model]['precision_test']['mean']
            rec_mean = self.results[model]['recall_test']['mean']
            
            print(f"  F1 Score: {f1_mean:.3f} (±{f1_std:.3f})")
            print(f"  Accuracy: {acc_mean:.3f}")
            print(f"  Precision: {prec_mean:.3f}")
            print(f"  Recall: {rec_mean:.3f}")
            print(f"  Overall: {overall_scores[model]:.3f}")
        
        # Provide interpretation
        print(f"\nInterpretation:")
        if best_score > 0.8:
            print("✅ Excellent performance - Ready for deployment consideration")
        elif best_score > 0.7:
            print("⚠️ Good performance - Consider more data and tuning")
        elif best_score > 0.6:
            print("⚠️ Moderate performance - Need significant improvements")
        else:
            print("❌ Poor performance - Requires major changes")
        
        # Data size warning
        print(f"\n⚠️ IMPORTANT: Current dataset size ({len(self.data)} samples) is still small")
        print("Recommendation: Collect 200+ samples for more reliable results")
        
        return best_model, best_score

    def train_final_models(self):
        """Train BOTH Random Forest and XGBoost on full dataset"""
        print("\nTraining final models on full dataset...")

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

        self.final_models = {
            "Random Forest": rf_model,
            "XGBoost": xgb_model
        }

        print("✅ Both models trained and stored in self.final_models")
        return self.final_models

    def save_models(self, output_dir="./Model"):
        """Save both trained models to disk"""
        if not hasattr(self, "final_models") or not self.final_models:
            raise RuntimeError("No final models found. Run train_final_models first.")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        for name, model in self.final_models.items():
            file_name = f"{output_dir}/{name.replace(' ', '_')}_final.pkl"
            joblib.dump(model, file_name)
            print(f"💾 Saved {name} model to {file_name}")

    def enhanced_save_models(self, output_dir="./Model"):
        """Enhanced version - save models with complete metadata"""
        
        if not hasattr(self, "final_models") or not self.final_models:
            raise RuntimeError("No final models found. Run train_final_models first.")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Save models
        model_paths = {}
        for name, model in self.final_models.items():
            file_name = f"{output_dir}/{name.replace(' ', '_')}_final.pkl"
            joblib.dump(model, file_name)
            model_paths[name] = file_name
            print(f"💾 Saved {name} model to {file_name}")
        
        # Save feature names
        feature_file = f"{output_dir}/feature_names.json"
        with open(feature_file, 'w') as f:
            json.dump(self.feature_names, f)
        print(f"💾 Saved feature names to {feature_file}")
        
        # Save model metadata
        metadata = {
            "training_date": datetime.now().isoformat(),
            "dataset_info": {
                "total_samples": len(self.data),
                "features_count": len(self.feature_names),
                "class_distribution": dict(self.data['label'].value_counts()),
                "families": dict(self.data['family'].value_counts()) if 'family' in self.data.columns else {}
            },
            "model_performance": self.results if hasattr(self, 'results') else {},
            "model_paths": model_paths,
            "feature_names": self.feature_names
        }
        
        metadata_file = f"{output_dir}/model_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"💾 Saved metadata to {metadata_file}")
        
        print(f"\n✅ Models successfully saved to {output_dir}/")
        print("Files created:")
        print("  - Random_Forest_final.pkl")
        print("  - XGBoost_final.pkl") 
        print("  - feature_names.json")
        print("  - model_metadata.json")

    def predict_with_models(self, new_data):
        """
        Predict using both models.
        new_data: pd.DataFrame (ต้องมี features เหมือน self.feature_names)
        """
        if not hasattr(self, "final_models") or not self.final_models:
            raise RuntimeError("Models not trained yet. Run train_final_models first.")

        predictions = {}
        for name, model in self.final_models.items():
            pred = model.predict(new_data)
            predictions[name] = pred

        return predictions

# Example usage
def run_malware_analysis(csv_file_path):
    """Run complete malware detection analysis"""
    
    # Initialize comparison
    comparison = MalwareModelComparison(csv_file_path)
    
    # Load and prepare data
    data = comparison.load_and_prepare_data()
    
    # Select features
    X, y = comparison.select_features()
    
    # Train and evaluate models
    results = comparison.train_and_evaluate_models(cv_folds=5)
    
    # Create comparison plots
    comparison.plot_comparison()
    
    # Print recommendation
    best_model, score = comparison.print_final_recommendation()

    return comparison, results

# Run the analysis
if __name__ == "__main__":
    # Replace with your actual file path
    CSV_FILE = "./Dataset/malware_dataset.csv"
    
    try:
        print("Starting malware detection analysis...")
        
        # Run analysis
        comparison, results = run_malware_analysis(CSV_FILE)
        
        # Train final models
        print("\nTraining final models...")
        comparison.train_final_models()
        
        # Save models with enhanced method
        print("\nSaving models...")
        comparison.enhanced_save_models("./Model")
        
        print(f"\n🎉 Analysis completed successfully!")
        print("Models are saved and ready to use!")
        
    except FileNotFoundError:
        print(f"❌ Error: Could not find {CSV_FILE}")
        print("Please make sure the CSV file exists in the correct path.")
    
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        print("Please check your data format and try again.")