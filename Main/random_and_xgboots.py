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

    # constructure
    def __init__(self, data_path):
        """Initialize with dataset path"""
        self.data_path = data_path # path ที่เก็บ dataset
        self.data = None # DataFrame สำหรับเก็บข้อมูล
        self.X = None # Feature matrix
        self.y = None # Target vector
        self.feature_names = None # ชื่อฟีเจอร์
        self.results = {} # ผลลัพธ์การประเมินโมเดล
        self.final_models = {} # โมเดลสุดท้ายที่เลือก

    def load_and_prepare_data(self): # <-- fucntion for read dataset 
        """Load and prepare the dataset"""
        print("Loading dataset...")
        self.data = pd.read_csv(self.data_path) # อ่านไฟล์ CSV เป็น DataFrame
        print(f"Dataset shape: {self.data.shape}")
        
        # if "total_permissions" not in self.data.columns: # ตรวจสอบว่ามีคอลัมน์ total_permissions หรือไม่
        #     self.data["total_permissions"] = ( # คำนวณคอลัมน์ total_permissions
        #         self.data.get("dangerous_permissions", 0) +
        #         self.data.get("normal_permissions", 0) +
        #         self.data.get("unknown_permissions", 0)
        #     )
        #self.data = self.data[self.data['total_permissions'] > 0] # กรองแถวที่มี total_permissions > 0 กรองเพราะอย่างน้อย 1 แอปต้องขอสิทธิ์ dangerous normal unknown total
        #print(f"Cleaned dataset shape: {self.data.shape}")

        label_counts = self.data['label'].value_counts() # นับจำนวนตัวอย่างในแต่ละคลาส
        print(f"Class distribution: Safe(0): {label_counts.get(0,0)}, Malware(1): {label_counts.get(1,0)}")
        if len(self.data) > 0: # ตรวจสอบว่ามีข้อมูลอยู่หรือไม่
            print(f"Malware ratio: {label_counts.get(1,0)/len(self.data):.2%}") # แสดงสัดส่วนของ malware และ benign ใน dataset
        return self.data
    
    def select_features(self):  # <-- function for select feature
        """Select relevant features for modeling"""
        exclude_cols = ['label', 'family', 'filename'] # คอลัมน์ที่ไม่ใช้เป็นฟีเจอร์
        feature_cols = [ # เลือกคอลัมน์ที่ใช้เป็นฟีเจอร์
            col for col in self.data.columns
            if col not in exclude_cols and self.data[col].dtype in ['int64', 'float64']
        ]
        self.X = self.data[feature_cols] # กำหนด feature matrix
        self.y = self.data['label'] # กำหนด target vector
        self.feature_names = feature_cols # เก็บชื่อฟีเจอร์
        print(f"Selected {len(feature_cols)} features for modeling")
        return self.X, self.y # return feature matrix and target vector
    
    def train_and_evaluate_models(self, cv_folds=5): # <-- function for Test betterween xgboost and randomforest
        """Train and evaluate models using cross-validation"""
        models = { # dictionary เก็บโมเดลที่ใช้เปรียบเทียบ
            'Random Forest': RandomForestClassifier( # โมเดล Random Forest
                n_estimators=200, # จำนวนต้นไม้ในป่า
                max_depth=10, # ความลึกสูงสุดของต้นไม้
                min_samples_split=5, # จำนวนตัวอย่างขั้นต่ำในการแบ่ง
                min_samples_leaf=2, # จำนวนตัวอย่างขั้นต่ำในใบไม้
                random_state=42, # ตั้งค่า random state เพื่อความสม่ำเสมอ
                class_weight='balanced' # ปรับสมดุลของคลาส
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=200, # จำนวนต้นไม้ในป่า
                max_depth=6, # ความลึกสูงสุดของต้นไม้
                learning_rate=0.1, # อัตราการเรียนรู้
                subsample=0.8, # สัดส่วนของข้อมูลที่ใช้ในการฝึก
                colsample_bytree=0.8, # สัดส่วนของฟีเจอร์ที่ใช้ในการฝึก
                random_state=42, # ตั้งค่า random state เพื่อความสม่ำเสมอ
                scale_pos_weight=len(self.y[self.y==0])/len(self.y[self.y==1]) # ปรับสมดุลของคลาส
            )
        }

        scoring = [
            'accuracy', # ความแม่นยำ คือ อัตราของการทำนายที่ถูกต้อง
            'precision', # ความแม่นยำเชิงบวก คือ อัตราของการทำนายเชิงบวกที่ถูกต้อง
            'recall', # ความไว คือ อัตราการตรวจจับเชิงบวก
            'f1', # คะแนน F1 คือค่าเฉลี่ยเชิงฮาร์มอนิกของ precision และ recall
            'roc_auc' # AUC-ROC คือพื้นที่ใต้โค้ง ROC
        ] # เมตริกที่ใช้ประเมินโมเดล
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42) # กำหนด cross-validation แบบ stratified
        results = {} # dictionary เก็บผลลัพธ์การประเมินโมเดล
        
        for model_name, model in models.items(): # loop ผ่านแต่ละโมเดล
            print(f"\nTraining {model_name}...")
            cv_results = cross_validate( # ทำการ cross-validation 
                model, self.X, self.y,
                cv=cv, scoring=scoring, return_train_score=True
            )
            """
            5 k fold cross-validation results:
            round 1 | train = 2,3,4,5 | test = 1
            round 2 | train = 1,3,4,5 | test = 2
            round 3 | train = 1,2,4,5 | test = 3
            round 4 | train = 1,2,3,5 | test = 4
            round 5 | train = 1,2,3,4 | test = 5
            20% test 80% train 
            """
            results[model_name] = {} # สร้าง dictionary ย่อยสำหรับเก็บผลลัพธ์ของแต่ละโมเดล
            for metric in scoring:
                # เก็บผล test
                results[model_name][f'{metric}_test'] = {
                    'mean': np.mean(cv_results[f'test_{metric}']), # ค่าเฉลี่ยของเมตริก
                    'std': np.std(cv_results[f'test_{metric}']), # ส่วนเบี่ยงเบนมาตรฐานของเมตริก
                    'scores': cv_results[f'test_{metric}'] # ค่าของเมตริกในแต่ละรอบของ cross-validation
                }
                
                # เก็บผล train
                results[model_name][f'{metric}_train'] = {
                    'mean': np.mean(cv_results[f'train_{metric}']),
                    'std': np.std(cv_results[f'train_{metric}']),
                    'scores': cv_results[f'train_{metric}']
                }
                
                gap = results[model_name][f'{metric}_train']['mean'] - results[model_name][f'{metric}_test']['mean'] # คำนวณ Gap ระหว่าง train กับ test 0.94 - 0.91 = 0.03
    
                # แสดงผล พร้อม Gap เป็น %
                print(f"{metric.upper():8} | "
                    f"Train: {results[model_name][f'{metric}_train']['mean']:.3f} ± {results[model_name][f'{metric}_train']['std']:.3f} | " #  ผล train mean std
                    f"Test: {results[model_name][f'{metric}_test']['mean']:.3f} ± {results[model_name][f'{metric}_test']['std']:.3f} | " # ผล test mean std
                    f"Gap: {gap*100:.2f}%") # Gap เป็น %
        self.results = results 
        return results
    
    def print_final_recommendation(self): # <-- function show best model 
        """Print final model recommendation"""
        if not self.results: # ตรวจสอบว่ามีผลลัพธ์การประเมินโมเดลหรือไม่
            print("No results available.")
            return None, None

        models = list(self.results.keys()) # ดึงชื่อโมเดลทั้งหมด
        overall_scores = {} # dictionary เก็บคะแนนรวมของแต่ละโมเดล
        weights = {'accuracy':0.2, 'precision':0.2, 'recall':0.2, 'f1':0.3, 'roc_auc':0.1} # กำหนดน้ำหนักให้กับแต่ละเมตริก

        for model in models: # loop ผ่านแต่ละโมเดล
            score = 0 # ตัวแปรเก็บคะแนนรวม
            for metric, w in weights.items():
                score += self.results[model][f'{metric}_test']['mean'] * w # คำนวณคะแนนรวมโดยคูณค่า mean ของแต่ละเมตริกกับน้ำหนักที่กำหนด
            overall_scores[model] = score # เก็บคะแนนรวมใน dictionary
        
        best_model = max(overall_scores, key=overall_scores.get) # หาโมเดลที่มีคะแนนรวมสูงสุด
        best_score = overall_scores[best_model] # คะแนนรวมสูงสุด
        print(f"\nBest Model: {best_model} | Overall Score: {best_score:.3f}") # แสดงผลโมเดลที่ดีที่สุดและคะแนนรวมo
        
        # print("\nDetailed metrics per model:")
        # for model in models: 
        #     print(f"\n{model}:")
        #     for metric in ['accuracy','precision','recall','f1','roc_auc']:
        #         print(f"  {metric.upper():8}: {self.results[model][f'{metric}_test']['mean']:.3f} ± {self.results[model][f'{metric}_test']['std']:.3f}")
        #     print(f"  Weighted Overall Score: {overall_scores[model]:.3f}")
        
        return best_model, best_score
    
    def train_final_models(self): # <-- function for train final model 
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
        os.makedirs(output_dir, exist_ok=True) #
        for name, model in self.final_models.items():
            path = f"{output_dir}/{name.replace(' ','_')}_final.pkl"
            joblib.dump(model, path)
            print(f"Saved {name} model to {path}")
        feature_file = f"{output_dir}/feature_names.json"
        with open(feature_file, 'w') as f:
            json.dump(self.feature_names, f)
        print(f"Saved feature names to {feature_file}")

if __name__ == "__main__": # <-- Methode Main
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
