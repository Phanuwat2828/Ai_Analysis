import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import LabelEncoder
import joblib  # สำหรับบันทึกโมเดล

# อ่านไฟล์ CSV ที่เก็บ dataset
df = pd.read_csv("./Dataset/apk_analysis_dataset.csv")

# แปลง label เป็นตัวเลข (0, 1, 2)
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(df["label"])

# แยกฟีเจอร์
X = df.drop(columns=["label"])

# แบ่งข้อมูลเป็น train/test set (80% สำหรับเทรน, 20% สำหรับทดสอบ)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# สร้างโมเดล XGBoost
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42)

# ทำนายผลจากข้อมูล test
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

# ประเมินผลโมเดล
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("Classification Report:")
print(classification_report(y_test, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ใช้ Cross-validation เพื่อประเมินโมเดล
cv_scores = cross_val_score(model, X, y, cv=5)  # 5-fold cross-validation
print(f"Cross-validation Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

# แสดงความสำคัญของฟีเจอร์
feature_importances = model.feature_importances_
sorted_idx = feature_importances.argsort()

print("\nFeature Importance:")
for idx in sorted_idx[::-1]:
    print(f"{X.columns[idx]}: {feature_importances[idx]:.4f}")

# ใช้ GridSearchCV เพื่อหาพารามิเตอร์ที่ดีที่สุด
param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [10, 20, None],
    'learning_rate': [0.01, 0.1, 0.2],
    'subsample': [0.8, 1.0]
}

grid_search = GridSearchCV(estimator=model, param_grid=param_grid, cv=5, n_jobs=-1, verbose=2)
grid_search.fit(X_train, y_train)

print("\nBest parameters from GridSearchCV:")
print(grid_search.best_params_)

# สร้างโมเดลใหม่ที่ใช้พารามิเตอร์ที่ดีที่สุดจาก GridSearchCV
best_model = grid_search.best_estimator_

# บันทึกโมเดลที่ฝึกแล้ว
joblib.dump(best_model, './Model/apk_malware_xgboost_model.pkl')
print("โมเดล XGBoost ได้ถูกบันทึกลงในไฟล์ 'apk_malware_xgboost_model.pkl'")

