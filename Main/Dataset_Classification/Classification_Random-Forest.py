import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import os

# ใช้ path ให้ตรงกับของผู้ใช้: Main/Dataset/all_features_df.csv
dataset_path = os.path.join("Main", "Dataset", "all_features_df.csv")
df = pd.read_csv(dataset_path)

# แยก Features กับ Labels
X = df.drop(columns=["label"])
y = df["label"]

# แบ่ง train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

# สร้างและเทรนโมเดล Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ทำนายและประเมินผล
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, output_dict=True)
conf_matrix = confusion_matrix(y_test, y_pred, labels=[0, 1])


# บันทึกโมเดลในตำแหน่งเดียวกัน
model_path = os.path.join("Main", "Dataset", "Model.joblib")
joblib.dump(model, model_path)

# วาดกราฟความสำคัญของฟีเจอร์
importances = model.feature_importances_
feature_names = X.columns
forest_importances = pd.Series(importances, index=feature_names).sort_values(ascending=False)

plot_path = os.path.join("Main", "Dataset", "feature_importance_plot.png")
plt.figure(figsize=(10, 6))
forest_importances.head(15).plot(kind="bar")
plt.title("Top 15 Important Features")
plt.ylabel("Feature Importance Score")
plt.tight_layout()
plt.savefig(plot_path)

# สรุปผลลัพธ์
summary = {
    "Accuracy": accuracy,
    "Classification Report": report,
    "Confusion Matrix": conf_matrix.tolist(),
    "Model Path": model_path,
    "Feature Importance Plot": plot_path
}

summary

