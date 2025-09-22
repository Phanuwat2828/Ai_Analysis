import json
import joblib
import pandas as pd
from feature import extract_features_from_json as extract_features

# โหลดโมเดลและ LabelEncoder ที่บันทึกไว้ตอน train
model = joblib.load('./Model/apk_malware_xgboost_model.pkl')
label_encoder = joblib.load('./Model/label_encoder.pkl')

# โหลด JSON ตัวอย่างจาก MobSF
with open('./Data/Safe/Safe_Facebook.json', 'r', encoding='utf-8') as f:
    json_data = json.load(f)

# Extract features ออกมาเป็น dict
features = extract_features(json_data)

# แปลงเป็น DataFrame 1 แถว
df_new = pd.DataFrame([features])

# Predict
y_pred = model.predict(df_new)
proba = model.predict_proba(df_new)[0]

# แปลงตัวเลขกลับเป็น label
predicted_label = label_encoder.inverse_transform(y_pred)[0]

# แสดงผล
print(f"Prediction: {predicted_label}")
print("Confidence:", round(float(max(proba)), 4))
