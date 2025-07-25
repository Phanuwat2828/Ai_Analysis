import joblib
import json
import pandas as pd

# ==============================================================================
#  ส่วนที่ 1: เตรียมเครื่องมือ (โหลดโมเดล และเตรียมฟังก์ชัน)
# ==============================================================================

# 1.1 - โหลดโมเดลที่ฝึกสอนแล้วจากไฟล์
try:
    model = joblib.load('mobsf_risk_classifier.joblib')
    print("โหลดโมเดล 'mobsf_risk_classifier.joblib' สำเร็จ!")
except FileNotFoundError:
    print("ไม่พบไฟล์โมเดล! กรุณาตรวจสอบว่ามีไฟล์ .joblib อยู่ในโฟลเดอร์เดียวกัน")
    exit()

# 1.2 - คัดลอกฟังก์ชัน extract_features ตัวเดิมมาไว้ที่นี่
# **สำคัญมาก:** ต้องเป็นฟังก์ชันเดียวกับที่ใช้เทรนโมเดลทุกประการ
# เพื่อให้ข้อมูลที่ป้อนให้โมเดลมีรูปแบบเดียวกัน
def extract_features(report_data):
    features = {}
    try:
        permissions_df = pd.DataFrame(report_data['permissions'])
        features['dangerous_permissions_count'] = len(permissions_df[permissions_df['status'] == 'dangerous'])
    except (KeyError, TypeError, AttributeError):
        features['dangerous_permissions_count'] = 0
    try:
        code_analysis_df = pd.DataFrame(report_data['code_analysis']['analysis'])
        features['high_severity_vulns'] = len(code_analysis_df[code_analysis_df['metadata']['severity'] == 'high'])
    except (KeyError, TypeError, AttributeError):
        features['high_severity_vulns'] = 0
    try:
        manifest_df = pd.DataFrame(report_data['manifest_analysis']['analysis'])
        allow_backup_rule = manifest_df[manifest_df['title'].str.contains("allowBackup", na=False)]
        features['is_allow_backup'] = 1 if not allow_backup_rule.empty and allow_backup_rule.iloc[0]['stat'] == 'bad' else 0
    except (KeyError, TypeError, AttributeError):
        features['is_allow_backup'] = 0
    return features

# ==============================================================================
#  ส่วนที่ 2: การทำนายผล (Prediction Pipeline)
# ==============================================================================

# 2.1 - ระบุชื่อไฟล์ JSON ของแอปใหม่ที่ต้องการตรวจสอบ
NEW_REPORT_PATH = '../Data/report_b4269d1444cdc7f9b7c1c4e815870c83.json' # <-- แก้ไขเป็นชื่อไฟล์ของคุณ

print(f"\n--- กำลังทำนายผลจากไฟล์: {NEW_REPORT_PATH} ---")

try:
    # 2.2 - โหลดข้อมูลจากไฟล์ JSON ใหม่
    with open(NEW_REPORT_PATH, 'r', encoding='utf-8') as f:
        new_data = json.load(f)

    # 2.3 - สกัด Features จากข้อมูลใหม่ด้วยฟังก์ชันเดิม
    new_features = extract_features(new_data)
    print(f"Features ที่สกัดได้: {new_features}")

    # 2.4 - แปลง Features ให้อยู่ในรูปแบบ DataFrame ที่โมเดลเข้าใจ
    # ต้องสร้างเป็น DataFrame ที่มีคอลัมน์เหมือนกับตอนเทรนทุกประการ
    input_df = pd.DataFrame([new_features])

    # 2.5 - สั่งให้โมเดลทำนายผล!
    prediction = model.predict(input_df)
    
    # (แนะนำ) ดูความน่าจะเป็นของการทำนาย
    # ผลลัพธ์จะเป็น [[Prob_of_0, Prob_of_1]]
    probabilities = model.predict_proba(input_df)

    # 2.6 - แสดงผลลัพธ์ให้ผู้ใช้เข้าใจง่าย
    print("\n--- ผลการวิเคราะห์จาก AI ---")
    predicted_label = prediction[0]
    
    if predicted_label == 1:
        print("ผลการทำนาย: 🚨 มีความเสี่ยง (Risky) - Label 1")
    else:
        print("ผลการทำนาย: ✅ ปลอดภัย (Safe) - Label 0")

    print(f"ความเชื่อมั่น (Confidence):")
    print(f"  - ปลอดภัย (Safe): {probabilities[0][0] * 100:.2f}%")
    print(f"  - มีความเสี่ยง (Risky): {probabilities[0][1] * 100:.2f}%")


except FileNotFoundError:
    print(f"[ผิดพลาด] ไม่พบไฟล์ '{NEW_REPORT_PATH}'")
except Exception as e:
    print(f"[ผิดพลาด] เกิดปัญหาในการประมวลผล: {e}")