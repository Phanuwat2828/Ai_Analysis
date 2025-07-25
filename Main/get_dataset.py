import pandas as pd
import json
import os

# (สมมติว่ามีฟังก์ชัน extract_features() ที่สมบูรณ์อยู่แล้ว)
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
#  ส่วนที่ 1: การสร้างและเพิ่มข้อมูลสมมติ (เหมือนที่คุณต้องการ)
# ==============================================================================
print("--- ขั้นตอนที่ 1: กำลังสร้างข้อมูลสมมติ (Mock Data) ---")

all_features = []
all_labels = []

# ตัวอย่างข้อมูลชุดที่ 1 (แอปเสี่ยง)
report_risky = {'permissions': [{'status': 'dangerous'}, {'status': 'dangerous'}], 'code_analysis': {'analysis': [{'metadata': {'severity': 'high'}}]}}
features1 = extract_features(report_risky)
all_features.append(features1)
all_labels.append(1) # Label 1 = เสี่ยง

# ตัวอย่างข้อมูลชุดที่ 2 (แอปปลอดภัย)
report_safe = {'permissions': [{'status': 'normal'}], 'code_analysis': {'analysis': [{'metadata': {'severity': 'low'}}]}}
features2 = extract_features(report_safe)
all_features.append(features2)
all_labels.append(0) # Label 0 = ปลอดภัย

# ตัวอย่างข้อมูลชุดที่ 3 (เสี่ยงน้อย)
features3 = extract_features({'permissions': [{'status': 'dangerous'}], 'code_analysis': {'analysis': []}})
all_features.append(features3)
all_labels.append(0)

# ตัวอย่างข้อมูลชุดที่ 4 (เสี่ยงมาก)
features4 = extract_features({'permissions': [{'status': 'dangerous'}], 'code_analysis': {'analysis': [{'metadata': {'severity': 'high'}}, {'metadata': {'severity': 'high'}}]}})
all_features.append(features4)
all_labels.append(1)

print("สร้างข้อมูลสมมติเสร็จสิ้น จำนวน:", len(all_features), "ชุด")


# ==============================================================================
#  ส่วนที่ 2: การโหลดข้อมูลจริงจากโฟลเดอร์ `reports` (เหมือนคำตอบที่แล้ว)
# ==============================================================================
print("\n--- ขั้นตอนที่ 2: กำลังโหลดข้อมูลจริงจากไฟล์ JSON ---")

REPORTS_DIR = 'Data' # กำหนด Path ไปยังโฟลเดอร์

# ตรวจสอบว่ามีโฟลเดอร์ reports อยู่จริงหรือไม่
if os.path.isdir(REPORTS_DIR):
    print(f"กำลังอ่านข้อมูลจากโฟลเดอร์: {REPORTS_DIR}")

    # วนลูปอ่านทุกไฟล์ในโฟลเดอร์
    for filename in os.listdir(REPORTS_DIR):
        if filename.endswith('.json'):
            file_path = os.path.join(REPORTS_DIR, filename)
            label = 1 if filename.startswith('risky_') else 0
            
            print(f"  - กำลังประมวลผลไฟล์: {filename} (Label: {label})")

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                features = extract_features(report_data)
                
                # เพิ่มข้อมูลที่อ่านจากไฟล์เข้าไปใน list เดิม
                all_features.append(features)
                all_labels.append(label)

            except Exception as e:
                print(f"    [ผิดพลาด] เกิดปัญหาในการประมวลผลไฟล์ {filename}: {e}")
else:
    print(f"ไม่พบโฟลเดอร์ '{REPORTS_DIR}' จะใช้แค่ข้อมูลสมมติในการทำงานต่อไป")


# ==============================================================================
#  ส่วนที่ 3: รวมข้อมูลทั้งหมดและสร้าง DataFrame
# ==============================================================================
print("\n--- ขั้นตอนที่ 3: กำลังสร้าง DataFrame สำหรับฝึกสอน AI ---")

if not all_features:
    print("ไม่พบข้อมูลสำหรับฝึกสอน! โปรดตรวจสอบโค้ดหรือไฟล์ของคุณ")
else:
    # --- แปลงข้อมูลทั้งหมด (ทั้งสมมติและของจริง) เป็น DataFrame ของ Pandas ---
    df = pd.DataFrame(all_features)
    df['label'] = all_labels # เพิ่มคอลัมน์คำตอบ (label)

    print("\nDataset ทั้งหมดที่พร้อมสำหรับฝึกสอน AI:")
    print(df) # <-- แสดง DataFrame ทั้งหมดตามที่คุณต้องการ

    print("\nสรุปข้อมูลทั้งหมด:")
    print(f"จำนวนข้อมูลทั้งหมด: {len(df)} ชุด")
    print(df['label'].value_counts()) # นับจำนวนของแต่ละ Label

# ==============================================================================
#  ส่วนต่อไป: นำ DataFrame (df) ไปเทรนด้วย Scikit-learn
# ==============================================================================
# ...
# วางโค้ดขั้นตอนที่ 3 (train_test_split, model.fit) และ 4 (joblib.dump)
# จากคำตอบก่อนๆ มาต่อท้ายตรงนี้ได้เลย
# ...

# สมมติว่าตัวแปร 'df' ที่เป็น DataFrame ของคุณถูกสร้างเรียบร้อยแล้ว
# จากโค้ดในขั้นตอนก่อนหน้า...

# ตรวจสอบก่อนว่า df มีข้อมูลหรือไม่
if 'df' not in locals() or df.empty:
    print("DataFrame 'df' ไม่ได้ถูกสร้างหรือไม่มีข้อมูล, ไม่สามารถดำเนินการต่อได้")
else:
    # --- เริ่มกระบวนการ Machine Learning ---
    from sklearn.model_selection import train_test_split
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    import joblib
    import pandas as pd # อาจจะต้อง import อีกครั้งเผื่อรันแยก

    # ขั้นตอนที่ 1: แบ่งข้อมูล Features (X) และ Label (y)
    print("\n--- ขั้นตอนที่ 1: กำลังแบ่งข้อมูล Features และ Labels ---")
    
    # X คือข้อมูลทั้งหมด "ยกเว้น" คอลัมน์คำตอบ
    X = df.drop('label', axis=1) 
    
    # y คือคอลัมน์คำตอบเพียงอย่างเดียว
    y = df['label']
    
    print("Features (X) ที่จะใช้สอน:")
    print(X.head())
    print("\nLabels (y) ที่เป็นคำตอบ:")
    print(y.head())

    # ขั้นตอนที่ 2: แบ่งข้อมูลสำหรับ Train (80%) และ Test (20%)
    print("\n--- ขั้นตอนที่ 2: กำลังแบ่งข้อมูลสำหรับฝึกสอนและทดสอบ ---")
    # random_state=42 เพื่อให้ผลการสุ่มเหมือนเดิมทุกครั้งที่รัน (สำคัญมาก!)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=42, stratify=y)
    # stratify=y ช่วยให้สัดส่วนของ label 0 และ 1 ในชุด train/test ใกล้เคียงกับของเดิม
    
    print(f"ขนาดข้อมูลสำหรับฝึกสอน (Train Set): {X_train.shape[0]} ชุด")
    print(f"ขนาดข้อมูลสำหรับทดสอบ (Test Set): {X_test.shape[0]} ชุด")

    # ขั้นตอนที่ 3: เลือกและสร้างโมเดล
    print("\n--- ขั้นตอนที่ 3: กำลังสร้างโมเดล (Decision Tree) ---")
    # เราเลือก DecisionTreeClassifier เพราะมันเข้าใจง่าย เหมือนแผนผังการตัดสินใจ
    model = DecisionTreeClassifier(random_state=42)
    print(f"สร้างโมเดลประเภท: {type(model).__name__}")

    # ขั้นตอนที่ 4: ฝึกสอนโมเดล (Training / Fitting)
    print("\n--- ขั้นตอนที่ 4: กำลังฝึกสอนโมเดล... ---")
    # .fit() คือคำสั่ง "เริ่มเรียนรู้!"
    model.fit(X_train, y_train)
    print("ฝึกสอนโมเดลเสร็จสิ้น!")

    # ขั้นตอนที่ 5: ประเมินผลโมเดล (Evaluation)
    print("\n--- ขั้นตอนที่ 5: กำลังประเมินผลโมเดลด้วย Test Set ---")
    
    # ให้โมเดลลองทำนายผลจากข้อมูล X_test ที่มันไม่เคยเห็นมาก่อน
    y_pred = model.predict(X_test)

    # 5.1) วัดความแม่นยำ (Accuracy)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nความแม่นยำ (Accuracy): {accuracy * 100:.2f}%")
    
    # 5.2) ดูรายงานผลแบบละเอียด (Classification Report)
    print("\nClassification Report:")
    # target_names ช่วยให้รายงานอ่านง่ายขึ้น
    print(classification_report(y_test, y_pred, target_names=['ปลอดภัย (0)', 'มีความเสี่ยง (1)']))

    # 5.3) ดู Confusion Matrix เพื่อให้เห็นว่าโมเดลทายผิด-ทายถูกอย่างไร
    print("\nConfusion Matrix:")
    # ผลลัพธ์คือ [[TN, FP],
    #             [FN, TP]]
    # TN = ทายว่าปลอดภัย และมันปลอดภัยจริงๆ (ถูก)
    # FP = ทายว่าเสี่ยง แต่จริงๆ มันปลอดภัย (False Positive)
    # FN = ทายว่าปลอดภัย แต่จริงๆ มันเสี่ยง (False Negative - ***อันตรายที่สุด***)
    # TP = ทายว่าเสี่ยง และมันเสี่ยงจริงๆ (ถูก)
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    # ขั้นตอนสุดท้าย: บันทึกโมเดลที่ฉลาดแล้วเก็บไว้ใช้
    print("\n--- กำลังบันทึกโมเดลที่ฝึกสอนแล้ว ---")
    joblib.dump(model, 'mobsf_risk_classifier.joblib')
    print("โมเดลถูกบันทึกเรียบร้อยในชื่อ: 'mobsf_risk_classifier.joblib'")