# Android Malware Detection & Risk Assessment

โปรเจคนี้ใช้ Machine Learning ในการวิเคราะห์แอปพลิเคชัน Android เพื่อตรวจจับมัลแวร์และประเมินความเสี่ยง โดยใช้ข้อมูลจาก MobSF (Mobile Security Framework)

## โครงสร้างโปรเจค

```
📁 classification/          # โมเดลจำแนกประเภท (Malware vs Benign)
  ├── features.py           # ฟังก์ชันสกัด features จาก JSON
  ├── 1_create_dataset.py   # สร้าง dataset จากไฟล์ JSON
  ├── 2_train_model.py      # train Random Forest และ XGBoost
  └── 3_use_model.py        # ทดสอบใช้โมเดล

📁 regression/              # โมเดลประเมินความเสี่ยง (Risk Score 0-1)
  ├── features.py           # ฟังก์ชันสกัด features จาก JSON
  ├── 1_create_dataset.py   # สร้าง dataset จากไฟล์ JSON
  ├── 2_train_model.py      # train Random Forest และ XGBoost
  └── 3_use_model.py        # ทดสอบใช้โมเดล

📁 utils/                   # เครื่องมือช่วยเหลือ
  └── analyze_features.py   # วิเคราะห์ความแตกต่างของ features

📁 Dataset/                 # ไฟล์ dataset (CSV)
  ├── malware_dataset.csv            # สำหรับ classification
  └── malware_dataset_regression.csv # สำหรับ regression

📁 Model/                   # โมเดลที่ train เสร็จแล้ว (Classification)
  ├── Random_Forest_final.pkl
  ├── XGBoost_final.pkl
  ├── feature_names.json
  └── model_metadata.json

📁 Model_Regression/        # โมเดลที่ train เสร็จแล้ว (Regression)
  ├── Random_Forest_risk_regressor.pkl
  ├── XGBoost_risk_regressor.pkl
  └── feature_names.json

📁 Data/                    # ข้อมูลต้นฉบับ (JSON จาก MobSF)
  ├── malware/              # ไฟล์ JSON ของ malware
  └── benign/               # ไฟล์ JSON ของแอปปกติ

📁 archived/                # ไฟล์เก่าที่ไม่ได้ใช้แล้ว
  ├── feature_extraction_test.py
  └── Dataset_Classification/
```

## วิธีใช้งาน

### 1. Classification Model (จำแนก Malware vs Benign)

#### สร้าง Dataset
```bash
cd classification
python 1_create_dataset.py
```
- อ่านไฟล์ JSON จากโฟลเดอร์ `Data/malware/` และ `Data/benign/`
- สกัด features โดยใช้ `features.py`
- บันทึก dataset ไปที่ `Dataset/malware_dataset.csv`

#### Train Model
```bash
python 2_train_model.py
```
- โหลด dataset จาก `Dataset/malware_dataset.csv`
- Train Random Forest และ XGBoost
- ทำ Cross Validation (5-fold)
- บันทึกโมเดลไปที่ `Model/`

#### ทดสอบใช้ Model
```bash
python 3_use_model.py
```
- โหลดโมเดลจาก `Model/`
- ทดสอบกับไฟล์ JSON
- แสดงความน่าจะเป็นที่เป็น Malware

### 2. Regression Model (ประเมินคะแนนความเสี่ยง)

#### สร้าง Dataset
```bash
cd regression
python 1_create_dataset.py
```
- อ่านไฟล์ JSON จากโฟลเดอร์ `Data/regression/`
- แปลง features เป็น binary (0/1)
- คำนวณ risk score = (จำนวน features ที่มีค่า 1) / (จำนวน features ทั้งหมด)
- บันทึก dataset ไปที่ `Dataset/malware_dataset_regression.csv`

#### Train Model
```bash
python 2_train_model.py
```
- โหลด dataset จาก `Dataset/malware_dataset_regression.csv`
- Train Random Forest และ XGBoost Regressor
- ทำ Cross Validation (5-fold)
- บันทึกโมเดลไปที่ `Model_Regression/`

#### ทดสอบใช้ Model
```bash
python 3_use_model.py
```
- โหลดโมเดลจาก `Model_Regression/`
- ทดสอบกับไฟล์ JSON
- แสดง Risk Score (0-1)

## Features ที่ใช้ในการวิเคราะห์

### Classification Features (40+ features)
- ข้อมูลพื้นฐาน: ขนาดไฟล์, จำนวน activities, services, receivers, providers
- Exported Components: จำนวน components ที่เปิดเผยออกไป
- Permissions: dangerous, normal, unknown permissions
- Permissions เฉพาะ: camera, location, SMS, microphone, call log, contacts, storage
- Certificate Analysis: ประเภท signature (v1-v4)
- Manifest Analysis: ปัญหาใน AndroidManifest.xml
- API Usage: การใช้ API ที่น่าสงสัย (reflection, dexloading, os_command, etc.)
- Code Analysis: ปัญหาจากการวิเคราะห์โค้ด
- Network: จำนวน domains และ URLs
- Hardcoded Keystore: การฝัง keystore ในโค้ด
- PlayStore Status: อยู่บน Play Store หรือไม่

### Regression Features
ใช้ features เดียวกับ Classification แต่แปลงเป็น binary (0/1)

## ความต้องการของระบบ

```bash
pip install -r requirements.txt
```

Dependencies:
- pandas==2.0.3
- numpy==1.26.1
- matplotlib==3.8.0
- seaborn==0.13.2
- scikit-learn==1.4.0
- xgboost==1.8.5
- joblib==1.3.2
- requests==2.31.0

## ไฟล์เก่าที่ถูกย้ายไป archived/

ไฟล์ที่อยู่ใน `archived/` คือโค้ดเวอร์ชันเก่าหรือไฟล์ที่ไม่ได้ใช้แล้ว:
- `feature_extraction_test.py` - ไฟล์ทดสอบที่มี bug (ขาดตัวแปร `feature_order`)
- `Dataset_Classification/` - โครงสร้างเก่าของโปรเจค

## การพัฒนาต่อ

1. ปรับ hyperparameters ใน `2_train_model.py`
2. เพิ่ม features ใหม่ใน `features.py`
3. ทดสอบโมเดลกับ dataset ใหม่
4. เปรียบเทียบประสิทธิภาพระหว่าง Classification และ Regression

## หมายเหตุ

- ไฟล์ JSON ต้องมาจาก MobSF (Mobile Security Framework)
- โมเดล Classification เหมาะสำหรับการตัดสินใจว่าเป็น malware หรือไม่
- โมเดล Regression เหมาะสำหรับการประเมินระดับความเสี่ยง
