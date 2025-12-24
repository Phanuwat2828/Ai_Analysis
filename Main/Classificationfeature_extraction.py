import glob
import pandas as pd
import json
import os
from Classificationusefeature import extract_features_001 as extract_features
import matplotlib.pyplot as plt
import seaborn as sns

def process_malware_dataset(max_files_per_folder=4000): # <-- function for create dataset from json report file
    BASE_PATH = os.path.abspath(os.path.join(os.getcwd(), "."))  # กำหนด path ฐานที่เก็บข้อมูล
    folders = ['malware', 'benign'] # โฟลเดอร์ที่เก็บข้อมูล malware และ benign
    dataset = [] # list สำหรับเก็บข้อมูลทั้งหมด

    for folder in folders: # loop ผ่านแต่ละโฟลเดอร์
        folder_path = os.path.join(BASE_PATH, "Data", folder) # สร้าง path เต็มไปยังโฟลเดอร์ folder Data
        print("===========> " + folder_path)

        json_files = glob.glob(os.path.join(folder_path, "*.json")) # ค้นหาไฟล์ .json ทั้งหมดในโฟลเดอร์
        print(f"{folder}: found {len(json_files)} JSON files")

        if len(json_files) > max_files_per_folder:  # จำกัดจำนวนไฟล์ที่ใช้ต่อโฟลเดอร์
            json_files = json_files[:max_files_per_folder] # ตัดไฟล์ให้เหลือไม่เกิน max_files_per_folder

        print(f"{folder}: using {len(json_files)} files")

        label = 0 if folder == 'benign' else 1 # กำหนด label 0 สำหรับ benign และ 1 สำหรับ malware
        
        for json_file in json_files: # loop ผ่านแต่ละไฟล์ json
            try:
                with open(json_file, 'r', encoding='utf-8', errors='ignore') as f: # เปิดไฟล์ json
                    data = json.load(f)
                
                features = extract_features(data) # เรียกใช้ฟังก์ชัน extract_features เพื่อดึงคุณลักษณะจากข้อมูล
                features['label'] = label # เพิ่มคอลัมน์ label
                features['family'] = folder # เพิ่มคอลัมน์ family
                features['filename'] = os.path.basename(json_file) # เพิ่มคอลัมน์ filename
                
                dataset.append(features) # เพิ่มข้อมูลคุณลักษณะลงใน dataset
            except Exception as e:
                print(f"Error processing {json_file}: {e}")
    
    return pd.DataFrame(dataset) # แปลง dataset เป็น DataFrame และคืนค่า



if __name__ == "__main__":
    df = process_malware_dataset() # เรียกใช้ฟังก์ชันเพื่อสร้าง dataset
    print(f"Dataset shape: {df.shape}")

    if not df.empty and 'label' in df.columns: # ตรวจสอบว่า dataset ไม่ว่างและมีคอลัมน์ 'label'
        print(f"Malware samples: {df['label'].sum()}")
        print(f"Safe samples: {len(df) - df['label'].sum()}")

        # ===== Export as CSV =====
        output_dir = os.path.join(os.getcwd(), "Dataset") # กำหนดโฟลเดอร์สำหรับบันทึก dataset
        os.makedirs(output_dir, exist_ok=True) # สร้างโฟลเดอร์ถ้ายังไม่มี
        output_file = os.path.join(output_dir, "malware_dataset.csv") # กำหนดชื่อไฟล์ CSV
        df.to_csv(output_file, index=False, encoding='utf-8') # บันทึก DataFrame เป็นไฟล์ CSV
        print(f"✅ Dataset saved to {output_file}")
    else:
        print("⚠️ Dataset ว่างหรือไม่มีคอลัมน์ 'label'")
