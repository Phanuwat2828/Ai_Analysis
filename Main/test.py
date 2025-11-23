import pandas as pd

csv_path = "./data/latest.csv"

# คอลัมน์ที่อยากอ่าน
desired_cols = ["sha256", "pkg_name", "vercode", "vername", "dex_date", "vt_detection"]

# 🔹 ขั้นแรก: อ่านชื่อคอลัมน์จริงในไฟล์
header_cols = pd.read_csv(csv_path, nrows=0).columns.tolist()

# 🔹 เลือกเฉพาะคอลัมน์ที่มีอยู่จริง
available_cols = [c for c in desired_cols if c in header_cols]

print(f"🧩 พบคอลัมน์ในไฟล์: {header_cols}")
print(f"✅ จะอ่านเฉพาะคอลัมน์ที่มีอยู่จริง: {available_cols}\n")

chunk_size = 100000  # อ่านทีละ 1 แสนแถว

for chunk in pd.read_csv(csv_path, usecols=available_cols, chunksize=chunk_size):
    print(chunk.head())
    
    # ตรวจว่ามีคอลัมน์ vt_detection ก่อนกรอง
    if "vt_detection" in chunk.columns:
        malware = chunk[chunk["vt_detection"] > 0]
        print(f"พบมัลแวร์ {len(malware)} รายการในชุดข้อมูลนี้\n")
    else:
        print("⚠️ ไม่มีคอลัมน์ 'vt_detection' ในไฟล์นี้\n")
