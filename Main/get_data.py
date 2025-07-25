
import requests
import json

# --- ตั้งค่าตัวแปร ---
MOBSF_URL = "http://100.85.4.118:8888"
API_KEY = "b75bf63030e6cfab53811eb080d0be0c55d971f43345ccea68f09a5addd331da"  # <-- ใส่ API Key ของคุณที่นี่
FILE_HASH = "334edf9311e3cae6fab67cb7c9a81e00" # <-- ใส่ MD5 Hash ของไฟล์ที่สแกนแล้ว
OUTPUT_FILENAME = f"./Data/report_{FILE_HASH}.json"

# --- เตรียมข้อมูลสำหรับส่งไปยัง API ---
api_endpoint = f"{MOBSF_URL}/api/v1/report_json"
headers = {"Authorization": API_KEY}
data = {"hash": FILE_HASH}

print(f"กำลังดึงรายงานสำหรับ hash: {FILE_HASH}...")

try:
    # --- ส่ง Request ไปยัง MOBSF API ---
    response = requests.post(api_endpoint, headers=headers, data=data)

    # ตรวจสอบว่า API ตอบกลับมาสำเร็จ (HTTP Status Code 200)
    if response.status_code == 200:
        # แปลงผลลัพธ์ที่เป็นข้อความเป็น JSON object
        report_data = response.json()

        # บันทึก JSON ลงไฟล์
        with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=4)
        
        print(f"ดาวน์โหลดรายงานสำเร็จ! บันทึกเป็นไฟล์ชื่อ: {OUTPUT_FILENAME}")
        
    else:
        # หากไม่สำเร็จ ให้แสดงข้อความผิดพลาด
        print(f"เกิดข้อผิดพลาด: {response.status_code}")
        print(f"ข้อความจาก Server: {response.text}")

except requests.exceptions.RequestException as e:
    print(f"ไม่สามารถเชื่อมต่อกับ MOBSF server ได้: {e}")