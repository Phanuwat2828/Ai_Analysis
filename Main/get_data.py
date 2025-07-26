import requests
import json
import os

MOBSF_URL = "http://100.85.4.118:8888"
API_KEY = "b75bf63030e6cfab53811eb080d0be0c55d971f43345ccea68f09a5addd331da"
FILE_HASH = "28ac5460e68eb83737ae2d3cd4f1d49f"
OUTPUT_FILENAME = f"./Data/report_{FILE_HASH}.json"

api_endpoint = f"{MOBSF_URL}/api/v1/report_json"
headers = {"Authorization": API_KEY}
data = {"hash": FILE_HASH}

print(f"กำลังดึงรายงานสำหรับ hash: {FILE_HASH}...")

try:
    response = requests.post(api_endpoint, headers=headers, data=data)

    if response.status_code == 200:
        report_data = response.json()

        # ✅ สร้างโฟลเดอร์ถ้ายังไม่มี
        os.makedirs("./Data", exist_ok=True)

        with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=4)
        
        print(f"✅ ดาวน์โหลดรายงานสำเร็จ! บันทึกเป็นไฟล์ชื่อ: {OUTPUT_FILENAME}")
        
    else:
        print(f"❌ เกิดข้อผิดพลาด: {response.status_code}")
        print(f"ข้อความจาก Server: {response.text}")

except requests.exceptions.RequestException as e:
    print(f"❌ ไม่สามารถเชื่อมต่อกับ MOBSF server ได้: {e}")
