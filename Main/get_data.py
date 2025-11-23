import requests
import json
import os

MOBSF_URL = "http://localhost:8000"
# "http://localhost:8000"
# "http://100.85.4.118:8888" 
API_KEY ="bd54344feef27f85886aed8904ef23e8d775813680b743e339610e7d12457d34"
# "bd54344feef27f85886aed8904ef23e8d775813680b743e339610e7d12457d34"
# "b75bf63030e6cfab53811eb080d0be0c55d971f43345ccea68f09a5addd331da"
FILE_HASH_BANKER = [
    "3310f995682443b8d52a05f0ea42b942",
    "53f917ea05e9c340792217623a0ea74d",
    "b52f359e584fec7d53f2681545e00988",
    "2ed1579a7dc1113187998198d3da74db",
    "ebd947377d053f26ae3a02e31525f4cb",
    "2dfdce36a367b89b0de1a2ffc1052e24",
    "3a98fa552fdb6796cc64ad49f4ffad67",
    "20e116b9581eb7190aa22e5144358b9c",
    "f0a1475583278466b673ac902b664e42",
    "264f40a43f28b866f310e9ec527f9d2b"
]

FILE_HASH_TROJAN = [
    "e6ece4cfe94dade686c212fa8bda83e0",
    "3ae0f9cdc6472eb19a3126e5ec4410de",
    "315afc9faec4f56448771ef501f11d16",
    "3140c7447c97d5ea99a593f6ec2eb33c",
    "70c974b961c846ec08f7aa07501a97f7",
    "5d9345efba67d438c44c12696e6f802e",
    "8e83d178c1a3b9da0c71c613e2c77647",
    "7a3bfc8b91531cd09582c1e3571d1985",
    "1f382667d72b987cdd1d18b3beacc548",
    "7229dc5304cc5f9f5ec4e2af25512c53"
]

FILE_HASH_SPYWARE = [
    "48ab25bc1b06eaf2cbbdfed3c3127cea",
    "708445b8d358c254e861effffd4f819b",
    "39fca709b416d8da592de3a3f714dce8",
    "9452673652cee123f62a87f12e2894df",
    "113f3f9f4ef2d12919842f8b9849977a",
    "6fe08da2f19c3b16622aa00816199a8d",
    "2c0276d3d3d6f07d01e352dfbe0c5baa",
    "1cd72b1ded9e34810302fdc654e0ff5d",
    "4ce78163eef9d470b76e70676bf6f7b9",
    "4ab6bab65805838612f298f5e544b0c6"
]
FILE_HASH_TEST = [
    "fd0b81f3219af435570d2cc87e7022aa"
]
PATH = "Test"


def get_json():  
    try:
        response = requests.post(api_endpoint, headers=headers, data=data)
        if response.status_code == 200:
            report_data = response.json()

            os.makedirs("./Data/"+PATH, exist_ok=True)

            with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, ensure_ascii=False, indent=4)
            
            print(f"✅ ดาวน์โหลดรายงานสำเร็จ! บันทึกเป็นไฟล์ชื่อ: {OUTPUT_FILENAME}")
            
        else:
            print(f"❌ เกิดข้อผิดพลาด: {response.status_code}")
            print(f"ข้อความจาก Server: {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"❌ ไม่สามารถเชื่อมต่อกับ MOBSF server ได้: {e}")

for hash in FILE_HASH_TEST:
    OUTPUT_FILENAME = f"./Data/"+PATH+"/"+PATH+"_"+hash+".json"
    api_endpoint = f"{MOBSF_URL}/api/v1/report_json"
    headers = {"Authorization": API_KEY}
    print(f"กำลังดึงรายงานสำหรับ hash: {hash}")
    data = {"hash": hash};
    get_json();