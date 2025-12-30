import requests
import time
import json

MOBSF_URL = "http://127.0.0.1:8080"
API_KEY = "3008a014ab2f8cefe1ea5b5b063525bc907fcf73c7c30612e78a7a1b32d386fe"
APK_PATH = "ThaID_2.7.0_APKPure.xapk"
hash_value = "d8817b258b570da7e1443cc7e63e0f79"

headers = {
    "Authorization": API_KEY,
}

# ===== Get JSON Report =====
response = requests.post(
    f"{MOBSF_URL}/api/v1/report_json",
    headers=headers,
    data={"hash": hash_value}
)

if response.status_code == 200:
    analysis = response.json()
    print("✅ Scan Result Loaded")

    # ---- Save as .json file ----
    file_name = f"{hash_value}_mobsf_report.json"
    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=4, ensure_ascii=False)

    print(f"📁 File saved: {file_name}")

else:
    print("❌ Report Failed:", response.text)

