import glob
import json
import os
from feature import extract_features_001 as extract_features

BASE_PATH = os.path.abspath(os.path.join(os.getcwd(), "."))

malware_files = glob.glob(os.path.join(BASE_PATH, "Data", "malware", "*.json"))
benign_files  = glob.glob(os.path.join(BASE_PATH, "Data", "benign", "*.json"))

# ลิสต์ feature ตามลำดับที่คุณต้องการ
feature_order = [
    "binary_count",
    "binary_has_rpath",
    "binary_has_runpath",
    "binary_no_canary",
    "binary_no_fortify",
    "binary_no_nx",
    "binary_no_relro",
    "binary_not_pie",
    "binary_symbol_not_stripped",
    "count_activities",
    "count_dangerous_permissions",
    "count_exported_activities",
    "count_exported_receivers",
    "count_exported_services",
    "count_normal_permissions",
    "count_providers",
    "count_receivers",
    "count_services",
    "count_unknown_permissions",
    "hardcoded_keystore",
    "hardcoded_keystore_count",
    "has_body_sensors_permission",
    "has_calllog_permissions",
    "has_camera",
    "has_cert_v1",
    "has_cert_v2",
    "has_cert_v3",
    "has_cert_v4",
    "has_certificate_high",
    "has_certificate_info",
    "has_certificate_warning",
    "has_code_high",
    "has_code_info",
    "has_contacts_permissions",
    "has_location_permissions",
    "has_manifest_high",
    "has_manifest_warning",
    "has_microphone_permission",
    "has_phonecall_permission",
    "has_sms_permissions",
    "has_storage_permissions",
    "has_suspicious_api_count",
    "has_system_alert_window",
    "has_uses_os_command",
    "has_uses_sms_api",
    "is_on_playstore",
    "network_domains",
    "network_urls",
    "size_mb"
]

def debug(json_path, label):
    print("\n==============================")
    print(f"FILE: {os.path.basename(json_path)} ({label})")
    print("==============================")

    with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
        data = json.load(f)

    features = extract_features(data)

    print(f"\nจำนวน feature: {len(features)}\n")

    # Loop ตามลำดับ feature ที่กำหนด
    for idx, feat in enumerate(feature_order, start=1):
        value = features.get(feat, None)
        # print(f"{idx:02d}| {feat:35} : {value}")
        print(value)

# ใช้แค่ไฟล์แรกของแต่ละโฟลเดอร์
debug(malware_files[0], "malware")
debug(benign_files[0], "benign")


