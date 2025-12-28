import json
import os

# อ่านไฟล์ตัวอย่าง
malware_files = [
    'Data/malware/16_25_独角兽号的秘密_下集.json',
    'Data/malware/20_25_51达人.json',
    'Data/malware/49_25_火柴人摆POSE.json'
]

benign_files = [
    'Data/benign/SAFE_40_25_(V3)_Hoy_b.json',
    'Data/benign/SAFE_67_25_Vu.json',
    'Data/benign/SAFE_74_25_Hwki.json'
]

print("=" * 80)
print("ANALYZING MobSF JSON STRUCTURE")
print("=" * 80)

# โหลดไฟล์ตัวอย่างหนึ่งไฟล์
sample_file = malware_files[0]
with open(sample_file, 'r', encoding='utf-8') as f:
    sample_data = json.load(f)

print(f"\n[OK] Sample file loaded")
print(f"Total keys in MobSF JSON: {len(sample_data.keys())}\n")

# แสดง keys ทั้งหมด
print("=" * 80)
print("ALL AVAILABLE KEYS IN MobSF JSON:")
print("=" * 80)
for i, key in enumerate(sorted(sample_data.keys()), 1):
    value = sample_data[key]
    type_name = type(value).__name__

    # แสดงข้อมูลเพิ่มเติม
    extra_info = ""
    if isinstance(value, dict):
        extra_info = f"({len(value)} keys)"
    elif isinstance(value, list):
        extra_info = f"({len(value)} items)"
    elif isinstance(value, str):
        extra_info = f'"{value[:50]}..."' if len(value) > 50 else f'"{value}"'
    elif isinstance(value, (int, float)):
        extra_info = f"= {value}"

    print(f"{i:2}. {key:30} [{type_name:8}] {extra_info}")

print("\n" + "=" * 80)
print("DETAILED ANALYSIS OF IMPORTANT FIELDS:")
print("=" * 80)

# วิเคราะห์ fields ที่สำคัญ
important_fields = {
    'permissions': 'Permission analysis',
    'android_api': 'Android API usage',
    'code_analysis': 'Code quality issues',
    'manifest_analysis': 'AndroidManifest.xml issues',
    'certificate_analysis': 'Certificate/signing info',
    'file_analysis': 'File-level findings',
    'malware_permissions': 'Malware-specific permissions',
    'trackers': 'Tracking libraries detected',
    'secrets': 'Hardcoded secrets',
    'appsec': 'App security best practices',
    'network_security': 'Network security config',
    'binary_analysis': 'Binary/native code analysis',
    'average_cvss': 'CVSS vulnerability score',
    'virus_total': 'VirusTotal scan results',
    'strings': 'Extracted strings',
    'urls': 'URLs found',
    'domains': 'Domains contacted',
    'emails': 'Email addresses',
    'exported_count': 'Exported components count',
    'niap_analysis': 'NIAP compliance check'
}

for field, description in important_fields.items():
    if field in sample_data:
        value = sample_data[field]
        print(f"\n[OK] {field} - {description}")
        print(f"   Type: {type(value).__name__}")

        if isinstance(value, dict):
            if len(value) > 0:
                print(f"   Keys: {list(value.keys())[:10]}")
                # แสดงตัวอย่างข้อมูล
                for k in list(value.keys())[:3]:
                    v = value[k]
                    print(f"      - {k}: {type(v).__name__}")
        elif isinstance(value, list):
            print(f"   Count: {len(value)} items")
            if len(value) > 0:
                print(f"   Sample: {str(value[0])[:100]}")
        else:
            print(f"   Value: {str(value)[:150]}")
    else:
        print(f"\n[X] {field} - {description} (NOT FOUND)")

# เปรียบเทียบกับ features ที่ดึงแล้ว
print("\n" + "=" * 80)
print("FEATURE EXTRACTION COVERAGE:")
print("=" * 80)

current_features_classification = [
    "size_mb", "count_receivers", "count_services", "count_providers", "count_activities",
    "count_exported_services", "count_exported_receivers", "count_exported_activities",
    "count_dangerous_permissions", "count_normal_permissions", "count_unknown_permissions",
    "has_camera", "has_location_permissions", "has_sms_permissions", "has_microphone_permission",
    "has_calllog_permissions", "has_phonecall_permission", "has_contacts_permissions",
    "has_body_sensors_permission", "has_system_alert_window", "has_storage_permissions",
    "has_cert_v1", "has_cert_v2", "has_cert_v3", "has_cert_v4",
    "has_certificate_high", "has_certificate_warning", "has_certificate_info",
    "has_manifest_high", "has_manifest_warning",
    "has_uses_os_command", "has_uses_sms_api", "has_suspicious_api_count",
    "has_code_high", "has_code_info",
    "network_domains", "network_urls",
    "hardcoded_keystore", "hardcoded_keystore_count",
    "is_on_playstore"
]

current_features_regression = [
    "count_exported_services", "count_exported_receivers", "count_exported_activities",
    "count_dangerous_permissions", "count_normal_permissions", "count_unknown_permissions",
    "has_camera", "has_location_permissions", "has_sms_permissions", "has_microphone_permission",
    "has_calllog_permissions", "has_phonecall_permission", "has_contacts_permissions",
    "has_body_sensors_permission", "has_system_alert_window", "has_storage_permissions",
    "has_cert_v1", "has_cert_v2", "has_certificate_high",
    "has_manifest_high",
    "has_uses_os_command", "has_uses_sms_api", "has_suspicious_api_count"
]

print(f"\nClassification features: {len(current_features_classification)} features")
print(f"Regression features: {len(current_features_regression)} features")

# แนะนำ features เพิ่มเติม
print("\n" + "=" * 80)
print("RECOMMENDED ADDITIONAL FEATURES:")
print("=" * 80)

recommendations = [
    ("trackers", "Number of tracking libraries", "len(data.get('trackers', {}))"),
    ("secrets", "Number of hardcoded secrets", "len(data.get('secrets', []))"),
    ("average_cvss", "CVSS vulnerability score", "float(data.get('average_cvss', 0))"),
    ("emails", "Number of email addresses found", "len(data.get('emails', []))"),
    ("malware_permissions", "Malware-specific permission count", "len(data.get('malware_permissions', []))"),
    ("appsec", "App security issues count", "len(data.get('appsec', {}))"),
    ("min_sdk", "Minimum Android SDK version", "int(data.get('min_sdk', 0))"),
    ("target_sdk", "Target Android SDK version", "int(data.get('target_sdk', 0))"),
    ("binary_analysis", "Binary analysis findings", "len(data.get('binary_analysis', []))"),
    ("has_code_warning", "Code analysis warnings", "code_analysis.get('summary', {}).get('warning', 0)"),
    ("has_manifest_info", "Manifest analysis info", "manifest.get('manifest_summary', {}).get('info', 0)"),
]

for i, (field, desc, code) in enumerate(recommendations, 1):
    exists = field in sample_data
    status = "[OK]" if exists else "[X]"
    print(f"{i:2}. {status} {field:25} - {desc}")
    print(f"    Code: features['{field}'] = {code}")

print("\n" + "=" * 80)
print("Analysis Complete!")
print("=" * 80)
