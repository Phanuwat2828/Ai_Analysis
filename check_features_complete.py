import json
import sys

# เปลี่ยน output ไปที่ไฟล์
output_file = open('feature_analysis_report.txt', 'w', encoding='utf-8')
sys.stdout = output_file

malware_file = 'Data/malware/16_25_独角兽号的秘密_下集.json'

with open(malware_file, 'r', encoding='utf-8') as f:
    data = json.load(f)

print("=" * 100)
print("MOBSF FEATURE ANALYSIS REPORT")
print("=" * 100)
print(f"\nTotal Keys in MobSF JSON: {len(data.keys())}")
print("\n" + "=" * 100)
print("ALL AVAILABLE KEYS:")
print("=" * 100)

for i, key in enumerate(sorted(data.keys()), 1):
    val = data[key]
    t = type(val).__name__

    extra = ""
    if isinstance(val, dict):
        extra = f"({len(val)} keys)"
    elif isinstance(val, list):
        extra = f"({len(val)} items)"
    elif isinstance(val, (int, float)):
        extra = f"= {val}"
    elif isinstance(val, str):
        extra = f'= "{val[:40]}..."' if len(val) > 40 else f'= "{val}"'

    print(f"{i:3}. {key:35} [{t:10}] {extra}")

# Features ที่ใช้แล้ว
current_features = {
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
}

print("\n" + "=" * 100)
print(f"CURRENT FEATURES EXTRACTED: {len(current_features)} features")
print("=" * 100)

# แนะนำ features เพิ่มเติม
print("\n" + "=" * 100)
print("RECOMMENDED ADDITIONAL FEATURES:")
print("=" * 100)

recommendations = []

# 1. Trackers
if 'trackers' in data:
    trackers = data['trackers']
    print(f"\n1. TRACKERS - Tracking libraries detected")
    print(f"   Type: {type(trackers).__name__}")
    print(f"   Count: {len(trackers)}")
    if trackers:
        print(f"   Sample keys: {list(trackers.keys())[:5]}")
    print(f"   Code: features['tracker_count'] = len(data.get('trackers', {{}}))")
    recommendations.append("tracker_count")

# 2. Secrets
if 'secrets' in data:
    secrets = data['secrets']
    print(f"\n2. SECRETS - Hardcoded secrets found")
    print(f"   Type: {type(secrets).__name__}")
    print(f"   Count: {len(secrets)}")
    if secrets:
        print(f"   Sample: {str(secrets[0])[:80]}")
    print(f"   Code: features['secrets_count'] = len(data.get('secrets', []))")
    recommendations.append("secrets_count")

# 3. Average CVSS
if 'average_cvss' in data:
    cvss = data['average_cvss']
    print(f"\n3. AVERAGE_CVSS - Vulnerability score")
    print(f"   Value: {cvss}")
    print(f"   Code: features['average_cvss'] = float(data.get('average_cvss', 0))")
    recommendations.append("average_cvss")

# 4. Malware Permissions
if 'malware_permissions' in data:
    mal_perms = data['malware_permissions']
    print(f"\n4. MALWARE_PERMISSIONS - Malware-specific permissions")
    print(f"   Type: {type(mal_perms).__name__}")
    if isinstance(mal_perms, (list, dict)):
        print(f"   Count: {len(mal_perms)}")
        if isinstance(mal_perms, list) and len(mal_perms) > 0:
            print(f"   Sample: {mal_perms[:3]}")
        elif isinstance(mal_perms, dict) and len(mal_perms) > 0:
            print(f"   Sample keys: {list(mal_perms.keys())[:3]}")
    print(f"   Code: features['malware_permission_count'] = len(data.get('malware_permissions', []))")
    recommendations.append("malware_permission_count")

# 5. Appsec
if 'appsec' in data:
    appsec = data['appsec']
    print(f"\n5. APPSEC - App security best practices")
    print(f"   Type: {type(appsec).__name__}")
    print(f"   Count: {len(appsec)}")
    if appsec:
        print(f"   Keys: {list(appsec.keys())[:5]}")
    print(f"   Code: features['appsec_issues_count'] = len(data.get('appsec', {{}}))")
    recommendations.append("appsec_issues_count")

# 6. Emails
if 'emails' in data:
    emails = data['emails']
    print(f"\n6. EMAILS - Email addresses found")
    print(f"   Count: {len(emails)}")
    print(f"   Code: features['email_count'] = len(data.get('emails', []))")
    recommendations.append("email_count")

# 7. Min/Target SDK
if 'min_sdk' in data and 'target_sdk' in data:
    print(f"\n7. SDK VERSIONS")
    print(f"   Min SDK: {data['min_sdk']}")
    print(f"   Target SDK: {data['target_sdk']}")
    print(f"   Code: features['min_sdk'] = int(data.get('min_sdk', 0))")
    print(f"   Code: features['target_sdk'] = int(data.get('target_sdk', 0))")
    recommendations.extend(["min_sdk", "target_sdk"])

# 8. Binary Analysis
if 'binary_analysis' in data:
    binary = data['binary_analysis']
    print(f"\n8. BINARY_ANALYSIS - Binary/native code findings")
    print(f"   Type: {type(binary).__name__}")
    print(f"   Count: {len(binary)}")
    print(f"   Code: features['binary_analysis_count'] = len(data.get('binary_analysis', []))")
    recommendations.append("binary_analysis_count")

# 9. Code Analysis - Warning
if 'code_analysis' in data:
    code = data['code_analysis']
    if 'summary' in code:
        summary = code['summary']
        print(f"\n9. CODE_ANALYSIS - Additional metrics")
        print(f"   High: {summary.get('high', 0)} (already extracted)")
        print(f"   Warning: {summary.get('warning', 0)} [NEW]")
        print(f"   Info: {summary.get('info', 0)} (already extracted)")
        print(f"   Code: features['has_code_warning'] = code_analysis.get('summary', {{}}).get('warning', 0)")
        recommendations.append("has_code_warning")

# 10. Manifest Analysis - Info
if 'manifest_analysis' in data:
    manifest = data['manifest_analysis']
    if 'manifest_summary' in manifest:
        summary = manifest['manifest_summary']
        print(f"\n10. MANIFEST_ANALYSIS - Additional metrics")
        print(f"   High: {summary.get('high', 0)} (already extracted)")
        print(f"   Warning: {summary.get('warning', 0)} (already extracted)")
        print(f"   Info: {summary.get('info', 0)} [NEW]")
        print(f"   Code: features['has_manifest_info'] = manifest.get('manifest_summary', {{}}).get('info', 0)")
        recommendations.append("has_manifest_info")

print("\n" + "=" * 100)
print("SUMMARY:")
print("=" * 100)
print(f"Current features: {len(current_features)}")
print(f"Recommended additional features: {len(recommendations)}")
print(f"Total potential features: {len(current_features) + len(recommendations)}")
print("\nRecommended features to add:")
for i, feat in enumerate(recommendations, 1):
    print(f"  {i}. {feat}")

print("\n" + "=" * 100)
print("ANALYSIS COMPLETE!")
print("=" * 100)

output_file.close()
print("Report saved to: feature_analysis_report.txt", file=sys.__stdout__)
