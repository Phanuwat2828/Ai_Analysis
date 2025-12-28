import json
from pyexpat import features

def extract_features_001(data):
    features = {}

    # 1. Basic info
    features["size_mb"] = float(data.get("size", "0MB").replace("MB", "")) # ขนาดของไฟล์แอปพลิเคชัน 
    def safe_int(val, default=0): # function แปลงค่าเป็น int ถ้าแปลงไม่ได้จะคืนค่า default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    features["count_receivers"] = len(data.get("receivers", [])) # การนับจำนวน broadcast receivers ทั้งหมดที่อยู่ใน androidmanifest.xml Broadcast Receiver คือ ตัวดักฟังเหตุการณ์ในเครื่อง Android เช่นหน้าจอดับ แบตไกล้หมด sms ใหม่เข้ามา เป็นต้น
    features["count_services"] = len(data.get("services", [])) # การนับจำนวน services ทั้งหมดที่อยู่ใน androidmanifest.xml Service คือ ส่วนทำงานเบื้องหลังที่ทำงานโดยไม่ต้องมี UI เช่น การเล่นเพลง การดาวน์โหลดไฟล์ เป็นต้น
    features["count_providers"] = len(data.get("providers", [])) # การนับจำนวน content providers ทั้งหมดที่อยู่ใน androidmanifest.xml Content Provider คือ ส่วนที่จัดการข้อมูลและแชร์ข้อมูลระหว่างแอปพลิเคชันต่างๆ
    features["count_activities"] = len(data.get("activities", [])) # การนับจำนวน activities ทั้งหมดที่อยู่ใน androidmanifest.xml Activity คือ หน้าจอหรือ UI ที่ผู้ใช้โต้ตอบกับแอปพลิเคชัน
    exported = data.get("exported_count", {}) # ดึงข้อมูล exported components จาก JSON ที่ได้จาก MobSF
    features["count_exported_services"] = exported.get("exported_services", 0) # Services ที่ถูกตั้งค่าให้ export หรือเปิดเผยออกไปยังแอปพลิเคชันอื่นๆ ผ่าน Internet
    features["count_exported_receivers"] = exported.get("exported_receivers", 0) # Receivers ที่ถูกตั้งค่าให้ export หรือเปิดเผยออกไปยังแอปพลิเคชันอื่นๆ ผ่าน Internet
    features["count_exported_activities"] = exported.get("exported_activities", 0) # Activities ที่ถูกตั้งค่าให้ export หรือเปิดเผยออกไปยังแอปพลิเคชันอื่นๆ ผ่าน Internet
    # 2. Permissions
    permissions = data.get("permissions", {}) # ดึงข้อมูล permissions จาก JSON ที่ได้จาก MobSF
    features["count_dangerous_permissions"] = sum(1 for p in permissions.values() if p["status"] == "dangerous") # การนับจำนวน permissions ทีที่ classified เป็น “dangerous” ตัวอย่าง permissions dangerous เช่น android.permission.CAMERA, android.permission.RECORD_AUDIO
    features["count_normal_permissions"] = sum(1 for p in permissions.values() if p["status"] == "normal") # การนับจำนวน permissions ทีที่ classified เป็น “normal” ตัวอย่าง permissions normal เช่น android.permission.INTERNET, android.permission.ACCESS_NETWORK_STATE
    features["count_unknown_permissions"] = sum(1 for p in permissions.values() if p["status"] == "unknown") # การนับจำนวน permissions ทีที่ classified เป็น “unknown” ซึ่ง MobSF ไม่สามารถระบุได้ว่าปลอดภัยหรือไม่

    # Flag important permissions
    def has_perm(perm): # function ตรวจสอบว่า permission นั้นๆ ขอ permissions หรือไม่ 1 ถ้ามี 0 ถ้าไม่มี
        return 1 if perm in permissions else 0

    features["has_camera"] = has_perm("android.permission.CAMERA") # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงกล้องหรือไม่
    features["has_location_permissions"] = int(any(has_perm(p) for p in [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION"
    ])) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงตำแหน่งที่ตั้งหรือไม่
    features["has_sms_permissions"] = int( any(has_perm(p) for p in [
        "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS", "android.permission.WRITE_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_SMS"
    ])) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึง SMS หรือไม่
    features["has_microphone_permission"] = has_perm("android.permission.RECORD_AUDIO") # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงไมโครโฟนหรือไม่
    features["has_calllog_permissions"] = int(any(has_perm(p) for p in [
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
    ])) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงบันทึกการโทรหรือไม่
    features["has_phonecall_permission"] = int(any(has_perm(p) for p in [
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.USE_SIP",
        "android.permission.ADD_VOICEMAIL"
    ])) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์โทรออกหรือไม่
    features["has_contacts_permissions"] = int(any(has_perm(p) for p in [
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS"
    ])) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงรายชื่อผู้ติดต่อหรือไม่
    features["has_body_sensors_permission"] = int(has_perm("android.permission.BODY_SENSORS")) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงเซ็นเซอร์ร่างกายหรือไม่
    features["has_system_alert_window"] = int(has_perm("android.permission.SYSTEM_ALERT_WINDOW")) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์สร้างหน้าต่างแบบ System Alert หรือไม่
    features["has_storage_permissions"] = int(any(has_perm(p) for p in [
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE"
    ])) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงที่เก็บข้อมูลภายนอกหรือไม่


    # 3. Certificate analysis
    cert = data.get("certificate_analysis", {})
    info = cert.get("certificate_info", "")
    summary = cert.get("certificate_summary", {})
    features["has_cert_v1"] = int("v1 signature: True" in info)
    features["has_cert_v2"] = int("v2 signature: True" in info)
    features["has_cert_v3"] = int("v3 signature: True" in info)
    features["has_cert_v4"] = int("v4 signature: True" in info)
    features["has_certificate_high"] = summary.get("high", 0)
    features["has_certificate_warning"] = summary.get("warning", 0)
    features["has_certificate_info"] = summary.get("info", 0)

    # 4. Manifest analysis
    manifest = data.get("manifest_analysis", {}) # ดึง manifest analysis จาก JSON ที่
    features["has_manifest_high"] = manifest.get("manifest_summary", {}).get("high", 0) # จำนวนปัญหาระดับสูง (high) ที่พบใน manifest analysis 
    features["has_manifest_warning"] = manifest.get("manifest_summary", {}).get("warning", 0) # จำนวนปัญหาระดับเตือน (warning) ที่พบใน manifest analysis  

    # 5. API usage
    api_usage = data.get("android_api", {}) # ดึง android api usage จาก JSON ที่ได้จาก MobSF
    def has_api(key):
        return 1 if key in api_usage and api_usage[key].get("files") else 0 # function ตรวจสอบว่า API นั้นๆ ถูกใช้งานในแอปพลิเคชันหรือไม่ 1 ถ้าใช่ 0 ถ้าไม่ใช่

    features["has_uses_os_command"] = has_api("api_os_command") # ตรวจสอบว่าแอปพลิเคชันใช้ OS Command Execution API หรือไม่
    features["has_uses_sms_api"] = has_api("api_sms_call") or has_api("api_send_sms") # ตรวจสอบว่าแอปพลิเคชันใช้ SMS API หรือไม่

    suspicious_keys = [ # รายการ API ที่มักถูกใช้ในแอปพลิเคชันที่เป็นมัลแวร์
        "api_java_reflection", "api_dexloading", "api_os_command",
        "api_sms_call", "api_send_sms", "api_gps", "api_get_location",
        "api_http_connection", "api_tcp", "api_udp_datagram"
    ]
    features["has_suspicious_api_count"] = sum(has_api(k) for k in suspicious_keys) # นับจำนวน API ที่น่าสงสัยที่ถูกใช้งานในแอปพลิเคชัน

    # 6. Code analysis
    code_analysis = data.get("code_analysis", {}) # ดึง code analysis จาก JSON ที่ได้จาก MobSF
    features["has_code_high"] = code_analysis.get("summary", {}).get("high", 0) # จำนวนปัญหาระดับสูง (high) ที่พบใน code analysis
    features["has_code_info"] = code_analysis.get("summary", {}).get("info", 0) # จำนวนปัญหาระดับข้อมูล (info) ที่พบใน code analysis
    # 7 certificate analysis
    
    # 8. Network
    features["network_domains"] = len(data.get("domains", {})) # นับจำนวนโดเมนที่แอปพลิเคชันติดต่อ
    features["network_urls"] = len(data.get("urls", [])) # นับจำนวน URL ที่แอปพลิเคชันติดต่อ



    features["hardcoded_keystore"] = 0
    features["hardcoded_keystore_count"] = 0  # จำนวนไฟล์ที่เจอ

    file_analysis = data.get("file_analysis", [])

    for item in file_analysis:
        finding = item.get("finding", "").lower()
        files = item.get("files", [])
        if "hardcoded keystore" in finding:
            features["hardcoded_keystore"] = 1  # เจอ Hardcoded Keystore
            features["hardcoded_keystore_count"] += len(files)
    features["is_on_playstore"] = 1 if data.get("playstore_details") else 0

    # 9. Trackers - ตรวจจับ tracking libraries
    trackers_data = data.get("trackers", {})
    if isinstance(trackers_data, dict):
        tracker_list = trackers_data.get("trackers", [])
        features["tracker_count"] = len(tracker_list) if isinstance(tracker_list, list) else 0
    else:
        features["tracker_count"] = 0

    # 10. Secrets - hardcoded secrets (API keys, passwords, etc.)
    secrets = data.get("secrets", [])
    features["secrets_count"] = len(secrets) if isinstance(secrets, list) else 0

    # 11. Average CVSS - คะแนนความเสี่ยงจาก vulnerability
    cvss = data.get("average_cvss")
    features["average_cvss"] = float(cvss) if cvss and cvss != "null" else 0.0

    # 12. Malware Permissions - permissions ที่มัลแวร์มักใช้
    malware_perms = data.get("malware_permissions", {})
    if isinstance(malware_perms, dict):
        features["malware_permission_count"] = malware_perms.get("total_malware_permissions", 0)
    else:
        features["malware_permission_count"] = 0

    # 13. SDK Versions - Android SDK ที่รองรับ
    min_sdk_str = data.get("min_sdk", "0")
    target_sdk_str = data.get("target_sdk", "0")

    try:
        features["min_sdk"] = int(min_sdk_str) if min_sdk_str else 0
    except (ValueError, TypeError):
        features["min_sdk"] = 0

    try:
        features["target_sdk"] = int(target_sdk_str) if target_sdk_str else 0
    except (ValueError, TypeError):
        features["target_sdk"] = 0

    # 14. App Security (appsec) - app security best practices
    appsec = data.get("appsec", {})
    if isinstance(appsec, dict):
        # กรณีเป็น dict มี keys: high, warning, info ซึ่งเก็บเป็น list
        appsec_high_list = appsec.get("high", [])
        appsec_warning_list = appsec.get("warning", [])
        features["appsec_high"] = len(appsec_high_list) if isinstance(appsec_high_list, list) else 0
        features["appsec_warning"] = len(appsec_warning_list) if isinstance(appsec_warning_list, list) else 0
    else:
        features["appsec_high"] = 0
        features["appsec_warning"] = 0

    # 15. Email addresses found
    emails = data.get("emails", [])
    features["email_count"] = len(emails) if isinstance(emails, list) else 0

    # 16. Binary Analysis - native code findings
    binary_analysis = data.get("binary_analysis", [])
    features["binary_analysis_count"] = len(binary_analysis) if isinstance(binary_analysis, list) else 0

    # 17. Code Analysis - warning level (เพิ่มเติมจาก high, info)
    features["has_code_warning"] = code_analysis.get("summary", {}).get("warning", 0)

    # 18. Manifest Analysis - info level (เพิ่มเติมจาก high, warning)
    features["has_manifest_info"] = manifest.get("manifest_summary", {}).get("info", 0)

    return features

