import json
from pyexpat import features

def extract_features_002(data):
    features = {}
    def status_info(str):
        if str == "info":
            return 0
        else :
            return 1
    # 1. Basic info
    features["size_mb"] = float(data.get("size", "0MB").replace("MB", "")) # ขนาดของไฟล์แอปพลิเคชัน 
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
    ]))

    # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงรายชื่อผู้ติดต่อหรือไม่
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
    # 7 binaly_analysis
    ba = data.get("binary_analysis", [])
    # print(ba)
    
    for _ in ba:
        for item in _:
            data_ = _.get(item, "")
            print(data_)
            
    summary = ba.get("info", {}) if isinstance(ba, dict) else {}
    features["has_binary_high"] = summary.get("high", 0)

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
    # 9 email
    features["hardcoded_email"] = len(data.get("emails", [])) # นับจำนวนอีเมลที่ฝังมาในแอปพลิเคชัน

    # 10 sdk
    features["min_sdk_version"] = int(data.get("min_sdk_version", 0)) # ดึงค่า min sdk version ของแอปพลิเคชัน
    features["target_sdk_version"] = int(data.get("target_sdk_version", 0)) # ดึงค่า target sdk version ของแอปพลิเคชัน

    # 11 appsec 
    features["appsec_issues_high"] = data.get("appsec_analysis", {}).get("summary", {}).get("high", 0) # จำนวนปัญหาระดับสูง (high) ที่พบใน appsec analysis
    features["appsec_issues_warning"] = data.get("appsec_analysis", {}).get("summary", {}).get("warning", 0) # จำนวนปัญหาระดับเตือน (warning) ที่พบใน appsec analysis

    # 12 average_cvss
    cvss_scores = data.get("cvss_scores", [])
    if cvss_scores:
        features["average_cvss"] = sum(cvss_scores) / len(cvss_scores)
    #13 tracker analysis
    features["tracker_count"] = len(data.get("tracker_analysis", {}).get("trackers", [])) # นับจำนวน tracker ที่พบในแอปพลิเคชัน

    #14 secret analysis
    features["secret_count"] = len(data.get("secret_analysis", {}).get("secrets", [])) # นับจำนวน secret ที่พบในแอปพลิเคชัน

    return features

def extract_features_001(data):
    features = {}
    # 1. Basic info
    features["size_mb"] = float(data.get("size", "0MB").replace("MB", "")) # ขนาดของไฟล์แอปพลิเคชัน 
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
    ]))

    # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงรายชื่อผู้ติดต่อหรือไม่
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
    # 7 android_api
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
    return features