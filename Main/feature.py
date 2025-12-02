import json

def extract_features_001(data):
    features = {}

    # 1. Basic info
    features["size_mb"] = float(data.get("size", "0MB").replace("MB", "")) # ขนาดของไฟล์แอปพลิเคชัน 
    def safe_int(val, default=0): # function แปลงค่าเป็น int ถ้าแปลงไม่ได้จะคืนค่า default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    features["activities"] = len(data.get("activities", [])) # การนับจำนวน activities ทั้งหมดทีที่อยู่ใน androidmanifest.xml Mobsf วิเคราะห์และเก็บค่าไว้ Activities คือส่วนประกอบของแอปพลิเคชันที่แสดง UI และตอบสนองต่อการโต้ตอบของผู้ใช้ว่ามีกี่หน้า
    features["receivers"] = len(data.get("receivers", [])) # การนับจำนวน broadcast receivers ทั้งหมดที่อยู่ใน androidmanifest.xml Broadcast Receiver คือ ตัวดักฟังเหตุการณ์ในเครื่อง Android เช่นหน้าจอดับ แบตไกล้หมด sms ใหม่เข้ามา เป็นต้น
    features["services"] = len(data.get("services", [])) # การนับจำนวน services ทั้งหมดที่อยู่ใน androidmanifest.xml Service คือ ส่วนทำงานเบื้องหลังที่ทำงานโดยไม่ต้องมี UI เช่น การเล่นเพลง การดาวน์โหลดไฟล์ เป็นต้น
    features["providers"] = len(data.get("providers", [])) # การนับจำนวน content providers ทั้งหมดที่อยู่ใน androidmanifest.xml Content Provider คือ ส่วนที่จัดการข้อมูลและแชร์ข้อมูลระหว่างแอปพลิเคชันต่างๆ
    exported = data.get("exported_components", {}) # ดึงข้อมูล exported components จาก JSON ที่ได้จาก MobSF
    features["exported_activities"] = exported.get("exported_activities", 0) # Activities ที่ถูกตั้งค่าให้ export หรือเปิดเผยออกไปยังแอปพลิเคชันอื่นๆ ผ่าน Internet
    features["exported_services"] = exported.get("exported_services", 0) # Services ที่ถูกตั้งค่าให้ export หรือเปิดเผยออกไปยังแอปพลิเคชันอื่นๆ ผ่าน Internet
    features["exported_receivers"] = exported.get("exported_receivers", 0) # Broadcast Receivers ที่ถูกตั้งค่าให้ export หรือเปิดเผยออกไปยังแอปพลิเคชันอื่นๆ ผ่าน Internet

    # 2. Permissions
    permissions = data.get("permissions", {}) # ดึงข้อมูล permissions จาก JSON ที่ได้จาก MobSF
    features["dangerous_permissions"] = sum(1 for p in permissions.values() if p["status"] == "dangerous") # การนับจำนวน permissions ทีที่ classified เป็น “dangerous” ตัวอย่าง permissions dangerous เช่น android.permission.CAMERA, android.permission.RECORD_AUDIO
    features["normal_permissions"] = sum(1 for p in permissions.values() if p["status"] == "normal") # การนับจำนวน permissions ทีที่ classified เป็น “normal” ตัวอย่าง permissions normal เช่น android.permission.INTERNET, android.permission.ACCESS_NETWORK_STATE
    features["unknown_permissions"] = sum(1 for p in permissions.values() if p["status"] == "unknown") # การนับจำนวน permissions ทีที่ classified เป็น “unknown” ซึ่ง MobSF ไม่สามารถระบุได้ว่าปลอดภัยหรือไม่

    # Flag important permissions
    def has_perm(perm): # function ตรวจสอบว่า permission นั้นๆ ขอ permissions หรือไม่ 1 ถ้ามี 0 ถ้าไม่มี
        return 1 if perm in permissions else 0

    features["has_camera"] = has_perm("android.permission.CAMERA") # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงกล้องหรือไม่
    features["has_record_audio"] = has_perm("android.permission.RECORD_AUDIO") # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงไมโครโฟนหรือไม่
    features["has_location_permissions"] = any(has_perm(p) for p in [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION"
    ]) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงตำแหน่งที่ตั้งหรือไม่
    features["has_sms_permissions"] = any(has_perm(p) for p in [
        "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS", "android.permission.WRITE_SMS"
    ]) # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึง SMS หรือไม่
    
    features["has_contacts_permissions"] = has_perm("android.permission.READ_CONTACTS") or has_perm("android.permission.GET_ACCOUNTS") # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงรายชื่อผู้ติดต่อหรือไม่
    features["has_calllog_permissions"] = has_perm("android.permission.READ_CALL_LOG") or has_perm("android.permission.WRITE_CALL_LOG") # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงบันทึกการโทรหรือไม่
    features["has_external_storage"] = has_perm("android.permission.WRITE_EXTERNAL_STORAGE") or has_perm("android.permission.READ_EXTERNAL_STORAGE") # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงหน่วยความจำภายนอกหรือไม่
    features["system_alert_window"] = has_perm("android.permission.SYSTEM_ALERT_WINDOW") # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์สร้างหน้าต่างแบบ System Alert หรือไม่
    features["internet_access"] = has_perm("android.permission.INTERNET") # ตรวจสอบว่าแอปพลิเคชันขอสิทธิ์เข้าถึงอินเทอร์เน็ตหรือไม่

    # 3. Certificate analysis
    cert = data.get("certificate_analysis", {}) # ดึง certificate analysis จาก JSON ที่ได้จาก MobSF
    cert_findings = cert.get("certificate_findings", []) # ดึงรายการ certificate findings จะบอกว่าใช้ signature แบบไหน เช่น v1 android 1.0-6.0, v2 android 8.0 + , v3 android 9.0+ หรือใช้ hash algorithm แบบไหน เช่น SHA1, SHA256
    features["certificate_v1_only"] = 0  # flag ว่าใช้แค่ v1 signature scheme หรือไม่
    for fnd in cert_findings: # วนลูปตรวจสอบ findings ต่างๆ ใน certificate analysis
        if "v1 signature scheme" in fnd[1]:
            features["certificate_v1_only"] = 1

    # 4. Manifest analysis
    manifest = data.get("manifest_analysis", {}) # ดึง manifest analysis จาก JSON ที่ได้จาก MobSF
    features["manifest_high"] = manifest.get("manifest_summary", {}).get("high", 0) # จำนวนปัญหาระดับสูง (high) ที่พบใน manifest analysis 
    features["manifest_warning"] = manifest.get("manifest_summary", {}).get("warning", 0) # จำนวนปัญหาระดับเตือน (warning) ที่พบใน manifest analysis

    # 5. API usage
    api_usage = data.get("android_api", {}) # ดึง android api usage จาก JSON ที่ได้จาก MobSF
    def has_api(key):
        return 1 if key in api_usage and api_usage[key].get("files") else 0 # function ตรวจสอบว่า API นั้นๆ ถูกใช้งานในแอปพลิเคชันหรือไม่ 1 ถ้าใช่ 0 ถ้าไม่ใช่

    features["uses_reflection"] = has_api("api_java_reflection") # ตรวจสอบว่าแอปพลิเคชันใช้ Java Reflection API หรือไม่
    features["uses_dexloading"] = has_api("api_dexloading") # ตรวจสอบว่าแอปพลิเคชันใช้ Dex Loading API หรือไม่
    features["uses_os_command"] = has_api("api_os_command") # ตรวจสอบว่าแอปพลิเคชันใช้ OS Command Execution API หรือไม่
    features["uses_sms_api"] = has_api("api_sms_call") or has_api("api_send_sms") # ตรวจสอบว่าแอปพลิเคชันใช้ SMS API หรือไม่
    features["uses_location_api"] = has_api("api_gps") or has_api("api_get_location") # ตรวจสอบว่าแอปพลิเคชันใช้ Location API หรือไม่
    features["uses_network_api"] = has_api("api_http_connection") or has_api("api_tcp") or has_api("api_udp_datagram") # ตรวจสอบว่าแอปพลิเคชันใช้ Network API หรือไม่

    suspicious_keys = [ # รายการ API ที่มักถูกใช้ในแอปพลิเคชันที่เป็นมัลแวร์
        "api_java_reflection", "api_dexloading", "api_os_command",
        "api_sms_call", "api_send_sms", "api_gps", "api_get_location",
        "api_http_connection", "api_tcp", "api_udp_datagram"
    ]
    features["suspicious_api_count"] = sum(has_api(k) for k in suspicious_keys) # นับจำนวน API ที่น่าสงสัยที่ถูกใช้งานในแอปพลิเคชัน

    # 6. Code analysis
    code_analysis = data.get("code_analysis", {}) # ดึง code analysis จาก JSON ที่ได้จาก MobSF
    features["code_high"] = code_analysis.get("summary", {}).get("high", 0) # จำนวนปัญหาระดับสูง (high) ที่พบใน code analysis
    features["code_warning"] = code_analysis.get("summary", {}).get("warning", 0) # จำนวนปัญหาระดับเตือน (warning) ที่พบใน code analysis

    # 7. Network
    features["network_domains"] = len(data.get("domains", {})) # นับจำนวนโดเมนที่แอปพลิเคชันติดต่อ
    features["network_urls"] = len(data.get("urls", [])) # นับจำนวน URL ที่แอปพลิเคชันติดต่อ


    return features

def extract_features_002(data):
    features = {}

    def safe_int(val, default=0):
        try:
            return int(val)
        except:
            return default

    # -----------------------------------------------
    # 1. Basic Info
    # -----------------------------------------------
    features["size_mb"] = float(data.get("size", "0MB").replace("MB", ""))
    features["activities"] = len(data.get("activities", []))
    features["receivers"] = len(data.get("receivers", []))
    features["services"] = len(data.get("services", []))
    features["providers"] = len(data.get("providers", []))

    # -----------------------------------------------
    # 2. Permissions
    # -----------------------------------------------
    permissions = data.get("permissions", {})

    features["dangerous_perm_count"] = sum(1 for p in permissions.values() if p["status"] == "dangerous")
    features["normal_perm_count"] = sum(1 for p in permissions.values() if p["status"] == "normal")
    features["unknown_perm_count"] = sum(1 for p in permissions.values() if p["status"] == "unknown")
    features["dangerous_permissions"] = sum(1 for p in permissions.values() if p["status"] == "dangerous")
    # permission ratio
    total_perm = len(permissions)
    features["dangerous_ratio"] = features["dangerous_perm_count"] / total_perm if total_perm > 0 else 0
    
    def has_perm(perm):
        return 1 if perm in permissions else 0

    # common malware permissions
    suspicious_perm = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_CONTACTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    ]
    features["suspicious_permission_hits"] = sum(has_perm(p) for p in suspicious_perm)
    features["has_record_audio"] = has_perm("android.permission.RECORD_AUDIO")
    # -----------------------------------------------
    # 3. Certificate Analysis
    # -----------------------------------------------
    cert = data.get("certificate_analysis", {})
    cert_findings = cert.get("certificate_findings", [])

    features["is_v1_signature"] = 0
    features["uses_sha1"] = 0
    features["cert_warnings"] = len(cert_findings)

    for finding in cert_findings:
        msg = str(finding).lower()
        if "v1 signature scheme" in msg:
            features["is_v1_signature"] = 1
        if "sha1" in msg:
            features["uses_sha1"] = 1

    # -----------------------------------------------
    # 4. Manifest Analysis
    # -----------------------------------------------
    manifest = data.get("manifest_analysis", {})

    features["manifest_high"] = manifest.get("manifest_summary", {}).get("high", 0)
    features["manifest_warning"] = manifest.get("manifest_summary", {}).get("warning", 0)

    exported_components = manifest.get("exported_components", {})
    features["exported_activities"] = len(exported_components.get("activities", []))
    features["exported_services"] = len(exported_components.get("services", []))
    features["exported_receivers"] = len(exported_components.get("receivers", []))

    # -----------------------------------------------
    # 5. API Usage
    # -----------------------------------------------
    api_usage = data.get("android_api", {})
    
    def has_api(k):
        return 1 if k in api_usage and api_usage[k].get("files") else 0

    suspicious_apis = [
        "api_java_reflection",
        "api_dexloading",
        "api_crypto",
        "api_os_command",
        "api_root_detection",
        "api_gps",
        "api_http_connection",
        "api_send_sms",
        "api_sms_call",
    ]
    features["uses_dexloading"] = has_api("api_dexloading")
    features["uses_reflection"] = has_api("api_java_reflection")
    features["uses_os_command"] = has_api("api_os_command")

    for api in suspicious_apis:
        features[f"use_{api}"] = has_api(api)

    features["suspicious_api_count"] = sum(has_api(a) for a in suspicious_apis)

    # -----------------------------------------------
    # 6. Code Analysis
    # -----------------------------------------------
    code_analysis = data.get("code_analysis", {})

    features["code_high"] = code_analysis.get("summary", {}).get("high", 0)
    features["code_warning"] = code_analysis.get("summary", {}).get("warning", 0)

    # suspicious strings in code
    suspicious_strings = ["chmod", "exec", "su", "keylogger", "base64", "shell", "/system/bin/"]
    found_strings = code_analysis.get("findings", [])

    features["dangerous_string_hits"] = sum(
        1 for s in suspicious_strings if any(s in str(item).lower() for item in found_strings)
    )

    # -----------------------------------------------
    # 7. Network
    # -----------------------------------------------
    domains = data.get("domains", {})
    urls = data.get("urls", [])

    features["domain_count"] = len(domains)
    features["url_count"] = len(urls)

    # count suspicious TLD
    sus_tld = [".ru", ".cn", ".pw", ".su"]
    features["suspicious_domain_hits"] = sum(1 for d in domains if any(t in d for t in sus_tld))

    # -----------------------------------------------
    return features
