import json

def extract_features_001(data):
    features = {}

    # 1. Basic info
    features["size_mb"] = float(data.get("size", "0MB").replace("MB", ""))
    def safe_int(val, default=0):
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    features["activities"] = len(data.get("activities", []))
    features["receivers"] = len(data.get("receivers", []))
    features["services"] = len(data.get("services", []))

    # 2. Permissions
    permissions = data.get("permissions", {})
    features["dangerous_permissions"] = sum(1 for p in permissions.values() if p["status"] == "dangerous")
    features["normal_permissions"] = sum(1 for p in permissions.values() if p["status"] == "normal")
    features["unknown_permissions"] = sum(1 for p in permissions.values() if p["status"] == "unknown")

    # Flag important permissions
    def has_perm(perm):
        return 1 if perm in permissions else 0

    features["has_camera"] = has_perm("android.permission.CAMERA")
    features["has_record_audio"] = has_perm("android.permission.RECORD_AUDIO")
    features["has_sms_permissions"] = any(has_perm(p) for p in [
        "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS", "android.permission.WRITE_SMS"
    ])
    features["has_contacts_permissions"] = has_perm("android.permission.READ_CONTACTS") or has_perm("android.permission.GET_ACCOUNTS")
    features["has_calllog_permissions"] = has_perm("android.permission.READ_CALL_LOG") or has_perm("android.permission.WRITE_CALL_LOG")
    features["system_alert_window"] = has_perm("android.permission.SYSTEM_ALERT_WINDOW")
    features["internet_access"] = has_perm("android.permission.INTERNET")

    # 3. Certificate analysis
    cert = data.get("certificate_analysis", {})
    cert_findings = cert.get("certificate_findings", [])
    features["certificate_v1_only"] = 0
    for fnd in cert_findings:
        if "v1 signature scheme" in fnd[1]:
            features["certificate_v1_only"] = 1

    # 4. Manifest analysis
    manifest = data.get("manifest_analysis", {})
    features["manifest_high"] = manifest.get("manifest_summary", {}).get("high", 0)
    features["manifest_warning"] = manifest.get("manifest_summary", {}).get("warning", 0)

    # 5. API usage
    api_usage = data.get("android_api", {})
    def has_api(key):
        return 1 if key in api_usage and api_usage[key].get("files") else 0

    features["uses_reflection"] = has_api("api_java_reflection")
    features["uses_dexloading"] = has_api("api_dexloading")
    features["uses_os_command"] = has_api("api_os_command")
    features["uses_sms_api"] = has_api("api_sms_call") or has_api("api_send_sms")
    features["uses_location_api"] = has_api("api_gps") or has_api("api_get_location")
    features["uses_network_api"] = has_api("api_http_connection") or has_api("api_tcp") or has_api("api_udp_datagram")

    suspicious_keys = [
        "api_java_reflection", "api_dexloading", "api_os_command",
        "api_sms_call", "api_send_sms", "api_gps", "api_get_location",
        "api_http_connection", "api_tcp", "api_udp_datagram"
    ]
    features["suspicious_api_count"] = sum(has_api(k) for k in suspicious_keys)

    # 6. Code analysis
    code_analysis = data.get("code_analysis", {})
    features["code_high"] = code_analysis.get("summary", {}).get("high", 0)
    features["code_warning"] = code_analysis.get("summary", {}).get("warning", 0)

    # 7. Network
    features["network_domains"] = len(data.get("domains", {}))

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
