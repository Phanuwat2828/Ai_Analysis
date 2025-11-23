import json

def extract_features(data):
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
