

folders = ['Banker', 'Spyware', 'Trojan','Safe']

import json

permissions_list = ['SEND_SMS', 'READ_CONTACTS', 'INTERNET', 'ACCESS_FINE_LOCATION', 'CAMERA']
api_calls_list = ['Runtime.exec', 'DexClassLoader', 'Reflection', 'exec', 'getExternalStorage']
network_hosts_list = ['http', 'https', 'ftp']
activities_services_list = ['MainActivity', 'Service', 'Receiver']
security_issues_list = ['Weak Encryption', 'Hardcoded Credentials', 'Insecure Communication']

def extract_features_from_json(json_data):
    features = {}

    # 1. Dangerous Permissions
    try:
        permissions_raw = json_data.get('permissions', {})
        dangerous = [v for v in permissions_raw.values() if v.get('status') == 'dangerous']
        features['dangerous_permissions_count'] = len(dangerous)
    except:
        features['dangerous_permissions_count'] = 0

    # 2. High & Medium Severity Vulnerabilities from manifest and certificate
    try:
        manifest_findings = json_data.get('manifest_analysis', {}).get('manifest_findings', [])
        features['high_severity_vulns'] = sum(1 for x in manifest_findings if x.get('severity') == 'high')
        features['medium_severity_vulns'] = sum(1 for x in manifest_findings if x.get('severity') == 'medium')
    except:
        features['high_severity_vulns'] = 0
        features['medium_severity_vulns'] = 0

    try:
        cert_summary = json_data.get('certificate_analysis', {}).get('certificate_summary', {})
        features['high_severity_vulns'] += cert_summary.get('high', 0)
        features['medium_severity_vulns'] += cert_summary.get('warning', 0)
    except:
        pass

    # 3. AllowBackup & Debuggable
    findings = json_data.get('manifest_analysis', {}).get('manifest_findings', [])
    features['is_allow_backup'] = int(any('allowbackup' in f.get('title', '').lower() and f.get('severity') == 'high' for f in findings))
    features['is_debuggable'] = int(any('debuggable' in f.get('title', '').lower() and f.get('severity') == 'high' for f in findings))

    # 4. Obfuscation & Reflection
    try:
        code_str = json.dumps(json_data.get("code_analysis", {})).lower()
        features['uses_reflection'] = int('reflection' in code_str)
        features['uses_obfuscation'] = int('obfuscation' in code_str)
    except:
        features['uses_reflection'] = 0
        features['uses_obfuscation'] = 0

    # 5. VirusTotal Summary (if exists)
    vt = json_data.get('virus_total_summary', {})
    try:
        features['virustotal_positives'] = vt.get('positives', 0)
        features['virustotal_total'] = vt.get('total', 1)
        features['virustotal_ratio'] = features['virustotal_positives'] / features['virustotal_total']
    except:
        features['virustotal_positives'] = 0
        features['virustotal_ratio'] = 0.0

    # 6. Binary Flags (Native, Java Debug, Cleartext)
    binary_flags = {
        'uses_native': 'lib/' in json.dumps(json_data.get('binary_analysis', [])).lower(),
        'uses_java_debug': False,  # MobSF JSON ไม่มี uses_java_debug
        'uses_cleartext': any('cleartext' in f.get('title', '').lower() for f in findings)
    }
    for k, v in binary_flags.items():
        features[k] = int(v)

    # 7. Trackers (best-effort)
    features['has_tracker'] = 0  # Not found in this JSON

    # 8. Suspicious URLs
    url_list = json_data.get('urls', [])
    suspicious = []

    for item in url_list:
        if isinstance(item, dict):
            url = item.get('url', '')
        elif isinstance(item, str):
            url = item
        else:
            continue

        if any(tld in url for tld in ['.ru', '.cn', '.xyz']) or (url.startswith('http://') and '127.0.0.1' not in url):
            suspicious.append(url)

    features['suspicious_url_count'] = len(suspicious)

    # 9. Exported Components
    for comp in ['activities', 'services', 'receivers', 'providers']:
        comp_list = json_data.get(comp, [])
        features[f'exported_{comp}_count'] = sum(1 for c in comp_list if isinstance(c, dict) and c.get('exported') is True)
    features['exported_components_total'] = sum(features[f'exported_{c}_count'] for c in ['activities', 'services', 'receivers', 'providers'])

    # 10. Dangerous API Calls
    features['uses_exec'] = int('exec(' in code_str or 'runtime.getruntime().exec' in code_str)
    features['uses_system_exit'] = int('system.exit' in code_str)

    # 11. Crypto API
    features['uses_md5'] = int('md5' in code_str)
    features['uses_des'] = int('des' in code_str)

    # 12. Suspicious Strings
    all_text = json.dumps(json_data).lower()
    for s in ['root', 'shell', 'inject']:
        features[f'has_{s}_string'] = int(s in all_text)

    # 13. Dynamic Behavior & Frequency Features
    features['api_call_count'] = sum(1 for api in ['exec', 'runtime.exec', 'system.exit'] if api in code_str)

    # 14. Rooting Detection (if exists)
    features['is_rooted'] = int(any(keyword in all_text for keyword in ['root', 'su', 'busybox']))

    return features
