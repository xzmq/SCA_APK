"""
extract_risk_profile.py - Risk profile: data_classification, risk_dimension_scores,
advertisement_analysis, attack_profile.
Depends on sub01-03 output JSON files.
Usage: python extract_risk_profile.py <output_dir> <sub01_dir> <sub02_dir> <sub03_dir>
"""
import os
import sys
import json
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import androguard_extractor

# Module-level APK path for androguard fallback in code search
_apk_path = None
from config import *
from common import *
from jadx_extractor import (
    get_all_classes, get_strings, get_main_application_classes_names,
    search_code_for_pattern, get_android_manifest,
)


def extract_data_classification(sub_data):
    """Build data_classification from sub01-03 results."""
    result = []

    mb = sub_data.get("malicious_behavior", {})
    c2 = sub_data.get("c2_communication", {})
    perms = sub_data.get("permissions", {})
    code = sub_data.get("code_analysis", {})

    # SMS stealing
    if mb.get("sms_intercept_via_broadcast") or mb.get("sms_intercept_via_content_observer"):
        result.append({
            "category": "短信窃取",
            "subcategory": "ContentObserver实时监控" if mb.get("sms_intercept_via_content_observer") else "广播拦截",
            "is_confirmed": True,
            "evidence": "检测到短信拦截行为，涉及广播和/或ContentObserver",
            "risk_level": "CRITICAL",
        })

    # SMS delete capability
    if mb.get("sms_delete_capability"):
        result.append({
            "category": "短信删除",
            "subcategory": "ContentResolver.delete操作",
            "is_confirmed": True,
            "evidence": "检测到ContentResolver.delete对content://sms的删除操作",
            "risk_level": "HIGH",
        })

    # Device info collection / data exfiltration
    if mb.get("data_exfiltration") or mb.get("device_fingerprint_collection"):
        details = mb.get("device_fingerprint_details", [])
        fields = ", ".join(d.get("field_name", "") for d in details if d.get("field_name"))
        cat = "数据外传" if mb.get("data_exfiltration") else "设备信息采集"
        result.append({
            "category": cat,
            "subcategory": fields if fields else "设备标识",
            "is_confirmed": True,
            "evidence": f"检测到采集以下字段: {fields}" if fields else "检测到数据外传行为",
            "risk_level": "CRITICAL" if mb.get("data_exfiltration") else "HIGH",
        })

    # Call forwarding
    if mb.get("call_forwarding"):
        result.append({
            "category": "呼叫转移劫持",
            "subcategory": "setCallForward操作",
            "is_confirmed": True,
            "evidence": "检测到setCallForward/CF_ENABLE/GSM_CALL_FORWARD呼叫转移设置",
            "risk_level": "HIGH",
        })

    # C2 communication (has_c2_communication boolean + c2.has_c2)
    if mb.get("has_c2_communication") or c2.get("has_c2"):
        servers = c2.get("c2_servers", [])
        urls = ", ".join(s.get("url", "")[:50] for s in servers[:3])
        result.append({
            "category": "C2通信",
            "subcategory": "HTTP POST + JSON封装" if c2.get("c2_communication_pattern", {}).get("uses_http_url_connection") else "网络通信",
            "is_confirmed": True,
            "evidence": f"URL: {urls}" if urls else "检测到硬编码URL与网络请求组合",
            "risk_level": "CRITICAL",
        })

    # Dynamic code loading
    if mb.get("dynamic_code_loading"):
        result.append({
            "category": "动态DEX加载隐藏载荷",
            "subcategory": "DexClassLoader/PathClassLoader",
            "is_confirmed": True,
            "evidence": "检测到DexClassLoader/PathClassLoader/loadDex动态加载DEX",
            "risk_level": "HIGH",
        })

    # Encryption hardcoded key
    if mb.get("encryption_hardcoded_key"):
        result.append({
            "category": "硬编码加密",
            "subcategory": "Cipher.getInstance硬编码密钥",
            "is_confirmed": True,
            "evidence": "检测到Cipher.getInstance配合硬编码SecretKeySpec/DES密钥",
            "risk_level": "HIGH",
        })

    # Encrypted C2
    if c2.get("encrypted_c2_indicators"):
        result.append({
            "category": "加密混淆",
            "subcategory": "加密C2 URL",
            "is_confirmed": True,
            "evidence": "C2 URL被加密存储，运行时解密",
            "risk_level": "HIGH",
        })

    # Persistence
    if mb.get("boot_persistence") or mb.get("service_keepalive"):
        result.append({
            "category": "持久化驻留",
            "subcategory": "Service保活" if mb.get("service_keepalive") else "开机自启",
            "is_confirmed": True,
            "evidence": "检测到保活机制和/或开机自启",
            "risk_level": "HIGH",
        })

    # Anti-detection
    if mb.get("root_emulator_detection") or code.get("anti_analysis"):
        methods = code.get("anti_analysis", [])
        result.append({
            "category": "反检测对抗",
            "subcategory": ", ".join(methods) if methods else "环境检测",
            "is_confirmed": True,
            "evidence": f"检测到以下反分析手段: {', '.join(methods)}",
            "risk_level": "MEDIUM",
        })

    # Overlay phishing
    if mb.get("overlay_phishing"):
        result.append({
            "category": "钓鱼攻击",
            "subcategory": "悬浮窗覆盖",
            "is_confirmed": True,
            "evidence": "检测到TYPE_APPLICATION_OVERLAY和WindowManager使用",
            "risk_level": "CRITICAL",
        })

    return result


def extract_risk_dimension_scores(sub_data):
    """Calculate risk scores across dimensions."""
    result = dict(RISK_DIMENSION_SCORES_DEFAULT)

    mb = sub_data.get("malicious_behavior", {})
    c2 = sub_data.get("c2_communication", {})
    code = sub_data.get("code_analysis", {})
    perms = sub_data.get("permissions", {})

    # data_exfiltration score
    ex_score = 0
    ex_evidence = []
    if c2.get("has_c2"):
        ex_score += 3
        ex_evidence.append("存在C2通信")
    if mb.get("data_exfiltration"):
        ex_score += 3
        ex_evidence.append("数据外传行为确认")
    if mb.get("device_fingerprint_collection"):
        ex_score += 2
        ex_evidence.append("设备指纹收集")
    if c2.get("c2_communication_pattern", {}).get("uses_http_cleartext"):
        ex_score += 1
        ex_evidence.append("明文HTTP传输")
    ex_score = min(ex_score, 10)
    result["data_exfiltration"] = {"score": ex_score, "out_of": 10, "risk_level": _score_to_level(ex_score), "evidence": "; ".join(ex_evidence)}

    # c2_remote_control score
    c2_score = 0
    c2_evidence = []
    if c2.get("has_c2"):
        c2_score += 3
        c2_evidence.append("存在C2服务器")
    if mb.get("has_c2_communication"):
        c2_score += 3
        c2_evidence.append("C2远程控制通信")
    if c2.get("c2_commands"):
        c2_score += 2
        c2_evidence.append("存在C2指令集")
    if code.get("has_dynamic_dex_loading") or mb.get("dynamic_code_loading"):
        c2_score += 2
        c2_evidence.append("动态DEX加载")
    c2_score = min(c2_score, 10)
    result["c2_remote_control"] = {"score": c2_score, "out_of": 10, "risk_level": _score_to_level(c2_score), "evidence": "; ".join(c2_evidence)}

    # data_steal score
    ds_score = 0
    ds_evidence = []
    if mb.get("sms_intercept_via_broadcast") or mb.get("sms_intercept_via_content_observer"):
        ds_score += 3
        ds_evidence.append("短信窃取")
    if mb.get("sms_delete_capability"):
        ds_score += 2
        ds_evidence.append("短信删除能力")
    if mb.get("call_forwarding"):
        ds_score += 2
        ds_evidence.append("呼叫转移劫持")
    if perms.get("dangerous_perm_count", 0) > 5:
        ds_score += 2
        ds_evidence.append("大量危险权限")
    if mb.get("device_fingerprint_collection") or mb.get("data_exfiltration"):
        ds_score += 2
        ds_evidence.append("数据外传/设备信息采集")
    ds_score = min(ds_score, 10)
    result["data_steal"] = {"score": ds_score, "out_of": 10, "risk_level": _score_to_level(ds_score), "evidence": "; ".join(ds_evidence)}

    # encryption_obfuscation score
    eo_score = 0
    eo_evidence = []
    if code.get("is_code_obfuscated"):
        eo_score += 2
        eo_evidence.append("代码混淆")
    if code.get("string_encryption"):
        eo_score += 2
        eo_evidence.append("字符串加密")
    if code.get("weak_cryptographic_algorithms"):
        eo_score += 1
        eo_evidence.append("弱加密算法")
    if c2.get("encrypted_c2_indicators"):
        eo_score += 2
        eo_evidence.append("加密C2 URL")
    if mb.get("encryption_hardcoded_key"):
        eo_score += 2
        eo_evidence.append("硬编码加密密钥")
    if code.get("is_packed_and_repackaged"):
        eo_score += 2
        eo_evidence.append("加壳")
    eo_score = min(eo_score, 10)
    result["encryption_obfuscation"] = {"score": eo_score, "out_of": 10, "risk_level": _score_to_level(eo_score), "evidence": "; ".join(eo_evidence)}

    # persistence score
    ps_score = 0
    ps_evidence = []
    if mb.get("boot_persistence"):
        ps_score += 3
        ps_evidence.append("开机自启")
    if mb.get("service_keepalive"):
        ps_score += 3
        ps_evidence.append("Service保活")
    if mb.get("multi_process_architecture"):
        ps_score += 1
        ps_evidence.append("多进程")
    if mb.get("admin_abuse_signal"):
        ps_score += 2
        ps_evidence.append("设备管理员滥用")
    ps_score = min(ps_score, 10)
    result["persistence"] = {"score": ps_score, "out_of": 10, "risk_level": _score_to_level(ps_score), "evidence": "; ".join(ps_evidence)}

    # anti_detection score
    ad_score = 0
    ad_evidence = []
    if code.get("anti_analysis"):
        ad_score += 3
        ad_evidence.extend(code["anti_analysis"])
    if mb.get("root_emulator_detection"):
        ad_score += 2
        ad_evidence.append("Root/模拟器检测")
    if code.get("is_code_obfuscated"):
        ad_score += 1
        ad_evidence.append("代码混淆")
    if mb.get("dynamic_code_loading"):
        ad_score += 2
        ad_evidence.append("动态DEX加载隐藏")
    ad_score = min(ad_score, 10)
    result["anti_detection"] = {"score": ad_score, "out_of": 10, "risk_level": _score_to_level(ad_score), "evidence": "; ".join(ad_evidence)}

    # Total
    scores = [
        result["data_exfiltration"]["score"],
        result["c2_remote_control"]["score"],
        result["data_steal"]["score"],
        result["encryption_obfuscation"]["score"],
        result["persistence"]["score"],
        result["anti_detection"]["score"],
    ]
    avg = round(sum(scores) / len(scores), 1) if scores else 0
    result["total"] = {
        "score": avg,
        "risk_level": _score_to_level(avg),
    }

    return result


def _score_to_level(score):
    if score >= 8:
        return "RED"
    elif score >= 5:
        return "ORANGE"
    elif score >= 3:
        return "YELLOW"
    else:
        return "GREEN"


def extract_advertisement_analysis(apk_path):
    """Extract advertisement SDK and behavior analysis."""
    result = dict(ADVERTISEMENT_ANALYSIS_DEFAULT)

    # Load SDK constants
    sdk_dict, type_dict = load_sdk_constants(CONSTANT_PY)

    # Scan code for SDK package prefixes
    detected_skins = []
    # Build search patterns from SDK keys
    sdk_prefixes = list(sdk_dict.keys())[:50]  # Limit search patterns
    if sdk_prefixes:
        try:
            results = search_code_for_pattern(sdk_prefixes[:20])
            for prefix, matches in results.items():
                if matches:
                    sdk_name = sdk_dict.get(prefix, "Unknown SDK")
                    risk = type_dict.get(prefix, [])
                    risk_level = "; ".join(risk) if risk else "UNKNOWN"
                    detected_skins.append({
                        "sdk_name": sdk_name,
                        "package_prefix": prefix,
                        "risk_level": risk_level,
                        "note": "",
                    })
        except Exception:
            pass

    # Also scan manifest meta-data
    try:
        manifest = get_android_manifest()
        for prefix, sdk_name in sdk_dict.items():
            if prefix in manifest:
                already = any(s["package_prefix"] == prefix for s in detected_skins)
                if not already:
                    risk = type_dict.get(prefix, [])
                    detected_skins.append({
                        "sdk_name": sdk_name,
                        "package_prefix": prefix,
                        "risk_level": "; ".join(risk) if risk else "UNKNOWN",
                        "note": "",
                    })
    except Exception:
        pass

    result["ad_sdk_list"] = detected_skins

    # Ad behaviors
    behaviors = result["ad_behaviors"]
    try:
        adv_patterns = {
            "fullscreen_ad_detected": ["FullScreenActivity", "Interstitial"],
            "notification_ad_detected": ["NotificationManager", "ad_notify"],
            "lockscreen_ad_detected": ["LockScreen", "keyguard"],
            "popup_ad_detected": ["AlertDialog", "pop_ad", "popup"],
            "click_fraud_detected": ["dispatchTouchEvent", "performClick"],
            "overlay_ad_detected": ["TYPE_APPLICATION_OVERLAY", "ad_overlay"],
            "silent_download_promotion": ["silent_install", "auto_download"],
        }
        for field, patterns in adv_patterns.items():
            search_r = search_code_for_pattern(patterns)
            if any(search_r.get(p) for p in patterns):
                behaviors[field] = True
    except Exception:
        pass

    return result


def extract_attack_profile(sub_data):
    """Generate attack profile from all sub-agent results."""
    result = dict(ATTACK_PROFILE_DEFAULT)

    fb = sub_data.get("file_basic", {})
    cert = sub_data.get("certificate_analysis", {})
    perms = sub_data.get("permissions", {})
    comps = sub_data.get("components", {})
    code = sub_data.get("code_analysis", {})
    mb = sub_data.get("malicious_behavior", {})
    nat = sub_data.get("native_analysis", {})
    c2 = sub_data.get("c2_communication", {})
    iocs = sub_data.get("iocs", {})
    risk = sub_data.get("risk_dimension_scores", {})

    # Developer subject
    cn = cert.get("subject_common_name", "")
    org = cert.get("subject_organization", "")
    result["developer_subject"] = org if org else cn if cn else fb.get("package_name", "")

    # App function summary
    result["app_function_summary"] = fb.get("app_label", "") or fb.get("package_name", "")
    if mb.get("sms_intercept_via_broadcast") or mb.get("sms_intercept_via_content_observer"):
        result["app_function_summary"] += "，具备短信窃取能力"
    if c2.get("has_c2"):
        result["app_function_summary"] += "，存在C2远控通信"

    # Distribution form
    result["distribution_form"] = "标准APK应用"

    # Core framework
    result["core_framework"] = "原生Android"

    # Development language
    result["development_language"] = "Java"

    # Obfuscation solution
    techs = code.get("obfuscation_techniques", [])
    result["obfuscation_solution"] = "; ".join(t.get("technique", "") for t in techs) if techs else "未知"

    # Network stack
    c2_pattern = c2.get("c2_communication_pattern", {})
    net_parts = []
    if c2_pattern.get("uses_http_cleartext"):
        net_parts.append("HTTP明文")
    if c2_pattern.get("uses_https"):
        net_parts.append("HTTPS")
    if c2_pattern.get("uses_http_url_connection"):
        net_parts.append("HttpURLConnection")
    if c2_pattern.get("uses_socket_direct_connection"):
        net_parts.append("Socket直连")
    result["network_stack"] = " + ".join(net_parts) if net_parts else "未知"

    # Encryption library
    weak_algos = code.get("weak_cryptographic_algorithms", [])
    result["encryption_library"] = " + ".join(weak_algos) if weak_algos else "Android内置加密"

    # C2 flow
    decryption_step = ""
    if c2.get("encrypted_c2_indicators"):
        for ind in c2["encrypted_c2_indicators"]:
            decryption_step = ind.get("encryption_algorithm", "") + "解密C2 URL"
            break
    # Build destinations summary using the Fix 1 helper (domain-abbreviated)
    dest_summary = _build_destinations_summary(sub_data)
    result["c2_flow"] = {
        "decryption_step": decryption_step,
        "destinations_summary": dest_summary,
    }

    # Overall judgment
    total_risk = risk.get("total", {})
    overall_score = total_risk.get("score", 0)
    if overall_score >= 7:
        risk_label = "[RED] 极高风险 (Critical Risk)"
    elif overall_score >= 4:
        risk_label = "[ORANGE] 高风险 (High Risk)"
    elif overall_score >= 2:
        risk_label = "[YELLOW] 中风险 (Medium Risk)"
    else:
        risk_label = "[GREEN] 低风险 (Low Risk)"

    result["overall_judgment"] = {
        "risk_label": risk_label,
        "risk_score": overall_score,
        "summary": _build_summary(sub_data),
    }

    # Malware family indicators
    mf = fb.get("malware_family", "")
    if mf:
        result["malware_family_indicators"] = [{
            "indicator": "恶意家族匹配",
            "detail": f"通过SHA256匹配到已知恶意家族: {mf}",
        }]
    if iocs.get("c2_urls"):
        result["malware_family_indicators"].append({
            "indicator": "C2 URL特征",
            "detail": f"发现C2 URL: {', '.join(iocs['c2_urls'][:3])}",
        })

    # Attack chains
    attack_chains = _build_attack_chains(mb, c2, sub_data)
    result["attack_chains"] = attack_chains

    # Behavior tags
    result["behavior_tags"] = _build_behavior_tags(mb, c2, code, sub_data)

    return result


def _build_summary(sub_data):
    """Build overall summary description."""
    parts = []
    mb = sub_data.get("malicious_behavior", {})
    c2 = sub_data.get("c2_communication", {})
    fb = sub_data.get("file_basic", {})

    if fb.get("malware_family"):
        parts.append(f"确认为{fb['malware_family']}家族")
    if mb.get("sms_intercept_via_broadcast") or mb.get("sms_intercept_via_content_observer"):
        parts.append("高短信窃取能力")
    if mb.get("sms_delete_capability"):
        parts.append("短信删除能力")
    if mb.get("data_exfiltration"):
        parts.append("数据外传")
    if mb.get("call_forwarding"):
        parts.append("呼叫转移劫持")
    if mb.get("has_c2_communication") or c2.get("has_c2"):
        parts.append("具备C2远控通信")
    if mb.get("dynamic_code_loading"):
        parts.append("动态DEX加载")
    if mb.get("encryption_hardcoded_key"):
        parts.append("硬编码加密")
    if mb.get("service_keepalive"):
        parts.append("高持久化")
    if sub_data.get("code_analysis", {}).get("is_code_obfuscated"):
        parts.append("代码混淆")

    return ", ".join(parts) if parts else "未发现显著恶意行为"


def _build_attack_chains(mb, c2, sub_data):
    """Build attack chain descriptions."""
    chains = []

    if mb.get("sms_intercept_via_broadcast") or mb.get("sms_intercept_via_content_observer"):
        steps = []
        if mb.get("boot_persistence"):
            steps.append({"step_order": 1, "behavior": "开机自启", "target": "BOOT_COMPLETED广播"})
        step_order = len(steps) + 1
        if mb.get("sms_intercept_via_broadcast"):
            steps.append({"step_order": step_order, "behavior": "注册SMS BroadcastReceiver", "target": "SMS_RECEIVED intent"})
            step_order += 1
        if mb.get("sms_intercept_via_content_observer"):
            steps.append({"step_order": step_order, "behavior": "ContentObserver监控短信数据库", "target": "content://sms"})
            step_order += 1
        if c2.get("has_c2"):
            steps.append({"step_order": step_order, "behavior": "外传验证码", "target": "C2服务器"})
        chains.append({
            "chain_id": "CHAIN-001",
            "name": "SMS拦截攻击链",
            "steps": steps,
            "description": "从权限申请到验证码外传的完整攻击链路",
        })

    if c2.get("has_c2") and mb.get("device_fingerprint_collection"):
        chains.append({
            "chain_id": "CHAIN-002",
            "name": "设备信息采集攻击链",
            "steps": [
                {"step_order": 1, "behavior": "采集设备标识", "target": "IMEI/IMSI/手机号"},
                {"step_order": 2, "behavior": "上传到C2", "target": "远端服务器"},
            ],
            "description": "设备指纹信息收集并外传链路",
        })

    if mb.get("dynamic_code_loading"):
        chains.append({
            "chain_id": "CHAIN-003",
            "name": "动态代码加载攻击链",
            "steps": [
                {"step_order": 1, "behavior": "DexClassLoader加载DEX", "target": "动态DEX"},
                {"step_order": 2, "behavior": "执行隐藏代码", "target": "恶意逻辑"},
            ],
            "description": "通过动态加载DEX隐藏恶意行为",
        })

    if mb.get("sms_delete_capability") or mb.get("call_forwarding"):
        steps = []
        if mb.get("call_forwarding"):
            steps.append({"step_order": 1, "behavior": "设置呼叫转移", "target": "TelephonyManager.setCallForward"})
        if mb.get("sms_delete_capability"):
            so = len(steps) + 1
            steps.append({"step_order": so, "behavior": "删除短信记录", "target": "ContentResolver.delete(content://sms)"})
        if steps:
            chains.append({
                "chain_id": "CHAIN-004",
                "name": "通信劫持攻击链",
                "steps": steps,
                "description": "通过呼叫转移和/或短信删除实施通信劫持",
            })

    return chains


def _build_behavior_tags(mb, c2, code, sub_data):
    """Build behavior tags for quick classification."""
    tags = []
    tag_map = [
        ("automatic_c2_communication", "c2", c2.get("has_c2") or mb.get("has_c2_communication"), "定时HTTP POST到固定IP"),
        ("sms_hijacking", "data_steal", mb.get("sms_intercept_via_broadcast") or mb.get("sms_intercept_via_content_observer"), "BroadcastReceiver + ContentObserver双通道拦截"),
        ("sms_delete", "data_steal", mb.get("sms_delete_capability"), "ContentResolver.delete删除短信"),
        ("device_fingerprint", "privacy", mb.get("device_fingerprint_collection"), "采集IMEI/IMSI/设备标识"),
        ("data_exfiltration", "data_steal", mb.get("data_exfiltration"), "设备指纹采集并外传"),
        ("call_forwarding", "telecom", mb.get("call_forwarding"), "setCallForward呼叫转移劫持"),
        ("dynamic_code_loading", "execution", mb.get("dynamic_code_loading"), "DexClassLoader动态加载DEX"),
        ("encryption_hardcoded", "encryption", mb.get("encryption_hardcoded_key"), "Cipher+硬编码密钥加密"),
        ("service_persistence", "persistence", mb.get("service_keepalive"), "Service保活+AlarmManager"),
        ("boot_persistence", "persistence", mb.get("boot_persistence"), "开机自启持久化"),
        ("code_obfuscation", "anti_analysis", code.get("is_code_obfuscated"), "代码经过混淆处理"),
        ("root_detection", "anti_analysis", mb.get("root_emulator_detection"), "Root/模拟器检测机制"),
        ("overlay_phishing", "phishing", mb.get("overlay_phishing"), "悬浮窗覆盖钓鱼"),
        ("shell_execution", "execution", mb.get("shell_command_execution"), "Shell命令执行"),
        ("admin_abuse", "persistence", mb.get("admin_abuse_signal"), "设备管理员滥用"),
        ("accessibility_abuse", "abuse", mb.get("accessibility_abuse_signal"), "无障碍服务滥用"),
    ]

    for tag_name, category, detected, evidence in tag_map:
        if detected:
            tags.append({
                "tag": tag_name,
                "category": category,
                "confidence": 95,
                "evidence": evidence,
            })

    return tags


# ── Main ───────────────────────────────────────────────────────────────────────

def _build_destinations_summary(sub_data):
    """Build c2_flow.destinations_summary from sub03 c2_servers (Python-computed).
    Fix 1: top_5 uses abbreviated domain+path (max 50 chars) instead of full URL.
    Adds unique_domain_count for better summary value.
    """
    c2 = sub_data.get("c2_communication", {})
    c2_servers_list = c2.get("c2_servers", [])
    c2_urls = [s.get("url", "") for s in c2_servers_list if s.get("url")]

    # Extract unique domains
    domains = set()
    for s in c2_servers_list:
        domain = s.get("domain", "")
        if domain:
            domains.add(domain)
        elif s.get("ip"):
            domains.add(s["ip"])

    protocol_dist = {}
    for s in c2_servers_list:
        proto = s.get("protocol", "HTTP")
        protocol_dist[proto] = protocol_dist.get(proto, 0) + 1

    # Abbreviate top_5: domain + first path segment (max 50 chars)
    top_5_abbrev = []
    for s in c2_servers_list[:5]:
        url = s.get("url", "")
        domain = s.get("domain", s.get("ip", ""))
        if not domain:
            continue
        # Extract first path segment
        path_m = re.match(r'https?://[^/]+(:\d+)?(/[^\s?]*)?', url)
        path = path_m.group(2) if path_m and path_m.group(2) else "/"
        abbrev = f"{domain}{path}"[:50]
        top_5_abbrev.append(abbrev)

    return {
        "total_count": len(c2_urls),
        "unique_domain_count": len(domains),
        "top_5": top_5_abbrev,
        "protocol_distribution": protocol_dist,
    }


def _python_fallback_synthesis(sub_data, output_dir, apk_path):
    """Emergency fallback: use Python hardcoded logic when LLM synthesis fails.
    This preserves the old Python-only behavior as a safety net.
    """
    print("  [*] [FALLBACK] Using Python hardcoded synthesis (LLM unavailable)...")

    # data_classification
    data_class = extract_data_classification(sub_data)
    save_json(data_class, os.path.join(output_dir, "data_classification.json"))

    # risk_dimension_scores
    risk_scores = extract_risk_dimension_scores(sub_data)
    save_json(risk_scores, os.path.join(output_dir, "risk_dimension_scores.json"))

    # Re-read updated sub_data with risk scores for attack_profile
    sub_data["risk_dimension_scores"] = risk_scores

    # attack_profile
    attack_prof = extract_attack_profile(sub_data)
    save_json(attack_prof, os.path.join(output_dir, "attack_profile.json"))


def main():
    if len(sys.argv) < 2:
        print("Usage: extract_risk_profile.py <output_dir> [apk_path]")
        sys.exit(1)

    output_dir = sys.argv[1]
    os.makedirs(output_dir, exist_ok=True)
    # F5 fix: apk_path is argv[2] (run_pipeline.py passes 2 args)
    apk_path = sys.argv[2] if len(sys.argv) > 2 else ""

    print("[sub04] Starting sub-agent 04 extraction...")

    # Load all sub-results from the output_dir (sub01-03 JSON files)
    sub_data = {}
    for field_name in ["file_basic", "certificate_analysis", "permissions", "components",
                        "code_analysis", "malicious_behavior", "native_analysis",
                        "c2_communication", "iocs"]:
        json_path = os.path.join(output_dir, field_name + ".json")
        if os.path.exists(json_path):
            sub_data[field_name] = load_json(json_path)
            print(f"  [+] Loaded: {field_name}")

    global _apk_path
    _apk_path = apk_path

    # ── Phase A: Python static computation (deterministic fields) ──
    print("  [*] Phase A: Python static computation...")

    # 1. advertisement_analysis (Python only — SDK package matching + behavior flags)
    print("  [*] Extracting advertisement_analysis...")
    adv_analysis = extract_advertisement_analysis(apk_path)
    save_json(adv_analysis, os.path.join(output_dir, "advertisement_analysis.json"))

    # 2. attack_profile skeleton (destinations_summary only — Python computed)
    dest_summary = _build_destinations_summary(sub_data)
    ap_skeleton = {
        "c2_flow": {
            "destinations_summary": dest_summary,
        }
    }
    save_json(ap_skeleton, os.path.join(output_dir, "attack_profile_skeleton.json"))

    # ── Phase B: LLM dynamic synthesis (data_classification, risk_dimension_scores, attack_profile) ──
    # Skip LLM when SKIP_LLM_SYNTHESIS env var is set (batch mode avoids nested opencode run)
    skip_llm = os.environ.get("SKIP_LLM_SYNTHESIS", "").lower() in ("1", "true", "yes")

    if skip_llm:
        print("  [*] Phase B: LLM synthesis SKIPPED (SKIP_LLM_SYNTHESIS set) — using Python fallback")
        _python_fallback_synthesis(sub_data, output_dir, apk_path)
    else:
        print("  [*] Phase B: LLM dynamic synthesis...")
        fb = sub_data.get("file_basic", {})
        apk_sha256 = fb.get("sha256", "")
        malware_family = fb.get("malware_family", "")

        # Load known_behaviors if available (saved by run_pipeline.py Phase 0)
        known_behaviors = []
        kb_path = os.path.join(output_dir, "known_behaviors.json")
        if os.path.exists(kb_path):
            known_behaviors = load_json(kb_path) or []

        try:
            from llm_synthesis import run_sub04_llm_synthesis
            success = run_sub04_llm_synthesis(
                output_dir, apk_path, apk_sha256, malware_family, known_behaviors
            )
            if not success:
                print("  [!] LLM synthesis failed — falling back to Python hardcoded synthesis")
                _python_fallback_synthesis(sub_data, output_dir, apk_path)
        except ImportError:
            print("  [!] llm_synthesis module not available — falling back to Python")
            _python_fallback_synthesis(sub_data, output_dir, apk_path)
        except Exception as e:
            print(f"  [!] LLM synthesis error: {e} — falling back to Python")
            _python_fallback_synthesis(sub_data, output_dir, apk_path)

    print("[sub04] Done.")


if __name__ == "__main__":
    main()
