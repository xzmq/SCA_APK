"""
extract_code_behavior.py - Code behavior: code_analysis, malicious_behavior, native_analysis.
Usage: python extract_code_behavior.py <apk_path> <output_dir>
"""
import os
import sys
import re
import json

sys.stderr.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import androguard_extractor
import packer_signatures

# Module-level APK path for androguard fallback in code search
_apk_path = None
from config import *
from common import (
    map_report_behavior_to_template_field,
    map_report_behavior_to_detection_patterns,
)
from common import *
from jadx_extractor import (
    get_android_manifest, get_all_classes, get_class_source,
    get_strings, search_code_for_pattern, get_xrefs_to_class,
    get_xrefs_to_method, get_main_application_classes_names,
)


def extract_code_analysis(apk_path, extracted_dir, axplorer_apis, malicious_behavior_result=None,
                          behavior_keywords=None, malicious_behavior_evidence=None):
    result = dict(CODE_ANALYSIS_DEFAULT)

    dex_files = get_dex_files(apk_path)
    result["dex_count"] = len(dex_files)
    result["dex_files_list"] = dex_files

    result["high_entropy_files"], result["high_entropy_files_count"] = _find_high_entropy_files(apk_path)
    result["string_encryption"] = _detect_string_encryption(apk_path)
    result["is_code_obfuscated"], result["obfuscation_techniques"] = _detect_obfuscation(apk_path)
    result["has_dynamic_dex_loading"] = _detect_dynamic_dex_loading()
    result["weak_cryptographic_algorithms"] = _detect_weak_crypto()
    result["sensitive_api_calls"] = _detect_sensitive_api_calls(axplorer_apis)
    # malicious_code_snippets: only record snippets for behaviors detected as true in malicious_behavior
    result["malicious_code_snippets"] = _find_malicious_snippets(
        malicious_behavior_result, malicious_behavior_evidence if malicious_behavior_evidence else {})
    result["webview_security_config"] = _analyze_webview_security()
    result["has_embedded_payload"], result["embedded_payloads"] = _detect_embedded_payloads(apk_path)
    result["is_packed_and_repackaged"] = _detect_packing()
    result["anti_analysis"] = _detect_anti_analysis()
    result["related_native_libs_for_crypt"] = _find_crypto_native_libs()

    # F-C: Comprehensive packing risk assessment
    result["_packing_assessment"] = _assess_packing_risk(apk_path, result)

    return result


def _find_high_entropy_files(apk_path, threshold=7.0):
    high_entropy = []
    all_files = list_apk_files(apk_path)
    skip_prefixes = ("META-INF/", "AndroidManifest.xml",
                     "res/drawable", "res/mipmap", "res/color", "res/menu", "res/values")
    skip_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.9.png',
                       '.xml', '.arsc', '.rsdp', '.RSA', '.DSA', '.EC', '.SF', '.MF')

    for fpath in all_files:
        if any(fpath.startswith(p) for p in skip_prefixes):
            continue
        if any(fpath.endswith(ext) for ext in skip_extensions):
            continue

        size = get_file_size_in_apk(apk_path, fpath)
        if size < 1024:
            continue

        ent = compute_file_entropy_in_apk(apk_path, fpath)
        if ent > threshold:
            risk = "HIGH" if ent > 7.5 else "MEDIUM"
            note = _get_entropy_note(fpath, ent)
            high_entropy.append({"path": fpath, "entropy": ent, "risk": risk, "note": note})

    return high_entropy, len(high_entropy)


def _get_entropy_note(filepath, entropy):
    ext = os.path.splitext(filepath)[1].lower()
    ext_map = {
        '.mp3': "音频文件熵值异常高，可能内含加密数据而非真实音频",
        '.png': "图片文件熵值异常高，可能为加密Payload伪装成图片",
        '.jpg': "图片文件熵值异常高，可能为加密Payload伪装成图片",
        '.dat': "数据文件高熵值，疑似加密或混淆Payload",
        '.so': "原生库文件，高熵值可能包含加壳或加密代码",
    }
    return ext_map.get(ext, "文件熵值较高，可能为加密或混淆数据")


def _detect_string_encryption(apk_path):
    patterns = ["decrypt", "decodeString", "Xor", "Base64.decode"]
    try:
        results = search_code_for_pattern(patterns)
        for pat, matches in results.items():
            if matches:
                return True
    except Exception:
        pass
    return False


def _detect_obfuscation(apk_path):
    techniques = []
    try:
        all_classes = get_all_classes(offset=0, count=500)
        if all_classes:
            short_names = 0
            hex_names = 0
            total = 0
            for cls in all_classes:
                if isinstance(cls, dict):
                    name = cls.get("name", cls.get("class_name", ""))
                elif isinstance(cls, str):
                    name = cls
                else:
                    continue
                if not name:
                    continue
                simple = name.split("/")[-1].split("$")[-1] if "/" in name else name.split(".")[-1]
                total += 1
                if len(simple) <= 2 and simple.isalpha():
                    short_names += 1
                if re.match(r'^[0-9a-f]{8,}$', simple):
                    hex_names += 1

            if total > 10 and short_names / total > 0.3:
                techniques.append({"technique": "类名混淆", "description": "大量类名被替换为短随机字符串(如a.b.c)"})
            if hex_names > 5:
                techniques.append({"technique": "十六进制类名", "description": "存在大量类名使用十六进制编码"})
    except Exception:
        pass

    try:
        ref_search = search_code_for_pattern(["Class.forName", "getMethod", "invoke("])
        ref_count = sum(len(v) for v in ref_search.values())
        if ref_count > 10:
            techniques.append({"technique": "反射调用混淆", "description": "检测到大量反射调用，代码逻辑被反射隐藏"})
    except Exception:
        pass

    if _detect_string_encryption(apk_path):
        techniques.append({"technique": "字符串加密", "description": "敏感字符串被加密存储，运行时解密"})

    return len(techniques) > 0, techniques


def _detect_dynamic_dex_loading():
    patterns = ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", "dalvik.system.DexFile"]
    try:
        results = search_code_for_pattern(patterns)
        return any(results.get(p) for p in patterns)
    except Exception:
        return False


def _detect_weak_crypto():
    weak_algos = set()
    try:
        strings_result = get_strings()
        if strings_result:
            all_text = json.dumps(strings_result, ensure_ascii=False)
            for algo in ["DES", "MD5", "RC4", "SHA1", "ECB", "3DES", "Blowfish"]:
                if algo in all_text:
                    weak_algos.add(algo)
    except Exception:
        pass

    try:
        cipher_patterns = ['"DES', '"MD5', '"RC4', '"ECB', '"3DES', '"Blowfish']
        r = search_code_for_pattern(cipher_patterns)
        for pat, matches in r.items():
            if matches:
                algo = pat.strip('"')
                if algo in ("DES", "MD5", "RC4", "ECB", "3DES", "Blowfish"):
                    weak_algos.add(algo)
    except Exception:
        pass

    return list(weak_algos)


# ── DEX descriptor helpers ────────────────────────────────────────────────────

_DEX_PRIMITIVE_MAP = {
    'V': 'void', 'Z': 'boolean', 'B': 'byte', 'S': 'short',
    'C': 'char', 'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double',
    'Ljava/lang/Object;': 'java.lang.Object',
    'Ljava/lang/String;': 'java.lang.String',
    'Ljava/lang/Integer;': 'java.lang.Integer',
    'Ljava/lang/Long;': 'java.lang.Long',
    'Ljava/lang/Boolean;': 'java.lang.Boolean',
    'Ljava/util/Set;': 'java.util.Set',
    'Ljava/util/List;': 'java.util.List',
    'Ljava/util/ArrayList;': 'java.util.ArrayList',
}

def _dex_desc_to_dotted(desc):
    if not desc or desc[0] != '(':
        return desc
    try:
        close_paren = desc.rindex(')')
        params_str = desc[1:close_paren]
        ret_str = desc[close_paren + 1:]
    except ValueError:
        return desc

    def _resolve_single(t):
        t = t.strip()
        if t in _DEX_PRIMITIVE_MAP:
            return _DEX_PRIMITIVE_MAP[t]
        if t.startswith('['):
            return _resolve_single(t[1:]) + '[]'
        if t.startswith('L') and t.endswith(';'):
            return t[1:-1].replace('/', '.')
        return t

    params_dotted = []
    if params_str:
        parts = []
        token = ''
        for ch in params_str:
            token += ch
            if ch == ';':
                parts.append(token.strip())
                if token != ';':
                    parts.append(token.strip() + ' dummy')
                token = ''
        current = ''
        for ch in params_str:
            current += ch
            if ch == ';':
                for seg in current.strip().split():
                    if seg:
                        params_dotted.append(_resolve_single(seg))
                current = ''
        if current.strip():
            for seg in current.strip().split():
                if seg:
                    params_dotted.append(_resolve_single(seg))

    ret_dotted = _resolve_single(ret_str)
    return '(%s)%s' % (','.join(params_dotted), ret_dotted)


def _dex_class_dotted(class_name):
    if class_name.startswith('L') and class_name.endswith(';'):
        return class_name[1:-1].replace('/', '.')
    return class_name.replace('/', '.')


_DEX2CATEGORY = {
    "短信收发": {"Landroid/telephony/SmsManager;", "Landroid/telephony/SmsMessage;",
                "Landroid/provider/Telephony$Sms;", "Landroid/telephony/gsm/SmsManager;"},
    "通讯录/通话": {"Landroid/provider/ContactsContract;", "Landroid/provider/CallLog;"},
    "位置": {"Landroid/location/LocationManager;", "Landroid/location/Location;",
             "Landroid/location/GpsStatus;"},
    "文件/存储": {"Landroid/os/Environment;", "Ljava/io/File;",
                  "Ljava/io/FileInputStream;", "Ljava/io/FileOutputStream;"},
    "网络/通信": {"Ljava/net/HttpURLConnection;", "Ljava/net/URL;", "Ljava/net/Socket;",
                  "Ljava/net/ServerSocket;", "Ljava/net/DatagramSocket;",
                  "Ljava/lang/Runtime;", "Ljava/lang/ProcessBuilder;",
                  "Landroid/net/ConnectivityManager;"},
    "系统/设备信息": {"Landroid/telephony/TelephonyManager;", "Landroid/os/Build;",
                      "Landroid/provider/Settings$Secure;", "Landroid/provider/Settings$System;",
                      "Landroid/app/ActivityManager;", "Landroid/app/Debug;",
                      "Landroid/hardware/fingerprint/FingerprintManager;",
                      "Landroid/os/PowerManager$WakeLock;"},
    "安装/执行": {"Landroid/content/pm/PackageManager;",
                  "Ldalvik/system/DexClassLoader;", "Ldalvik/system/PathClassLoader;",
                  "Ldalvik/system/BaseDexClassLoader;"},
    "其他": set(),
}


def _get_category(class_name_dex):
    for cat, prefixes in _DEX2CATEGORY.items():
        if class_name_dex in prefixes:
            return cat
    return None


def _detect_sensitive_api_calls(axplorer_apis):
    """
    Detect sensitive API calls by scanning DEX method references and
    matching against the Axplorer API database (exact format match).

    Hybrid strategy (spec sub02 3.9 + engineering note):
      1. jadx MCP (primary): get_all_classes() to enumerate application classes
         and filter out library/framework classes. This respects the spec's
         "jadx MCP 优先" rule for determining the app's code scope.
      2. androguard DEX (supplementary): batch-extract method references from
         DEX bytecode. jadx MCP's API has no "list all method signatures"
         endpoint (only per-class get_methods_of_class), so androguard DEX
         is used for efficient batch signature extraction.
         See jadx_mcp_api.txt for available endpoints.

    Returns [] if axplorer_apis is empty or scanning fails.
    """
    if not axplorer_apis:
        return []

    categories_out = {cat: set() for cat in _DEX2CATEGORY}
    seen = set()

    # ── Step 1: jadx MCP — enumerate application classes (determine app code scope) ──
    app_class_set = set()
    try:
        all_classes = get_all_classes(offset=0, count=0)
        if all_classes:
            for cls in all_classes:
                if isinstance(cls, dict):
                    name = cls.get("name", cls.get("class_name", ""))
                elif isinstance(cls, str):
                    name = cls
                else:
                    continue
                if name and not _is_library_class_for_api(name):
                    app_class_set.add(name.replace("/", "."))
            print(f"  [+] [sub02] jadx MCP: {len(app_class_set)} application classes (filtered from {len(all_classes)} total)")
    except Exception as e:
        print(f"  [!] [sub02] jadx MCP get_all_classes failed: {e}, using androguard-only fallback")
        app_class_set = set()

    # ── Step 2: androguard DEX — batch method reference extraction + Axplorer matching ──
    import zipfile
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
        from androguard_extractor import _get_apk_raw_bytes

        if not os.path.isfile(_apk_path):
            return []

        apk_obj = APK(_apk_path, skip_analysis=True)
        dex_names = apk_obj.get_dex_names()

        with zipfile.ZipFile(_apk_path, "r") as zf:
            for dex_name in dex_names:
                dex_bytes = zf.read(dex_name)
                if not dex_bytes:
                    continue
                vm = DEX(dex_bytes)
                for method_ref in vm.get_methods():
                    try:
                        cl = method_ref.get_class_name()
                        nm = method_ref.get_name()
                        ds = method_ref.get_descriptor()
                    except Exception:
                        continue

                    cl_dotted = _dex_class_dotted(cl)
                    desc_dotted = _dex_desc_to_dotted(ds)
                    signature = '%s.%s%s' % (cl_dotted, nm, desc_dotted)

                    if signature in seen:
                        continue
                    if signature not in axplorer_apis:
                        continue
                    seen.add(signature)

                    cat = _get_category(cl)
                    if cat:
                        categories_out[cat].add(signature)
                    else:
                        categories_out["其他"].add(signature)
    except Exception:
        return []

    result = []
    purpose_map = {
        "短信收发": "拦截/发送/读取短信",
        "通讯录/通话": "窃取通讯录、通话记录",
        "位置": "追踪用户位置",
        "文件/存储": "窃取/篡改文件",
        "网络/通信": "数据外传、命令执行、C2通信",
        "系统/设备信息": "设备指纹采集",
        "安装/执行": "提权、植入、动态加载",
        "反射与动态": "隐藏恶意逻辑、逃避检测",
        "加密": "加密通信/加密payload",
        "其他": "未分类敏感操作",
    }
    for cat, apis in categories_out.items():
        if not apis:
            continue
        result.append({
            "category": cat,
            "apis": sorted(apis),
            "malicious_purpose": purpose_map.get(cat, ""),
        })
    return result


def _is_library_class_for_api(class_name):
    """Check if a class is from a standard library/framework (for API detection filtering).
    Used to separate application code from framework/library code in jadx MCP class list.
    """
    cn = class_name.replace("/", ".")
    library_prefixes = (
        "android.support", "androidx", "com.google", "com.sun", "dalvik",
        "java.", "javax.", "android.os.", "android.content.", "android.app.",
        "android.view", "android.widget", "android.webkit", "android.media",
        "android.opengl", "android.text", "android.util", "android.location",
        "android.telephony", "android.provider", "android.net", "android.database",
        "android.hardware", "android.bluetooth", "android.nfc", "android.gesture",
        "android.preference", "android.service", "android.transition", "android.drm",
        "android.security", "android.speech", "android.se.omapi",
        "kotlin", "kotlinx", "scala", "org.apache", "org.json", "org.w3c",
        "org.xml", "org.jsoup", "okhttp3", "okio", "retrofit2", "com.squareup",
        "com.bumptech", "com.facebook", "com.tencent", "com.alibaba",
        "com.amap", "com.baidu", "com.bytedance", "com.umeng", "com.huawei",
        "com.qiyukf", "io.reactivex", "io.socket", "com.google.gson",
        "com.google.firebase", "com.google.android", "com.crashlytics",
    )
    for prefix in library_prefixes:
        if cn.startswith(prefix):
            return True
    return False


def _find_malicious_snippets(malicious_behavior_result=None, evidence=None):
    """
    Find malicious code snippets.
    【强制关联规则】有且只有与 malicious_behavior 字段中检测为 true 的恶意行为
    直接关联的代码，才能记录到 snippets 中。
    evidence: dict {behavior_field: search_results_dict} from extract_malicious_behavior.
    直接消费 _check_bool 已经搜索的结果，不重复搜索。
    策略: 从已检测到的行为证据中提取 class_name 字符串列表，然后通过
    get_main_application_classes_code 获取全部应用类源码，在源码中搜索这些类，
    找到匹配模式的方法体作为 snippet。
    """
    BEHAVIOR_TO_PATTERNMAP = {
        "sms_intercept_via_broadcast": (["abortBroadcast", "SMS_RECEIVED"], "短信广播拦截"),
        "sms_intercept_via_content_observer": (["ContentObserver", "content://sms"], "ContentObserver短信监控"),
        "dynamic_sms_receiver_registration": (["registerReceiver", "SMS_RECEIVED"], "动态注册短信Receiver"),
        "boot_persistence": (["BOOT_COMPLETED"], "开机自启"),
        "service_keepalive": (["START_STICKY", "AlarmManager"], "服务保活"),
        "device_fingerprint_collection": (["getDeviceId", "getSubscriberId", "getImei"], "设备指纹采集"),
        "overlay_phishing": (["TYPE_APPLICATION_OVERLAY", "WindowManager.addView"], "悬浮窗钓鱼"),
        "ad_click_fraud": (["dispatchTouchEvent", "performClick"], "广告点击欺诈"),
        "shell_command_execution": (["Runtime.exec", "ProcessBuilder"], "Shell命令执行"),
        "admin_abuse_signal": (["DeviceAdminReceiver", "ACTION_ADD_DEVICE_ADMIN"], "设备管理员滥用"),
        "accessibility_abuse_signal": (["AccessibilityService", "BIND_ACCESSIBILITY_SERVICE"], "无障碍服务滥用"),
        "has_c2_communication": (["HttpURLConnection", "Socket"], "C2通信"),
        "data_exfiltration": (["POST", "HttpURLConnection", "OutputStream"], "数据外传"),
        "sms_delete_capability": (["ContentResolver.delete", "content://sms"], "短信删除"),
        "call_forwarding": (["setCallForward", "GSM_CALL_FORWARD"], "呼叫转移"),
        "dynamic_code_loading": (["DexClassLoader", "PathClassLoader", "loadDex"], "动态DEX加载"),
        "encryption_hardcoded_key": (["Cipher.getInstance", "DES", "SecretKeySpec"], "硬编码加密"),
        "notification_spam_or_phishing": (["NotificationManager", "notify("], "通知垃圾/钓鱼"),
        "root_emulator_detection": (["magisk", "isRooted", "google_sdk"], "Root/模拟器检测"),
        "multi_process_architecture": (["Process.myPid", "android:process"], "多进程架构"),
        "c2_encrypted_urls": (["decrypt", "Cipher", "Base64"], "加密URL"),
        "cleartext_communication": (["http://"], "明文通信"),
    }

    # Collect all class names from evidence
    cls_names_from_evidence = set()
    if evidence:
        for field, field_ev in evidence.items():
            if isinstance(field_ev, dict):
                for pat, matches in field_ev.items():
                    if isinstance(matches, list):
                        for m in matches:
                            if isinstance(m, str):
                                cn = m.strip()
                                if cn:
                                    cls_names_from_evidence.add(cn)

    # Heuristic for Java/Android method detection:
    _method_re = re.compile(
        r'^(?:[\w\[\]<>,\s]+\s+)'  # return type(s)
        r'(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w\s,./]+)?\s*\{'
    )

    _JADX_COMMENT_RE = re.compile(r'/\*\s*JADX\s+|/* JADX INFO|/* JADX ERROR')

    _LIBRARY_PREFIXES = ("android.support", "androidx", "com.google", "com.sun", "dalvik", "java.", "javax.", "android.os.", "android.content.", "android.app.")

    def _is_library_class(class_name):
        """Check if a class is from a standard library/framework."""
        cn = class_name.replace("/", ".")
        for prefix in _LIBRARY_PREFIXES:
            if cn.startswith(prefix):
                return True
        return False

    def _is_method_line(line):
        """Check if line looks like a Java method declaration."""
        s = line.strip()
        if s.startswith("import ") or s.startswith("package ") or s.startswith("//") or _JADX_COMMENT_RE.search(s):
            return False
        if s.startswith("/* ") or s.startswith("* ") or s.startswith("*/"):
            return False
        m = _method_re.match(s)
        return m is not None

    def _extract_snippets_for_class(class_name, patterns, behavior_field, behavior_desc, risk):
        """Extract method-level code snippets from a single class source.

        Each matching evidence line generates a separate snippet context.
        Nearby evidence lines (within 3 lines) belonging to the same behavior
        are merged into one snippet.
        """
        # Skip library/framework classes
        if _is_library_class(class_name):
            return []
        results = []
        src = ""
        try:
            src = get_class_source(class_name)
            if not src:
                return results
        except Exception:
            return results

        lines = src.split("\n")
        total = len(lines)
        i = 0
        while i < total:
            stripped = lines[i].strip()
            if _is_method_line(stripped):
                m = _method_re.match(stripped)
                if m:
                    method_name = m.group(1)
                    # Skip common library methods we don't care about
                    if method_name in ("toString", "hashCode", "equals", "clone", "finalize", "wait", "notify", "notifyAll"):
                        i += 1
                        continue

                    method_sig = stripped.strip()

                    # Collect method body starting from this line
                    body_lines = [lines[i]]
                    brace_depth = stripped.count("{") - stripped.count("}")
                    j = i + 1
                    while j < total and brace_depth > 0:
                        ls = lines[j].strip()
                        if ls.startswith("import ") or ls.startswith("package "):
                            j += 1
                            continue
                        body_lines.append(lines[j])
                        brace_depth += ls.count("{") - ls.count("}")
                        j += 1

                    # Check if patterns match in the method body
                    method_body = "\n".join(body_lines)
                    matching_pats = [p for p in patterns if p in method_body]
                    if not matching_pats:
                        i = j
                        continue

                    body_list = method_body.split("\n")

                    # Find all matching line indices within method body (skip line 0 which is method sig)
                    matching_indices = []
                    for idx in range(1, len(body_list)):
                        bs = body_list[idx].strip()
                        if _JADX_COMMENT_RE.search(bs):
                            continue
                        if bs.startswith("//"):
                            continue
                        if any(pat in bs for pat in matching_pats):
                            matching_indices.append(idx)

                    if not matching_indices:
                        i = j
                        continue

                    # Merge nearby matching indices into groups (gap <= 3 lines)
                    groups = []
                    current_group = [matching_indices[0]]
                    for mi in matching_indices[1:]:
                        if mi - current_group[-1] <= 3:
                            current_group.append(mi)
                        else:
                            groups.append(current_group)
                            current_group = [mi]
                    groups.append(current_group)

                    # Generate one snippet per group
                    for group in groups:
                        snippet_parts = []

                        start_idx = max(1, group[0] - 2)
                        end_idx = min(len(body_list) - 1, group[-1] + 2)

                        for ci in range(start_idx, end_idx + 1):
                            bs = body_list[ci].strip()
                            if bs.startswith("import ") or bs.startswith("package "):
                                continue
                            if _JADX_COMMENT_RE.search(bs):
                                continue
                            if bs.startswith("//") or bs.startswith("/* JADX"):
                                continue
                            snippet_parts.append(body_list[ci])

                        # Strip leading/trailing lone curly braces
                        stripped_parts = list(snippet_parts)
                        while stripped_parts and stripped_parts[0].strip() in ("{", "}"):
                            stripped_parts.pop(0)
                        while stripped_parts and stripped_parts[-1].strip() in ("{", "}"):
                            stripped_parts.pop()
                        # If all lines were braces (edge case), keep original
                        if stripped_parts:
                            snippet_parts = stripped_parts

                        snippet_text = "\n".join(snippet_parts).strip()[:500]
                        if snippet_text:
                            results.append({
                                "class_name": class_name,
                                "method": method_sig,
                                "behavior": behavior_desc,
                                "code_snippet": snippet_text,
                                "risk": risk,
                            })

                    i = j
                else:
                    i += 1
            else:
                i += 1
        return results

    snippets = []
    behavior_detected = {}

    if malicious_behavior_result and isinstance(malicious_behavior_result, dict):
        for field, val in malicious_behavior_result.items():
            if isinstance(val, bool) and val and field in BEHAVIOR_TO_PATTERNMAP and field != "_malicious_behavior_evidence":
                behavior_detected[field] = True

    if not evidence:
        evidence = {}

    try:
        for behavior_field, (patterns, behavior_desc) in BEHAVIOR_TO_PATTERNMAP.items():
            if not behavior_detected.get(behavior_field, False):
                continue

            risk = "HIGH" if behavior_field in (
                "sms_intercept_via_broadcast", "sms_intercept_via_content_observer",
                "device_fingerprint_collection", "has_c2_communication",
                "data_exfiltration", "overlay_phishing",
                "sms_delete_capability", "encryption_hardcoded_key",
                "accessibility_abuse_signal", "admin_abuse_signal"
            ) else "MEDIUM"

            # Collect evidence for this behavior
            field_evidence = evidence.get(behavior_field, {})
            target_class_names = set()
            for p in patterns:
                if field_evidence.get(p):
                    for sr in field_evidence[p][:5]:
                        if isinstance(sr, str):
                            target_class_names.add(sr.strip())
            for ek in list(field_evidence.keys())[:10]:
                if not any(p in ek for p in patterns):
                    for sr in field_evidence[ek][:3]:
                        if isinstance(sr, str):
                            target_class_names.add(sr.strip())

            for cn in target_class_names:
                if not cn:
                    continue
                # Try both dot and slash format
                for name_variant in [cn, cn.replace(".", "/")]:
                    method_snippets = _extract_snippets_for_class(
                        name_variant, patterns, behavior_field, behavior_desc, risk
                    )
                    if method_snippets:
                        snippets.extend(method_snippets)
                        break  # Found in this variant, skip the other
    except Exception:
        pass

    # Deduplicate by (class_name, method, behavior, snippet_content_hash)
    # This allows multiple evidence groups in the same method to coexist
    seen = set()
    unique_snippets = []
    for s in snippets:
        code_hash = hash(s["code_snippet"][:200])
        key = (s["class_name"], s["method"], s["behavior"], code_hash)
        if key not in seen:
            seen.add(key)
            unique_snippets.append(s)

    return unique_snippets[:20]


def _analyze_webview_security():
    config = {"javascript_enabled": False, "save_password_enabled": False, "allow_file_access": False, "loaded_urls": []}
    try:
        patterns = ["setJavaScriptEnabled", "setSavePassword", "setAllowFileAccess", "loadUrl"]
        results = search_code_for_pattern(patterns)
        if results.get("setJavaScriptEnabled"):
            config["javascript_enabled"] = True
        if results.get("setSavePassword"):
            config["save_password_enabled"] = True
        if results.get("setAllowFileAccess"):
            config["allow_file_access"] = True
        if results.get("loadUrl"):
            url_pattern = re.compile(r'loadUrl\s*\(\s*"([^"]+)"')
            for m in results["loadUrl"]:
                urls = url_pattern.findall(str(m))
                config["loaded_urls"].extend(urls)
            config["loaded_urls"] = list(set(config["loaded_urls"]))
    except Exception:
        pass
    return config


def _detect_embedded_payloads(apk_path):
    payloads = []
    all_files = list_apk_files(apk_path)
    payload_dirs = ("assets/", "res/raw/")

    for fpath in all_files:
        if any(fpath.startswith(d) for d in payload_dirs):
            ext = os.path.splitext(fpath)[1].lower()
            if ext in ('.dex', '.elf', '.sh', '.py', '.js', '.lua', '.so'):
                ent = compute_file_entropy_in_apk(apk_path, fpath)
                if ext == '.dex':
                    ptype, purpose = "embedded_dex", "动态代码加载"
                elif ext in ('.elf', '.sh'):
                    ptype, purpose = "elf_executable", "原生可执行文件/脚本"
                elif ext in ('.py', '.js', '.lua'):
                    ptype, purpose = "script", "脚本文件"
                else:
                    ptype = "encrypted_file" if ent > 7.0 else "unknown_payload"
                    purpose = "可疑嵌入文件"
                payloads.append({"payload_type": ptype, "path": fpath, "purpose": purpose})

    return len(payloads) > 0, payloads


def _detect_packing():
    pack_indicators = ["com.qihoo.util", "com.shell.SuperApplication", "ReDex"]
    try:
        results = search_code_for_pattern(pack_indicators)
        return any(results.get(p) for p in pack_indicators)
    except Exception:
        return False


def _match_packer_signatures(apk_path, code_analysis_result):
    """F-A: Match APK against known packer signatures.
    Returns (packer_name, matched_java_patterns, matched_so_patterns).
    """
    matched_java = []
    matched_so = []

    # Check Java patterns via jadx MCP code search
    all_java_pats = packer_signatures.get_all_java_patterns()
    try:
        search_results = search_code_for_pattern(all_java_pats[:30], max_results_per_pattern=5)
        for pat, matches in search_results.items():
            if matches:
                packer = packer_signatures.match_packer_by_java(pat)
                if packer:
                    matched_java.append(pat)
    except Exception:
        pass

    # Check .so patterns via native library list
    native_libs = code_analysis_result.get("native_library_count", 0)
    native_libraries = []
    try:
        from common import get_native_libs
        native_libraries = get_native_libs(apk_path)
    except Exception:
        pass
    for so_path in native_libraries:
        so_name = os.path.basename(so_path).lower()
        packer = packer_signatures.match_packer_by_so(so_name)
        if packer and so_name not in matched_so:
            matched_so.append(so_name)

    # Also check manifest for packer class names
    try:
        manifest = get_android_manifest()
        for pat in all_java_pats:
            if pat in manifest and pat not in matched_java:
                packer = packer_signatures.match_packer_by_java(pat)
                if packer:
                    matched_java.append(pat)
    except Exception:
        pass

    # Determine primary packer name
    packer_name = ""
    if matched_java:
        packer_name = packer_signatures.match_packer_by_java(matched_java[0])
    if not packer_name and matched_so:
        packer_name = packer_signatures.match_packer_by_so(matched_so[0])

    return packer_name, matched_java, matched_so


def _assess_packing_risk(apk_path, code_analysis_result):
    """F-C: Comprehensive packing risk assessment.
    Combines 7 signals to produce a confidence score (0-100).
    Returns dict with is_packed, confidence, packer_name, indicators, dex_location.
    """
    signals = []
    score = 0

    # Signal 1: Packer SDK string match (F-A) — weight 30
    packer_name, matched_java, matched_so = _match_packer_signatures(apk_path, code_analysis_result)
    if packer_name:
        score += 30
        sig = f"检测到已知加固方案: {packer_name}"
        if matched_java:
            sig += f" (Java特征: {', '.join(matched_java[:3])})"
        if matched_so:
            sig += f" (SO特征: {', '.join(matched_so[:3])})"
        signals.append(sig)
    elif matched_java or matched_so:
        score += 15
        signals.append(f"检测到疑似壳特征（未匹配已知厂商）")

    # Signal 2: File entropy > 7.5 — weight 15
    try:
        with open(apk_path, "rb") as f:
            apk_bytes = f.read()
        file_entropy = shannon_entropy_bytes(apk_bytes)
        if file_entropy > 7.5:
            score += 15
            signals.append(f"APK整体熵值偏高({file_entropy:.2f})，疑似加密/加壳")
        elif file_entropy > 7.0:
            score += 5
            signals.append(f"APK整体熵值略高({file_entropy:.2f})")
    except Exception:
        pass

    # Signal 3: High-entropy files in assets/ — weight 15
    hef = code_analysis_result.get("high_entropy_files", [])
    assets_he = [f for f in hef if f.get("path", "").startswith("assets/")]
    if assets_he:
        score += 15
        signals.append(f"assets/下{len(assets_he)}个高熵文件（疑似加密DEX）: {[f['path'] for f in assets_he[:3]]}")

    # Signal 4: DexClassLoader/InMemoryDexClassLoader usage — weight 15
    if code_analysis_result.get("has_dynamic_dex_loading"):
        score += 15
        signals.append("检测到DexClassLoader动态加载（壳加载器的典型特征）")

    # Signal 5: DEX count == 1 but suspicious — weight 10
    # Check if stub: try to get class count from jadx MCP
    dex_count = code_analysis_result.get("dex_count", 0)
    total_classes = 0
    try:
        all_classes = get_all_classes(offset=0, count=0)
        total_classes = len(all_classes) if all_classes else 0
    except Exception:
        pass
    if dex_count == 1 and total_classes > 0 and total_classes < 50:
        score += 10
        signals.append(f"单DEX但仅{total_classes}个类（stub加载器特征）")
    elif dex_count == 1 and total_classes > 0 and total_classes < 150:
        score += 5
        signals.append(f"单DEX且类数偏少({total_classes})，可能为壳")

    # Signal 6: Suspicious .so libraries (packer-related) — weight 10
    if matched_so:
        score += 10
    else:
        # Check native_libraries for high-entropy suspicious .so
        native_analysis = code_analysis_result.get("native_analysis", {})
        if isinstance(native_analysis, dict):
            suspicious_native = native_analysis.get("suspicious_native_libraries", [])
            if suspicious_native:
                score += 5
                signals.append(f"检测到可疑原生库: {[l.get('library_name','') for l in suspicious_native[:3]]}")

    # Signal 7: Embedded encrypted payload — weight 5
    if code_analysis_result.get("has_embedded_payload"):
        score += 5
        signals.append("检测到嵌入的加密payload")

    score = min(score, 100)

    dex_location = packer_signatures.get_packer_dex_location(packer_name) if packer_name else "assets/"

    result = {
        "is_packed": score >= 40,
        "confidence": score,
        "packer_name": packer_name or "",
        "indicators": signals,
        "dex_location": dex_location,
        "matched_java_patterns": matched_java,
        "matched_so_patterns": matched_so,
        "dex_count": dex_count,
        "total_classes": total_classes,
    }
    if signals:
        print(f"  [+] [Packing] confidence={score}%, packer={packer_name or '未知'}, signals={len(signals)}")
    return result


def _detect_anti_analysis():
    techniques = []
    patterns = {
        "debug_detection": ["Debug.isDebuggerConnected", "isDebuggable", "DEBUGGABLE"],
        "emulator_detection": ["Build.FINGERPRINT", "google_sdk", "isEmulator", "goldfish",
                               "qemud", "checkprop", "emulator", "Build.PRODUCT", "sdk"],
        "root_detection": ["magisk", "isRooted", "supersu", "test-keys", "/system/xbin/su",
                           "/system/bin/su", "Superuser", "which su", "su"],
        "frida_detection": ["frida", ":27042", "XposedBridge", "xposed", "core.jar"],
    }
    try:
        all_p = [p for pl in patterns.values() for p in pl]
        results = search_code_for_pattern(all_p)
        for tech_name, tech_pats in patterns.items():
            if any(results.get(p) for p in tech_pats):
                techniques.append(tech_name)
    except Exception:
        pass
    return list(set(techniques))


def _find_crypto_native_libs():
    results = []
    try:
        r = search_code_for_pattern(["System.loadLibrary"])
        if r.get("System.loadLibrary"):
            for sr in r["System.loadLibrary"]:
                text = str(sr)
                m = re.search(r'loadLibrary\s*\(\s*"([^"]+)"', text)
                if m:
                    lib = m.group(1)
                    if any(kw in lib.lower() for kw in ['crypt', 'encrypt', 'sec', 'ssl', 'native']):
                        results.append("lib" + lib + ".so")
    except Exception:
        pass
    return results


# ── malicious_behavior ─────────────────────────────────────────────────────────

def extract_malicious_behavior(apk_path=None, known_behaviors=None, behavior_keywords=None, behavior_techs=None):
    """
    Extract malicious behavior indicators.
    apk_path: APK path (for androguard fallback)
    known_behaviors: list of {"name": ..., "risk": ...} from report MD
    behavior_keywords: list of keywords from report MD for priority detection
    behavior_techs: list of {"name": ..., "risk": ..., "techniques": [...]} from report MD
    """
    result = dict(MALICIOUS_BEHAVIOR_DEFAULT)

    # Build report-driven extra patterns map: {template_field: [extra_patterns]}
    report_extra_patterns = {}
    reported_fields = set()
    if behavior_techs:
        for bt in behavior_techs:
            field_name = map_report_behavior_to_template_field(bt["name"])
            if field_name:
                reported_fields.add(field_name)
                techs = bt.get("techniques", [])
                extra_pats = map_report_behavior_to_detection_patterns(bt["name"])
                extra_pats.extend([t for t in techs if len(t) > 3])
                report_extra_patterns[field_name] = list(set(extra_pats))
    # Also collect behavior_keywords as global extra patterns
    global_extra = set()
    if behavior_keywords:
        for kw in behavior_keywords:
            if len(kw) > 3:
                global_extra.add(kw)

    # ── Original 16 detections (with report-driven enhancement) ──
    _evidence = {}
    
    r, ev = _check_bool_with_report_hint(
        ["SMS_RECEIVED", "abortBroadcast"], report_extra_patterns.get("sms_intercept_via_broadcast", list(global_extra)), min_hits=2)
    result["sms_intercept_via_broadcast"] = r
    _evidence["sms_intercept_via_broadcast"] = ev

    r, ev = _check_bool_with_report_hint(
        ["ContentObserver", "content://sms"], report_extra_patterns.get("sms_intercept_via_content_observer", list(global_extra)), min_hits=2)
    result["sms_intercept_via_content_observer"] = r
    _evidence["sms_intercept_via_content_observer"] = ev

    r, ev = _check_bool(["registerReceiver", "SMS_RECEIVED"], min_hits=2)
    result["dynamic_sms_receiver_registration"] = r
    _evidence["dynamic_sms_receiver_registration"] = ev

    result["boot_persistence"] = _check_manifest_contains(["BOOT_COMPLETED"])
    r, ev = _check_bool_with_report_hint(
        ["START_STICKY", "AlarmManager", "setExactAndAllowWhileIdle"], report_extra_patterns.get("service_keepalive", list(global_extra)), min_hits=2)
    result["service_keepalive"] = r
    r, ev = _check_bool_with_report_hint(
        ["decrypt", "decode", "Cipher", "Base64"], report_extra_patterns.get("c2_encrypted_urls", list(global_extra)), min_hits=2)
    result["c2_encrypted_urls"] = r
    r, ev = _check_bool(["http://"], min_hits=1)
    result["cleartext_communication"] = r
    r, ev = _check_bool_with_report_hint(
        ["getDeviceId", "getSubscriberId", "getImei", "getSimSerialNumber"], report_extra_patterns.get("device_fingerprint_collection", list(global_extra)), min_hits=1)
    result["device_fingerprint_collection"] = r
    _evidence["device_fingerprint_collection"] = ev
    r, ev = _check_bool_with_report_hint(
        ["magisk", "isRooted", "google_sdk", "su"], report_extra_patterns.get("root_emulator_detection", list(global_extra)), min_hits=1)
    result["root_emulator_detection"] = r
    _evidence["root_emulator_detection"] = ev
    result["multi_process_architecture"] = _check_manifest_multi_process()
    r, ev = _check_bool_with_report_hint(
        ["TYPE_APPLICATION_OVERLAY", "WindowManager.addView", "SYSTEM_ALERT_WINDOW"], report_extra_patterns.get("overlay_phishing", list(global_extra)), min_hits=2)
    result["overlay_phishing"] = r
    _evidence["overlay_phishing"] = ev
    r, ev = _check_bool_with_report_hint(
        ["dispatchTouchEvent", "performClick", "MotionEvent"], report_extra_patterns.get("ad_click_fraud", list(global_extra)), min_hits=2)
    result["ad_click_fraud"] = r
    _evidence["ad_click_fraud"] = ev
    r, ev = _check_bool(["NotificationManager", "notify("], min_hits=2)
    result["notification_spam_or_phishing"] = r
    r, ev = _check_bool(["Runtime.exec", "ProcessBuilder", "/system/bin/sh"], min_hits=1)
    result["shell_command_execution"] = r
    _evidence["shell_command_execution"] = ev
    result["admin_abuse_signal"] = _check_manifest_contains_with_hint(
        ["DeviceAdminReceiver", "BIND_DEVICE_ADMIN"], report_extra_patterns.get("admin_abuse_signal", list(global_extra)))
    result["accessibility_abuse_signal"] = _check_manifest_contains(["BIND_ACCESSIBILITY_SERVICE", "AccessibilityService"])

    # ── 6 enhanced detections ──

    # 1. has_c2_communication: URL/IP + network request + data upload
    has_url, _ = _check_bool(["http://", "https://"], min_hits=1)
    has_network, ev_c2 = _check_bool_with_report_hint(
        ["HttpURLConnection", "Socket", "DefaultHttpClient"], report_extra_patterns.get("has_c2_communication", list(global_extra)), min_hits=1)
    has_post, _ = _check_bool(["setDoOutput", "POST", "OutputStream"], min_hits=1)
    result["has_c2_communication"] = has_url and has_network
    if result["has_c2_communication"]:
        _evidence["has_c2_communication"] = ev_c2
    if not result["has_c2_communication"] and global_extra:
        ekw = list(global_extra)[:10]
        r_kw, ev_kw = _check_bool(ekw, min_hits=1)
        if r_kw:
            result["has_c2_communication"] = True
            _evidence["has_c2_communication"] = ev_kw
        # Also search for POST patterns
        r_post, ev_post = _check_bool(["setDoOutput", "POST", "OutputStream"], min_hits=1)
        if r_post:
            result["has_c2_communication"] = True
            _evidence["has_c2_communication"] = ev_post

    # 2. data_exfiltration: fingerprint collection + network exfil
    has_collection = result["device_fingerprint_collection"]
    has_exfil_path, ev_exfil = _check_bool_with_report_hint(
        ["getBytes", "write", "POST", "OutputStream", "putStream"], report_extra_patterns.get("data_exfiltration", list(global_extra)), min_hits=2)
    result["data_exfiltration"] = has_collection and (has_network and has_exfil_path or has_post)
    if result["data_exfiltration"]:
        _evidence["data_exfiltration"] = ev_exfil

    # 3. sms_delete_capability
    r_del, ev_del = _check_bool_with_report_hint(
        ["ContentResolver.delete", "content://sms"], report_extra_patterns.get("sms_delete_capability", list(global_extra)), min_hits=2)
    r_del2, ev_del2 = _check_bool(["sms.delete", "sms/DELETE_SMS"], min_hits=1)
    result["sms_delete_capability"] = r_del or r_del2
    if r_del:
        _evidence["sms_delete_capability"] = ev_del
    elif r_del2:
        _evidence["sms_delete_capability"] = ev_del2

    # 4. call_forwarding
    r_cf, ev_cf = _check_bool_with_report_hint(
        ["setCallForward", "CF_ENABLE"], report_extra_patterns.get("call_forwarding", list(global_extra)), min_hits=2)
    r_cf2, ev_cf2 = _check_bool(["GSM_CALL_FORWARD", "CALL_FORWARD"], min_hits=1)
    result["call_forwarding"] = r_cf or r_cf2
    if r_cf:
        _evidence["call_forwarding"] = ev_cf
    elif r_cf2:
        _evidence["call_forwarding"] = ev_cf2

    # 5. dynamic_code_loading
    r_dcl, ev_dcl = _check_bool(
        ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", "loadDex"], min_hits=1
    )
    result["dynamic_code_loading"] = r_dcl
    if r_dcl:
        _evidence["dynamic_code_loading"] = ev_dcl

    # 6. encryption_hardcoded_key
    has_cipher, ev_cipher = _check_bool(["Cipher.getInstance", "SecretKeySpec", "IvParameterSpec"], min_hits=1)
    has_des, ev_des = _check_bool_with_report_hint(
        ["DES", "DESede", "\"DES\""], report_extra_patterns.get("encryption_hardcoded_key", list(global_extra)), min_hits=1)
    result["encryption_hardcoded_key"] = has_cipher and (has_des or result["c2_encrypted_urls"])
    if result["encryption_hardcoded_key"]:
        _evidence["encryption_hardcoded_key"] = ev_des
    result["_malicious_behavior_evidence"] = _evidence

    # ── report confirmation tracking ──
    report_confirmed = []
    if known_behaviors:
        for kb in known_behaviors:
            name = kb.get("name", "")
            risk = kb.get("risk", "")
            mapped_field = map_report_behavior_to_template_field(name)
            if mapped_field and mapped_field in result and mapped_field != "_malicious_behavior_evidence":
                report_confirmed.append({
                    "behavior_field": mapped_field,
                    "report_name": name,
                    "report_risk": risk,
                    "static_detected": bool(result.get(mapped_field, False)),
                    "report_confirmed": True,
                })
    result["suspicious_behavior_flags"] = _build_behavior_flags(result, report_confirmed, known_behaviors)
    result["device_fingerprint_details"] = _get_fingerprint_details(result)
    return result


def _check_bool(patterns, min_hits=1):
    try:
        results = search_code_for_pattern(patterns, apk_path=_apk_path)
        hit_count = sum(1 for p in patterns if results.get(p))
        return hit_count >= min_hits, results
    except Exception:
        return False, {}


def _check_bool_with_report_hint(patterns, extra_patterns, min_hits=1):
    """Check with standard patterns first, then expand with report-driven extra patterns. Returns (bool, combined_search_results)."""
    hit, results = _check_bool(patterns, min_hits)
    if hit:
        return True, results
    if extra_patterns:
        all_patterns = set(patterns)
        for ep in extra_patterns:
            all_patterns.add(ep)
        hit2, results2 = _check_bool(list(all_patterns), min_hits)
        if hit2:
            combined = dict(results2)
            # Preserve original pattern results if available
            for p in patterns:
                if p in results2:
                    combined[p] = results2[p]
            return True, combined
    return False, results


def _check_manifest_contains(patterns):
    try:
        manifest = get_android_manifest()
        return any(p in manifest for p in patterns)
    except Exception:
        return False


def _check_manifest_multi_process():
    try:
        manifest = get_android_manifest()
        return manifest.count('android:process=') > 1
    except Exception:
        return False


def _check_manifest_contains_with_hint(patterns, extra_patterns):
    """Check manifest with standard patterns, then expand with report-driven extra patterns."""
    if _check_manifest_contains(patterns):
        return True
    if extra_patterns:
        all_patterns = list(set(patterns + extra_patterns))
        return _check_manifest_contains(all_patterns)
    return False


def _build_behavior_flags(behavior, report_confirmed=None, known_behaviors=None):
    """
    Build suspicious_behavior_flags from detected behaviors.
    report_confirmed: list of dicts with report-confirmed behaviors
    known_behaviors: original known_behaviors list from report
    """
    flags = []
    flag_map = [
        ("sms_intercept_via_broadcast", "sms_broadcast_intercept", "CRITICAL"),
        ("sms_intercept_via_content_observer", "sms_content_observer", "CRITICAL"),
        ("dynamic_sms_receiver_registration", "dynamic_sms_receiver", "HIGH"),
        ("boot_persistence", "boot_persistence", "HIGH"),
        ("service_keepalive", "service_keepalive", "HIGH"),
        ("c2_encrypted_urls", "c2_encrypted_url", "HIGH"),
        ("cleartext_communication", "cleartext_communication", "MEDIUM"),
        ("device_fingerprint_collection", "device_fingerprint", "MEDIUM"),
        ("root_emulator_detection", "root_detection", "MEDIUM"),
        ("overlay_phishing", "overlay_phishing", "CRITICAL"),
        ("shell_command_execution", "shell_command_execution", "HIGH"),
        ("admin_abuse_signal", "admin_abuse", "HIGH"),
        ("accessibility_abuse_signal", "accessibility_abuse", "CRITICAL"),
        ("ad_click_fraud", "ad_click_fraud", "HIGH"),
        ("notification_spam_or_phishing", "notification_spam", "MEDIUM"),
        ("multi_process_architecture", "multi_process", "MEDIUM"),
        # New 6 fields
        ("has_c2_communication", "c2_communication", "CRITICAL"),
        ("data_exfiltration", "data_exfiltration", "CRITICAL"),
        ("sms_delete_capability", "sms_delete", "HIGH"),
        ("call_forwarding", "call_forwarding", "HIGH"),
        ("dynamic_code_loading", "dynamic_code_loading", "HIGH"),
        ("encryption_hardcoded_key", "encryption_hardcoded_key", "HIGH"),
    ]

    # Build set of report-confirmed field names for priority marking
    report_confirmed_fields = set()
    if report_confirmed:
        for rc in report_confirmed:
            report_confirmed_fields.add(rc.get("behavior_field", ""))

    for field, name, risk in flag_map:
        detected = behavior.get(field, False)
        flag = {
            "behavior": name,
            "detected": detected,
            "risk": risk,
        }
        if field in report_confirmed_fields:
            flag["priority_from_report"] = True
            flag["report_confirmed"] = True
        else:
            flag["priority_from_report"] = False
        flags.append(flag)

    return flags


def _get_fingerprint_details(mb_result=None):
    details = []
    fp_apis = {
        "android_id": ["Settings.Secure.ANDROID_ID"],
        "imei": ["getDeviceId", "getImei"],
        "imsi": ["getSubscriberId"],
        "phone_number": ["getLine1Number"],
        "sim_serial": ["getSimSerialNumber"],
        "device_model": ["Build.MODEL"],
    }
    try:
        all_p = [p for pl in fp_apis.values() for p in pl]
        results = search_code_for_pattern(all_p)
        has_c2 = False
        if mb_result and isinstance(mb_result, dict):
            has_c2 = mb_result.get("has_c2_communication", False)
        for field, pats in fp_apis.items():
            if any(results.get(p) for p in pats):
                details.append({"field_name": field, "collection_method": pats[0], "transmitted": has_c2})
    except Exception:
        pass
    return details


# ── native_analysis ────────────────────────────────────────────────────────────

def extract_native_analysis(apk_path):
    result = dict(NATIVE_ANALYSIS_DEFAULT)
    native_libs = get_native_libs(apk_path)

    if not native_libs:
        try:
            libs = androguard_extractor.get_libraries(apk_path)
            if libs:
                result["native_libraries"] = libs
                result["native_library_count"] = len(libs)
        except Exception:
            pass
        return result

    lib_entries = []
    abi_set = set()
    standard_libs = ["libflutter.so", "libv8.so", "libnode.so", "libc++_shared.so"]

    for lp in native_libs:
        parts = lp.split("/")
        abi = parts[1] if len(parts) >= 3 else ""
        abi_set.add(abi)
        size = get_file_size_in_apk(apk_path, lp)
        entropy = compute_file_entropy_in_apk(apk_path, lp)
        lib_name = os.path.basename(lp)

        is_standard = lib_name in standard_libs
        is_suspicious = not is_standard and entropy > 7.0
        note = "非标准库，高熵值，疑似包含加密逻辑" if is_suspicious else ("自定义原生库" if not is_standard else "系统/框架标准库")

        lib_entries.append({
            "path": lp,
            "abi": abi,
            "size_bytes": size,
            "entropy": entropy,
            "is_standard_library": is_standard,
            "is_suspicious": is_suspicious,
            "note": note,
        })

    result["native_library_count"] = len(lib_entries)
    result["native_libraries"] = lib_entries
    result["native_abi_support"] = sorted(abi_set) if abi_set else []

    # Executable files
    exe_files = []
    all_files = list_apk_files(apk_path)
    for fpath in all_files:
        data = read_apk_file_bytes(apk_path, fpath)
        if len(data) >= 4 and data[:4] == b'\x7fELF':
            abi = ""
            m = re.search(r'(armeabi|arm64-v8a|x86|x86_64)', fpath)
            if m:
                abi = m.group(1)
            exe_files.append({
                "path": fpath,
                "abi": abi,
                "risk_level": "HIGH",
                "note": "ELF可执行文件，可能为恶意守护进程或工具",
            })
    result["executable_files"] = exe_files

    # Suspicious native libs
    suspicious_native = []
    for entry in lib_entries:
        if entry["is_suspicious"]:
            suspicious_native.append({
                "library_name": os.path.basename(entry["path"]),
                "abi": entry["abi"],
                "suspicious_reason": entry["note"],
            })
    result["suspicious_native_libraries"] = suspicious_native

    return result


# ── Load Axplorer API database ─────────────────────────────────────────────────

def load_axplorer_apis(excel_path):
    try:
        import openpyxl
        wb = openpyxl.load_workbook(excel_path, read_only=True)
        ws = wb.active
        result = {}
        header = None
        for row in ws.iter_rows(values_only=True):
            if header is None:
                header = [str(c).strip().lower() if c else "" for c in row]
                api_idx = None
                for i, h in enumerate(header):
                    if "api" in h and "level" not in h:
                        api_idx = i
                if api_idx is None:
                    break
                continue
            if api_idx < len(row) and row[api_idx]:
                api_name = str(row[api_idx]).strip()
                result[api_name] = {"row": list(row)}
        wb.close()
        return result
    except Exception:
        return {}


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: extract_code_behavior.py <apk_path> <output_dir> [report_md_path]")
        sys.exit(1)

    apk_path = sys.argv[1]
    output_dir = sys.argv[2]
    report_md_path = sys.argv[3] if len(sys.argv) >= 4 else None
    os.makedirs(output_dir, exist_ok=True)

    global _apk_path
    _apk_path = apk_path

    print("[sub02] Starting sub-agent 02 extraction...")

    # Parse report behaviors if available
    known_behaviors = None
    behavior_keywords = None
    behavior_techs = None
    if report_md_path and os.path.isfile(report_md_path):
        print(f"  [*] Loading known behaviors from report: {os.path.basename(report_md_path)}")
        known_behaviors, behavior_keywords, behavior_techs = parse_report_behaviors(report_md_path)
        if known_behaviors:
            print(f"      Found {len(known_behaviors)} known behaviors: {[b['name'] for b in known_behaviors]}")
        if behavior_keywords:
            print(f"      Found {len(behavior_keywords)} keywords: {behavior_keywords[:10]}")
        if behavior_techs:
            print(f"      Found {len(behavior_techs)} behavior techs: {[bt['name'] for bt in behavior_techs]}")

    extracted_dir = os.path.join(os.path.dirname(apk_path), "extracted_tmp")
    axplorer_apis = load_axplorer_apis(AXPLORER_XLSX)

    # malicious_behavior FIRST (code_analysis depends on it for snippets)
    print("  [*] Extracting malicious_behavior...")
    malicious_behavior = extract_malicious_behavior(apk_path, known_behaviors, behavior_keywords, behavior_techs)
    evidence = malicious_behavior.pop("_malicious_behavior_evidence", {})
    save_json(malicious_behavior, os.path.join(output_dir, "malicious_behavior.json"))

    print("  [*] Extracting code_analysis...")
    code_analysis = extract_code_analysis(apk_path, extracted_dir, axplorer_apis, malicious_behavior, behavior_keywords, evidence)
    save_json(code_analysis, os.path.join(output_dir, "code_analysis.json"))

    print("  [*] Extracting native_analysis...")
    native_analysis = extract_native_analysis(apk_path)
    save_json(native_analysis, os.path.join(output_dir, "native_analysis.json"))

    # Clean up extracted dir
    import shutil
    if os.path.exists(extracted_dir):
        shutil.rmtree(extracted_dir, ignore_errors=True)

    print("[sub02] Done.")


if __name__ == "__main__":
    main()
