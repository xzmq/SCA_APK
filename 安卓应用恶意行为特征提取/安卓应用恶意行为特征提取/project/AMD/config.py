"""
config.py - Global configuration for AMD static analysis pipeline.
All paths, constants, permission mappings, and default templates are centralized here.
"""
import os
import tempfile

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))  # 特征json格式设计/

RESOURCE_DIR = os.path.join(PROJECT_ROOT, "resource")
MALWARE_FAMILY_XLSX = os.path.join(RESOURCE_DIR, "malradar_reports_sha256_mapping_260527_01.xlsx")
AXPLORER_XLSX = os.path.join(RESOURCE_DIR, "Axplorer汇总（增加api_level_26-36数据）.xlsx")
PERMISSION_MAPPING_JSON = os.path.join(RESOURCE_DIR, "permission_mapping.json")
CONSTANT_PY = os.path.join(RESOURCE_DIR, "constant.py")
REPORT_MAPPING_XLSX = os.path.join(RESOURCE_DIR, "report_apk_mappings_new.xlsx")
REPORT_MD_DIR = os.path.join(PROJECT_ROOT, "resource", "report_md")

# jadx-gui binary: env override → Windows install (D:\jadx-1.5.6) → macOS original path.
JADX_GUI_PATH = os.environ.get(
    "JADX_GUI_PATH",
    r"D:\jadx-1.5.6\bin\jadx-gui.bat"
    if os.path.isfile(r"D:\jadx-1.5.6\bin\jadx-gui.bat")
    else r"/Users/yqh/knowledge_graph/jadx-1.5.6/bin/jadx-gui",
)
# jadx CLI (Phase 0.5 full decompilation). Derived from the GUI path but with an
# explicit env override — the naive string replace in run_pipeline breaks on
# Windows paths (jadx-gui.bat → replace misses → GUI launcher used as CLI).
JADX_CLI_PATH = os.environ.get(
    "JADX_CLI_PATH",
    JADX_GUI_PATH.replace("jadx-gui.bat", "jadx.bat").replace("jadx-gui", "jadx"),
)
JADX_MCP_SERVER_SCRIPT = r"/Users/yqh/knowledge_graph/jadx-mcp-server/jadx_mcp_server.py"

# Java helper that sets the JADX-AI-MCP plugin port via java.util.prefs (the
# plugin reads the port from Preferences; `defaults write` does NOT reach it).
JAVA_BIN = os.environ.get(
    "JAVA_BIN",
    r"D:\jdk-12.0.1\bin\java.exe"
    if os.path.isfile(r"D:\jdk-12.0.1\bin\java.exe")
    else r"/Library/Java/JavaVirtualMachines/temurin-11.jdk/Contents/Home/bin/java",
)
JADX_PREFS_JAR = os.path.join(BASE_DIR, "jadxaimcp_prefs.jar")

# ── Parallel agent support ─────────────────────────────────────────────────────
# Each agent gets its own jadx plugin port and MCP server port so multiple
# run_pipeline.py instances can coexist. Set AGENT_ID via environment variable.
AGENT_ID = int(os.environ.get("AGENT_ID", "0"))
JADX_GUI_PLUGIN_PORT = 8650 + AGENT_ID
JADX_MCP_SERVER_PORT = 8651 + AGENT_ID
# Lock files live in the OS temp dir (works on Windows and POSIX).
_LOCK_DIR = tempfile.gettempdir()
JADX_LAUNCH_LOCK_FILE = os.path.join(_LOCK_DIR, "jadx_launch.lock")
ADB_LOCK_FILE = os.path.join(_LOCK_DIR, "adb_dynamic_unpack.lock")
JADX_MCP_READY_TIMEOUT = 180
JADX_MCP_POLL_INTERVAL = 2
JADX_LAUNCH_TIMEOUT = 120

OUTPUT_DIR_NAME = "output"

# ── opencode LLM synthesis config (for sub04 dynamic fields) ──────────────────
OPENCODE_BIN = os.environ.get("OPENCODE_BIN", "opencode")
SUB04_AGENT_NAME = "sub04_synthesis"
LLM_SYNTHESIS_TIMEOUT = 600  # seconds

# ── Unpacking config (F-E: dynamic DEX dumping) ────────────────────────────────
# Android SDK root: env override → Windows install (D:\Android\sdk) → macOS original.
_SDK_ROOT = os.environ.get(
    "ANDROID_SDK_ROOT",
    r"D:\Android\sdk" if os.path.isdir(r"D:\Android\sdk")
    else os.path.expanduser("~/Library/Android/sdk"),
)
_PY_BIN = "/Library/Frameworks/Python.framework/Versions/3.12/bin"


def _resolve_tool(env_var, *fallback_abs_paths, bare=""):
    """Resolve a tool binary: env var → known absolute paths → bare name."""
    env_val = os.environ.get(env_var)
    if env_val and os.path.isfile(env_val):
        return env_val
    for p in fallback_abs_paths:
        if os.path.isfile(p):
            return p
    return env_val or bare


ADB_BIN = _resolve_tool(
    "ADB_BIN",
    os.path.join(_SDK_ROOT, "platform-tools", "adb.exe"),
    os.path.join(_SDK_ROOT, "platform-tools", "adb"),
    bare="adb",
)
FRIDA_BIN = _resolve_tool(
    "FRIDA_BIN",
    os.path.join(_PY_BIN, "frida"),
    bare="frida",
)
EMULATOR_BIN = _resolve_tool(
    "EMULATOR_BIN",
    os.path.join(_SDK_ROOT, "emulator", "emulator.exe"),
    os.path.join(_SDK_ROOT, "emulator", "emulator"),
    bare="emulator",
)
FRIDA_SERVER_DEVICE_PATH = "/data/local/tmp/fs"
FRIDA_SERVER_PORT = 38042  # non-standard port to avoid packer port-scan detection
UNPACKING_CONFIDENCE_THRESHOLD = 60  # minimum confidence to trigger unpacking
UNPACKING_TIMEOUT = 120  # seconds for static unpacking attempt
DYNAMIC_UNPACKING_TIMEOUT = 300  # seconds for dynamic (Frida) unpacking
EMULATOR_AVD_NAME = os.environ.get("EMULATOR_AVD_NAME", "unpack_avd")
EMULATOR_AVD_32_NAME = os.environ.get("EMULATOR_AVD_32_NAME", "unpack_avd_32")
ANDROID_SDK_ROOT = os.environ.get("ANDROID_SDK_ROOT", _SDK_ROOT)

# frida-gadget settings
GADGET_PORT = 27042  # port frida-gadget listens on inside the app
# apktool / frida-gadget binaries: env override → Windows (D:\Android\tools) → macOS original.
APKTOOL_JAR = os.environ.get(
    "APKTOOL_JAR",
    r"D:\Android\tools\apktool.jar" if os.path.isfile(r"D:\Android\tools\apktool.jar")
    else os.path.expanduser("~/Library/Android/tools/apktool.jar"),
)
GADGET_BINARY_DIR = os.environ.get(
    "GADGET_BINARY_DIR",
    r"D:\Android\tools\frida-gadget" if os.path.isdir(r"D:\Android\tools\frida-gadget")
    else os.path.expanduser("~/Library/Android/tools/frida-gadget"),
)

# ── Malicious permission combos ───────────────────────────────────────────────
MALICIOUS_PERM_COMBOS = [
    {
        "attack_type": "短信窃取/拦截",
        "required_perms": ["RECEIVE_SMS", "READ_SMS", "INTERNET"],
        "risk_level": "CRITICAL",
    },
    {
        "attack_type": "设备信息窃取",
        "required_perms": ["READ_PHONE_STATE", "INTERNET"],
        "risk_level": "HIGH",
    },
    {
        "attack_type": "静默后台驻留",
        "required_perms": ["RECEIVE_BOOT_COMPLETED", "WAKE_LOCK"],
        "risk_level": "MEDIUM",
    },
    {
        "attack_type": "修改系统设置",
        "required_perms": ["WRITE_SETTINGS"],
        "risk_level": "HIGH",
    },
    {
        "attack_type": "悬浮窗覆盖",
        "required_perms": ["SYSTEM_ALERT_WINDOW"],
        "risk_level": "CRITICAL",
    },
    {
        "attack_type": "隐私数据窃取",
        "required_perms": ["READ_CONTACTS", "INTERNET"],
        "risk_level": "HIGH",
    },
    {
        "attack_type": "文件窃取",
        "required_perms": ["WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "INTERNET"],
        "risk_level": "MEDIUM",
    },
]

# ── High-signal permissions ───────────────────────────────────────────────────
HIGH_SIGNAL_PERMISSIONS = [
    "RECEIVE_SMS",
    "READ_SMS",
    "READ_PHONE_STATE",
    "SEND_SMS",
    "READ_CONTACTS",
    "WRITE_EXTERNAL_STORAGE",
    "BIND_ACCESSIBILITY_SERVICE",
]

HIGH_SIGNAL_MALICIOUS_USAGE = {
    "RECEIVE_SMS": "拦截接收到的短信，配合abortBroadcast()可实现短信静默拦截，常用于窃取验证码或银行卡通知",
    "READ_SMS": "读取设备中已存储的短信，提取短信中的验证码、银行通知等敏感信息",
    "READ_PHONE_STATE": "获取IMEI、IMSI、电话号码、SIM序列号等，用于设备指纹识别和唯一标识追踪",
    "SEND_SMS": "代用户发送短信，可用于订阅欺诈、发送高价短信(WAP计费)、或钓鱼链接扩散",
    "READ_CONTACTS": "窃取用户通讯录，用于社交工程攻击或传播恶意链接",
    "WRITE_EXTERNAL_STORAGE": "在外部存储写入恶意文件、下载次级APK载荷或存放窃取数据",
    "BIND_ACCESSIBILITY_SERVICE": "滥用无障碍服务实现自动化点击、监控屏幕内容、自动发送短信或验证码，是LIBSKIN等家族的核心攻击能力",
}

# ── Default empty values ──────────────────────────────────────────────────────
FILE_BASIC_DEFAULT = {
    "sha256": "",
    "md5": "",
    "sha1": "",
    "file_size_bytes": 0,
    "file_entropy": 0,
    "package_name": "",
    "package_name_entropy": 0,
    "app_label": "",
    "version_code": 0,
    "version_name": "",
    "min_sdk_version": 0,
    "target_sdk_version": 0,
    "is_packed": False,
    "malware_family": "",
}

CERT_ANALYSIS_DEFAULT = {
    "is_self_signed": False,
    "is_debug_certificate": False,
    "signing_algorithm": "",
    "public_key_type": "",
    "public_key_bit_length": 0,
    "subject": "",
    "issuer": "",
    "subject_common_name": "",
    "subject_organization": "",
    "subject_country": "",
    "valid_from": "",
    "valid_until": "",
    "valid_days": 0,
    "public_key_hash": "",
    "fingerprint_sha256": "",
    "fingerprint_sha1": "",
    "subject_anomaly": False,
    "signer_certificates": [],
}

PERMISSIONS_DEFAULT = {
    "total_perm_count": 0,
    "dangerous_perm_count": 0,
    "all_permissions": [],
    "malicious_perm_combos": [],
    "high_signal_permissions": [],
    "custom_permissions": [],
    "uses_features": [],
}

COMPONENTS_DEFAULT = {
    "suspicious_activities": [],
    "suspicious_services": [],
    "suspicious_receivers": [],
    "suspicious_providers": [],
    "component_export_summary": {
        "activity_total": 0,
        "activity_exported": 0,
        "service_total": 0,
        "service_exported": 0,
        "service_accessibility_count": 0,
        "receiver_total": 0,
        "receiver_exported": 0,
        "provider_total": 0,
    },
}

CODE_ANALYSIS_DEFAULT = {
    "is_code_obfuscated": False,
    "obfuscation_techniques": [],
    "high_entropy_files_count": 0,
    "high_entropy_files": [],
    "dex_count": 0,
    "dex_files_list": [],
    "has_dynamic_dex_loading": False,
    "weak_cryptographic_algorithms": [],
    "sensitive_api_calls": [],
    "malicious_code_snippets": [],
    "webview_security_config": {
        "javascript_enabled": False,
        "save_password_enabled": False,
        "allow_file_access": False,
        "loaded_urls": [],
    },
    "has_embedded_payload": False,
    "embedded_payloads": [],
    "is_packed_and_repackaged": False,
    "anti_analysis": [],
    "string_encryption": False,
    "related_native_libs_for_crypt": [],
}

MALICIOUS_BEHAVIOR_DEFAULT = {
    "sms_intercept_via_broadcast": False,
    "sms_intercept_via_content_observer": False,
    "dynamic_sms_receiver_registration": False,
    "boot_persistence": False,
    "service_keepalive": False,
    "c2_encrypted_urls": False,
    "cleartext_communication": False,
    "device_fingerprint_collection": False,
    "root_emulator_detection": False,
    "multi_process_architecture": False,
    "overlay_phishing": False,
    "ad_click_fraud": False,
    "notification_spam_or_phishing": False,
    "shell_command_execution": False,
    "admin_abuse_signal": False,
    "accessibility_abuse_signal": False,
    "has_c2_communication": False,
    "data_exfiltration": False,
    "sms_delete_capability": False,
    "call_forwarding": False,
    "dynamic_code_loading": False,
    "encryption_hardcoded_key": False,
    "suspicious_behavior_flags": [],
    "device_fingerprint_details": [],
}

NATIVE_ANALYSIS_DEFAULT = {
    "native_library_count": 0,
    "native_libraries": [],
    "executable_files": [],
    "native_abi_support": [],
    "suspicious_native_libraries": [],
}

C2_COMMUNICATION_DEFAULT = {
    "has_c2": False,
    "c2_servers": [],
    "encrypted_c2_indicators": [],
    "c2_communication_pattern": {
        "uses_http_cleartext": False,
        "uses_https": False,
        "uses_socket_direct_connection": False,
        "uses_http_url_connection": False,
        "uses_dynmaic_url_resolution": False,
        "has_retry_mechanism": False,
        "data_exfiltration_format": "",
    },
    "cleartext_traffic_permitted": False,
    "c2_command_categories": [],
    "c2_commands": [],
}

IOCS_DEFAULT = {
    "c2_urls": [],
    "c2_ips": [],
    "crypto_wallet_addresses": {
        "BTC": [],
        "ETH": [],
        "XMR": [],
        "TRX": [],
    },
    "suspicious_domains_detail": [],
}

DATA_CLASSIFICATION_DEFAULT = []

RISK_DIMENSION_SCORES_DEFAULT = {
    "data_exfiltration": {"score": 0, "out_of": 10, "risk_level": "", "evidence": ""},
    "c2_remote_control": {"score": 0, "out_of": 10, "risk_level": "", "evidence": ""},
    "data_steal": {"score": 0, "out_of": 10, "risk_level": "", "evidence": ""},
    "encryption_obfuscation": {"score": 0, "out_of": 10, "risk_level": "", "evidence": ""},
    "persistence": {"score": 0, "out_of": 10, "risk_level": "", "evidence": ""},
    "anti_detection": {"score": 0, "out_of": 10, "risk_level": "", "evidence": ""},
    "total": {"score": 0, "risk_level": ""},
}

ADVERTISEMENT_ANALYSIS_DEFAULT = {
    "ad_sdk_list": [],
    "ad_behaviors": {
        "fullscreen_ad_detected": False,
        "notification_ad_detected": False,
        "lockscreen_ad_detected": False,
        "popup_ad_detected": False,
        "click_fraud_detected": False,
        "overlay_ad_detected": False,
        "silent_download_promotion": False,
    },
}

ATTACK_PROFILE_DEFAULT = {
    "developer_subject": "",
    "app_function_summary": "",
    "distribution_form": "",
    "core_framework": "",
    "development_language": "",
    "obfuscation_solution": "",
    "network_stack": "",
    "encryption_library": "",
    "c2_flow": {
        "decryption_step": "",
        "destinations_summary": {
            "total_count": 0,
            "top_5": [],
            "protocol_distribution": {},
        },
    },
    "overall_judgment": {
        "risk_label": "",
        "risk_score": 0,
        "summary": "",
    },
    "malware_family_indicators": [],
    "attack_chains": [],
    "behavior_tags": [],
}

# ── All 13 top-level field defaults ───────────────────────────────────────────
ALL_DEFAULTS = {
    "file_basic": FILE_BASIC_DEFAULT,
    "certificate_analysis": CERT_ANALYSIS_DEFAULT,
    "permissions": PERMISSIONS_DEFAULT,
    "components": COMPONENTS_DEFAULT,
    "code_analysis": CODE_ANALYSIS_DEFAULT,
    "malicious_behavior": MALICIOUS_BEHAVIOR_DEFAULT,
    "native_analysis": NATIVE_ANALYSIS_DEFAULT,
    "c2_communication": C2_COMMUNICATION_DEFAULT,
    "iocs": IOCS_DEFAULT,
    "data_classification": DATA_CLASSIFICATION_DEFAULT,
    "risk_dimension_scores": RISK_DIMENSION_SCORES_DEFAULT,
    "advertisement_analysis": ADVERTISEMENT_ANALYSIS_DEFAULT,
    "attack_profile": ATTACK_PROFILE_DEFAULT,
}
