"""
packer_signatures.py - Packer/protector indicator database for Android APK packing detection.
Covers 15+ mainstream packing solutions with Java package patterns, .so library names,
and expected DEX encryption locations.
"""

# DEX magic bytes (for validating decrypted DEX)
DEX_MAGIC_BYTES = [
    b'dex\n035\x00',
    b'dex\n036\x00',
    b'dex\n037\x00',
    b'dex\n038\x00',
    b'dex\n039\x00',
    b'dex\n040\x00',
]

# DEX magic as hex prefix for binary scanning
DEX_MAGIC_HEX_PREFIXES = [m.hex() for m in DEX_MAGIC_BYTES]

# ── Packer indicator database ────────────────────────────────────────────────
# Each entry: packer_name → {java_patterns, so_patterns, dex_location, description}
PACKER_INDICATORS = {
    "360 Jiagu (360加固保)": {
        "java_patterns": [
            "com.qihoo.util", "com.qihoo.jiagu", "com.stealers",
            "com.qihoo.sdk", "QihooHandler",
        ],
        "so_patterns": ["libjiagu", "libmobisec", "libDexHelper", "libprotect"],
        "dex_location": "assets/",
        "description": "奇虎360加固保，国内主流加固方案",
    },
    "Bangcle (梆梆安全)": {
        "java_patterns": [
            "com.bangcle", "com.secapk", "com.secapkwrapper",
            "com.bangcle.tools", "SecAPKWrapper",
        ],
        "so_patterns": ["libchaosvmp", "libsecexe", "libsecmain", "libbcp"],
        "dex_location": "assets/",
        "description": "梆梆安全加固，企业级移动应用安全保护",
    },
    "Ijiami (爱加密)": {
        "java_patterns": [
            "com.ijiami", "com.ijm", "com.ijiami.jm",
            "com.ijiami.app", "IjiamiSDK",
        ],
        "so_patterns": ["libexec", "libdexhelper", "libijm", "libload"],
        "dex_location": "assets/",
        "description": "爱加密加固，国内常用加固方案",
    },
    "Tencent Legu (腾讯乐固)": {
        "java_patterns": [
            "com.tencent.beg", "com.tencent.StubShell",
            "com.tencent.bugly", "TencentApplication",
        ],
        "so_patterns": ["libshell", "libshella", "libtup", "libtprt"],
        "dex_location": "assets/",
        "description": "腾讯乐固加固",
    },
    "Alibaba Jiagu (阿里聚安全)": {
        "java_patterns": [
            "com.alibaba.jq", "com.ali.jq", "com.taobao.jq",
            "com.alibaba.security",
        ],
        "so_patterns": ["libjiagu", "libpreverify1", "libpreverify"],
        "dex_location": "assets/",
        "description": "阿里聚安全加固",
    },
    "NQShield (网秦)": {
        "java_patterns": ["com.nqshield", "com.nq", "NQApplication"],
        "so_patterns": ["libnqshield", "libnq", "libnqsec"],
        "dex_location": "assets/",
        "description": "网秦加固",
    },
    "Allerta (娜迦)": {
        "java_patterns": ["com.allerta", "com.naega", "NagaApplication"],
        "so_patterns": ["libnaga", "libal", "libnaga_main"],
        "dex_location": "assets/",
        "description": "娜迦加固，常见于国内恶意软件",
    },
    "Baidu Jiagu (百度加固)": {
        "java_patterns": ["com.baidu.japi", "com.baidu.protect", "BaiduJapi"],
        "so_patterns": ["libbaiduprotect", "libbaidu", "libjapi"],
        "dex_location": "assets/",
        "description": "百度加固",
    },
    "DexProtector": {
        "java_patterns": ["com.dexprotector", "DexProtectorUtils"],
        "so_patterns": ["libdp.so", "libdexprotector"],
        "dex_location": "assets/",
        "description": "DexProtector 国际商业加固方案",
    },
    "APKProtect": {
        "java_patterns": ["com.apkprotect", "APKProtect"],
        "so_patterns": ["libapkprotect"],
        "dex_location": "assets/",
        "description": "APKProtect 加固",
    },
    "Mobikey": {
        "java_patterns": ["com.mobikey", "MobikeyApplication"],
        "so_patterns": ["libmobikey"],
        "dex_location": "assets/",
        "description": "Mobikey 加固",
    },
    "Custom Shell (通用壳)": {
        "java_patterns": [
            "com.shell.SuperApplication", "com.shell", "com.app.shell",
            "ShellApplication", "ProxyApplication",
            "WrapperApplication", "ProtectApplication", "StubApplication",
        ],
        "so_patterns": [],
        "dex_location": "assets/",
        "description": "通用壳/自定义壳，非特定厂商",
    },
    "ReDex (Facebook)": {
        "java_patterns": ["ReDex", "com.facebook.redex"],
        "so_patterns": [],
        "dex_location": None,
        "description": "ReDex 是 Facebook 的 DEX 优化器，非传统壳但会改变 DEX 结构",
    },
    "Nagain (娜迦信息)": {
        "java_patterns": ["com.nagain", "NagainApplication"],
        "so_patterns": ["libnagain", "libng"],
        "dex_location": "assets/",
        "description": "娜迦信息加固",
    },
    "Megvii (旷视)": {
        "java_patterns": ["com.megvii", "com.facepp"],
        "so_patterns": ["libmegvii"],
        "dex_location": "assets/",
        "description": "旷视安全加固",
    },
}

# ── Generic packer behavior patterns (not vendor-specific) ─────────────────────
GENERIC_PACKER_BEHAVIORS = {
    "dex_class_loader": [
        "DexClassLoader", "InMemoryDexClassLoader", "PathClassLoader",
        "dalvik.system.DexFile", "defineClass", "BaseDexClassLoader",
    ],
    "stub_application_indicators": [
        "StubApplication", "ProxyApplication", "ShellApplication",
        "WrapperApplication", "ProtectApplication", "MainApplication",
        "StubApp", "ShellApp",
    ],
    "runtime_dex_loading": [
        "loadDex", "loadClass", "loadDexFile",
        "getDexFile", "openDexFile", "readDexFromAssets",
    ],
}


def get_all_java_patterns():
    """Return flat list of all Java package/class patterns for packer detection."""
    patterns = []
    for info in PACKER_INDICATORS.values():
        patterns.extend(info["java_patterns"])
    return patterns


def get_all_so_patterns():
    """Return flat list of all .so library name patterns for packer detection."""
    patterns = []
    for info in PACKER_INDICATORS.values():
        patterns.extend(info["so_patterns"])
    return patterns


def match_packer_by_java(java_pattern_found):
    """Given a Java pattern that was found in the APK, return the matching packer name.
    Returns packer name string or "" if no match.
    """
    for packer_name, info in PACKER_INDICATORS.items():
        if java_pattern_found in info["java_patterns"]:
            return packer_name
    return ""


def match_packer_by_so(so_name):
    """Given a .so filename, return the matching packer name.
    Returns packer name string or "" if no match.
    """
    for packer_name, info in PACKER_INDICATORS.items():
        for so_pat in info["so_patterns"]:
            if so_pat in so_name.lower():
                return packer_name
    return ""


def get_packer_dex_location(packer_name):
    """Get the expected DEX encryption location for a given packer.
    Returns "assets/" or None.
    """
    if packer_name in PACKER_INDICATORS:
        return PACKER_INDICATORS[packer_name].get("dex_location")
    return "assets/"


def is_valid_dex(data):
    """Check if data starts with a valid DEX magic header.
    Accepts bytes input.
    """
    if not data or len(data) < 8:
        return False
    return any(data.startswith(magic) for magic in DEX_MAGIC_BYTES)


def find_dex_magic_offset(data):
    """Find the offset of DEX magic bytes in binary data.
    Returns offset (int) or -1 if not found.
    """
    for magic in DEX_MAGIC_BYTES:
        idx = data.find(magic)
        if idx >= 0:
            return idx
    return -1
