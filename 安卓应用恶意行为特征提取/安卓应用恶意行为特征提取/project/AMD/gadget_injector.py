"""
gadget_injector.py - frida-gadget injection into APK for Java bridge support.

frida-gadget runs inside the app process, providing full Java VM access.
This replaces the remote-device frida-server approach where Java bridge
was unavailable (typeof Java === 'undefined').

Workflow:
  1. Decompile APK with apktool
  2. Find Application class from AndroidManifest.xml
  3. Patch Application.smali to load frida-gadget at startup
  4. Add libfrida-gadget.so + config to lib/{arch}/
  5. Recompile with apktool
  6. Sign with debug key
  7. Return path to gadget-injected APK
"""
import os
import sys
import shutil
import tempfile
import subprocess
import struct
import zipfile
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repacker import _ensure_debug_keystore, _find_apksigner, _find_jarsigner, \
    _DEBUG_KEY_ALIAS, _DEBUG_KEY_PASS, _DEBUG_STORE_PASS
from config import APKTOOL_JAR as _APKTOOL_JAR_CFG, GADGET_BINARY_DIR as _GADGET_DIR_CFG

# Binary locations: config (env-overridable, cross-platform) first, legacy
# macOS paths as fallback.
_APKTOOL_JAR = _APKTOOL_JAR_CFG if os.path.isfile(_APKTOOL_JAR_CFG) \
    else os.path.expanduser("~/Library/Android/tools/apktool.jar")
_GADGET_DIR = _GADGET_DIR_CFG if os.path.isdir(_GADGET_DIR_CFG) \
    else os.path.expanduser("~/Library/Android/tools/frida-gadget")
_GADGET_PORT = 27042

_GADGET_CONFIG = {
    "interaction": {
        "type": "listen",
        "address": "127.0.0.1",
        "port": _GADGET_PORT,
        "on_load": "wait",
    }
}


def _run_apktool(args, cwd=None, timeout=600):
    import sys as _sys
    cmd = ["java", "-jar", _APKTOOL_JAR] + args
    env = os.environ.copy()
    # Strip global memory caps (e.g. JAVA_TOOL_OPTIONS=-Xmx512m) that starve
    # apktool on large APKs; give it a healthy dedicated heap instead.
    for var in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        env.pop(var, None)
    env["JAVA_OPTS"] = "-Xmx2g"
    if _sys.platform == "win32":
        env["PATH"] = r"D:\jdk-12.0.1\bin;" + env.get("PATH", "")
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace", cwd=cwd, env=env,
    )
    if result.returncode != 0:
        print(f"  [!] [GadgetInjector] apktool failed: {result.stderr[:300]}")
    return result.returncode == 0, result.stdout, result.stderr


def _sign_apk(apk_path):
    keystore = _ensure_debug_keystore()
    if not keystore:
        return False

    apksigner = _find_apksigner()
    if apksigner:
        try:
            # apksigner may be a JVM-direct command list ([java, -jar, x.jar])
            # or a plain executable path (string). Argument order matters:
            # options first, APK path LAST.
            if isinstance(apksigner, list):
                cmd = apksigner + ["sign"]
            else:
                cmd = [apksigner, "sign"]
            subprocess.run(
                cmd + [
                    "--ks", keystore,
                    "--ks-key-alias", _DEBUG_KEY_ALIAS,
                    "--ks-pass", f"pass:{_DEBUG_STORE_PASS}",
                    "--key-pass", f"pass:{_DEBUG_KEY_PASS}",
                    apk_path,
                ],
                check=True, capture_output=True, timeout=120)
            print("  [+] [GadgetInjector] Signed with apksigner")
            return True
        except Exception:
            pass

    jarsigner = _find_jarsigner()
    if jarsigner:
        try:
            subprocess.run([
                jarsigner, "-keystore", keystore,
                "-storepass", _DEBUG_STORE_PASS,
                "-keypass", _DEBUG_KEY_PASS,
                "-signedjar", apk_path + ".signed", apk_path,
                _DEBUG_KEY_ALIAS,
            ], check=True, capture_output=True, timeout=60)
            shutil.move(apk_path + ".signed", apk_path)
            print("  [+] [GadgetInjector] Signed with jarsigner")
            return True
        except Exception:
            pass

    return False


def _find_application_class(manifest_path):
    """Extract the Application class name from the <application> tag of an
    apktool-decoded AndroidManifest.xml.

    Only looks INSIDE the <application ...> opening tag — the naive
    'first android:name in file' approach wrongly matched <uses-permission>.
    """
    import re
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            content = f.read()
        m = re.search(r"<application\b[^>]*>", content, re.DOTALL)
        if not m:
            return None
        app_tag = m.group(0)
        name_m = re.search(r'android:name="([^"]+)"', app_tag)
        if name_m:
            app_name = name_m.group(1)
            if app_name.startswith("."):
                package_match = re.search(r'package="([^"]+)"', content)
                if package_match:
                    app_name = package_match.group(1) + app_name
            # Guard against obviously non-class values
            if "permission" in app_name.lower():
                return None
            return app_name
    except Exception:
        pass
    return None


def _class_to_smali_path(class_name):
    """Convert a Java class name to its smali file path.
    e.g., com.example.App -> com/example/App.smali
    """
    return class_name.replace(".", "/") + ".smali"


def _patch_smali_add_loadlibrary(smali_path):
    """Patch a smali file to add System.loadLibrary("frida-gadget") in <clinit>.
    If <clinit> exists, prepend the call. If not, add a new <clinit> method.
    Returns True on success.
    """
    with open(smali_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    load_code = (
        '    const-string v0, "frida-gadget"\n'
        '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
    )

    if "# method: static constructor" in content or ".method static constructor <clinit>" in content:
        if ".method static constructor <clinit>" in content:
            patch = ".method static constructor <clinit>()V\n    .registers 1\n\n" + load_code
            content = content.replace(
                ".method static constructor <clinit>()V",
                patch,
                1,
            )
            with open(smali_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
    else:
        new_method = (
            "\n\n# method: static constructor for frida-gadget injection\n"
            ".method static constructor <clinit>()V\n"
            "    .registers 1\n\n"
            + load_code +
            "    return-void\n"
            ".end method\n"
        )
        content = content.rstrip() + new_method
        with open(smali_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True

    return False


def _create_custom_application(decompiled_dir, package_name):
    """Create a custom Application class that loads frida-gadget.
    Used when the APK has no custom Application class.
    Returns the smali file path.
    """
    app_class_name = "com.frida.gadget.GadgetApplication"
    smali_dir = os.path.join(decompiled_dir, "smali", "com", "frida", "gadget")
    os.makedirs(smali_dir, exist_ok=True)
    smali_path = os.path.join(smali_dir, "GadgetApplication.smali")

    smali_content = '''\
.class public Lcom/frida/gadget/GadgetApplication;
.super Landroid/app/Application;

# method: static constructor for frida-gadget injection
.method static constructor <clinit>()V
    .registers 1

    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method

.method public onCreate()V
    .registers 1

    invoke-super {p0}, Landroid/app/Application;->onCreate()V
    return-void
.end method
'''

    with open(smali_path, "w", encoding="utf-8") as f:
        f.write(smali_content)

    return app_class_name, smali_path


def _update_manifest_application(manifest_path, app_class_name):
    """Update AndroidManifest.xml to use the custom Application class.

    Only touches the name attribute INSIDE the <application ...> tag —
    never the first android:name in the file (which typically belongs to a
    <uses-permission> element).
    """
    with open(manifest_path, "r", encoding="utf-8") as f:
        content = f.read()

    import re
    # Match the <application ...> opening tag (may span several lines)
    m = re.search(r"<application\b[^>]*>", content, re.DOTALL)
    if not m:
        print("  [!] [GadgetInjector] No <application> tag found in manifest")
        return False
    app_tag = m.group(0)
    if re.search(r'android:name="[^"]*"', app_tag):
        new_tag = re.sub(r'android:name="[^"]*"', f'android:name="{app_class_name}"', app_tag, count=1)
    else:
        new_tag = app_tag.replace("<application", f'<application android:name="{app_class_name}"', 1)
    # Ensure debuggable=true (needed for run-as / /proc inspection after re-sign)
    if "android:debuggable" not in new_tag:
        new_tag = new_tag.replace("<application", '<application android:debuggable="true"', 1)
    content = content[:m.start()] + new_tag + content[m.end():]

    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(content)
    return True


def _add_gadget_binary(decompiled_dir, arch):
    """Add frida-gadget .so and config to the decompiled APK's lib directory.

    arch: 'arm32' | 'arm64' | 'x86_64'. On Windows x86_64 emulators the gadget
    must be x86_64 (loaded natively); ARM app code runs via native bridge
    (libndk translation) which is irrelevant to the gadget ABI.
    """
    arch_map = {
        "arm32": ("armeabi-v7a", ["libfrida-gadget-arm.so", "libfrida-gadget-arm32.so"]),
        "arm64": ("arm64-v8a", ["libfrida-gadget-arm64.so"]),
        "x86_64": ("x86_64", ["libfrida-gadget-x86_64.so", "libfrida-gadget-x64.so"]),
        "x86": ("x86", ["libfrida-gadget-x86.so"]),
    }
    if arch not in arch_map:
        print(f"  [!] [GadgetInjector] Unsupported arch: {arch}")
        return False

    abi_dir, candidates = arch_map[arch]
    lib_dir = os.path.join(decompiled_dir, "lib", abi_dir)

    gadget_src = None
    for name in candidates:
        p = os.path.join(_GADGET_DIR, name)
        if os.path.isfile(p):
            gadget_src = p
            break
    if not gadget_src:
        # Last resort: any gadget .so containing the arch token
        try:
            for f in os.listdir(_GADGET_DIR):
                if arch.replace("x86_64", "x86_64") in f and f.endswith(".so"):
                    gadget_src = os.path.join(_GADGET_DIR, f)
                    break
        except Exception:
            pass
    if not gadget_src:
        print(f"  [!] [GadgetInjector] No gadget binary for arch {arch} in {_GADGET_DIR}")
        return False

    os.makedirs(lib_dir, exist_ok=True)

    gadget_dst = os.path.join(lib_dir, "libfrida-gadget.so")
    shutil.copy2(gadget_src, gadget_dst)

    config_path = os.path.join(lib_dir, "libfrida-gadget.config.so")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(_GADGET_CONFIG, f, indent=2)

    print(f"  [+] [GadgetInjector] Added gadget ({arch}) to {lib_dir}")
    return True


def inject_gadget(apk_path, arch, output_dir):
    """Inject frida-gadget into an APK.

    Args:
        apk_path: Path to the original APK.
        arch: 'arm32' or 'arm64'.
        output_dir: Directory for temporary files and output.

    Returns:
        Path to the gadget-injected APK, or None on failure.
    """
    if not os.path.exists(_APKTOOL_JAR):
        print(f"  [!] [GadgetInjector] apktool not found: {_APKTOOL_JAR}")
        return None

    decompiled_dir = os.path.join(output_dir, "gadget_decompiled")
    os.makedirs(decompiled_dir, exist_ok=True)

    print("  [*] [GadgetInjector] Decompiling APK with apktool...")
    ok, _, err = _run_apktool(["d", "-f", "-o", decompiled_dir, apk_path], timeout=600)
    if not ok:
        print(f"  [!] [GadgetInjector] apktool decompile failed: {err[:200]}")
        return None

    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        print("  [!] [GadgetInjector] AndroidManifest.xml not found")
        return None

    import re
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = f.read()
    pkg_match = re.search(r'package="([^"]+)"', manifest)
    package_name = pkg_match.group(1) if pkg_match else ""

    app_class = _find_application_class(manifest_path)

    if app_class:
        print(f"  [*] [GadgetInjector] Found Application class: {app_class}")
        smali_path = os.path.join(decompiled_dir, "smali", _class_to_smali_path(app_class))
        if not os.path.exists(smali_path):
            for d in sorted(os.listdir(os.path.join(decompiled_dir, "smali"))):
                p = os.path.join(decompiled_dir, "smali", d, _class_to_smali_path(app_class))
                if os.path.exists(p):
                    smali_path = p
                    break
        if os.path.exists(smali_path):
            if _patch_smali_add_loadlibrary(smali_path):
                print(f"  [+] [GadgetInjector] Patched {app_class} <clinit>")
            else:
                print(f"  [!] [GadgetInjector] Failed to patch {app_class}")
        else:
            print(f"  [!] [GadgetInjector] Smali file not found: {smali_path}")
            app_class, smali_path = _create_custom_application(decompiled_dir, package_name)
            _update_manifest_application(manifest_path, app_class)
            print(f"  [+] [GadgetInjector] Created custom Application: {app_class}")
    else:
        print("  [*] [GadgetInjector] No custom Application class — creating one")
        app_class, smali_path = _create_custom_application(decompiled_dir, package_name)
        _update_manifest_application(manifest_path, app_class)
        print(f"  [+] [GadgetInjector] Created custom Application: {app_class}")

    if not _add_gadget_binary(decompiled_dir, arch):
        return None

    output_apk = os.path.join(output_dir, "gadget_injected.apk")
    print("  [*] [GadgetInjector] Recompiling with apktool...")
    ok, _, err = _run_apktool(["b", "-o", output_apk, decompiled_dir], timeout=900)
    if not ok:
        print(f"  [!] [GadgetInjector] apktool build failed: {err[:200]}")
        return None

    if not os.path.exists(output_apk):
        print("  [!] [GadgetInjector] Output APK not created")
        return None

    print("  [*] [GadgetInjector] Signing APK...")
    if not _sign_apk(output_apk):
        print("  [!] [GadgetInjector] Signing failed")
        return None

    print(f"  [+] [GadgetInjector] Gadget-injected APK: {output_apk}")
    return output_apk


def detect_apk_architecture(apk_path):
    """Detect the native library architecture required by an APK.

    Returns 'arm32' | 'arm64' | 'x86' | 'x86_64' | 'none' | 'mixed'.
    APKs with x86/x86_64 libs return those directly; ARM-only APKs keep
    their ARM arch (the x86 emulator runs them via ndk_translation and the
    injected gadget must match the EMULATOR abi — see inject_gadget callers).
    Scans lib/ and assets/ for .so files and checks ELF machine type.

    Returns: 'arm32', 'arm64', 'both', or 'unknown'
    """
    archs = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".so"):
                    continue
                try:
                    data = zf.read(name)
                    if len(data) < 52:
                        continue
                    if data[:4] != b'\x7fELF':
                        continue
                    e_machine = struct.unpack('<H', data[18:20])[0]
                    if e_machine == 0x28:
                        archs.add("arm32")
                    elif e_machine == 0xB7:
                        archs.add("arm64")
                    elif e_machine == 0x3E:
                        archs.add("x86_64")
                    elif e_machine == 0x03:
                        archs.add("x86")
                except Exception:
                    continue
    except Exception:
        pass

    if "arm32" in archs and "arm64" in archs:
        return "both"
    elif "arm32" in archs:
        return "arm32"
    elif "arm64" in archs:
        return "arm64"
    elif "x86_64" in archs:
        return "x86_64"
    elif "x86" in archs:
        return "x86"
    return "unknown"
