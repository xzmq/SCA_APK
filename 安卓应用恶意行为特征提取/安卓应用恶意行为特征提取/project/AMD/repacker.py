"""
repacker.py - DEX merge and APK repackaging for unpacked DEX files.

Strategy:
  1. Copy original APK to a new file (original is never modified)
  2. Replace/add decrypted DEX files (classes.dex, classes2.dex, ...)
  3. Remove packer stub assets (encrypted DEX files in assets/)
  4. Re-sign with a debug key (using apksigner or jarsigner)
  5. Return the path to the repackaged APK

The original APK remains untouched at its original path.
"""
import os
import sys
import json
import shutil
import zipfile
import tempfile
import subprocess
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import list_apk_files, read_apk_file_bytes, get_file_size_in_apk
from packer_signatures import is_valid_dex, find_dex_magic_offset


# Debug keystore for re-signing (generated if not exists)
_DEBUG_KEYSTORE_PATH = os.path.expanduser("~/.android/debug.keystore")
_DEBUG_KEY_ALIAS = "androiddebugkey"
_DEBUG_KEY_PASS = "android"
_DEBUG_STORE_PASS = "android"
_DEBUG_DN = "CN=Android Debug,O=Android,C=US"


def _ensure_debug_keystore():
    """Ensure a debug keystore exists for re-signing APKs."""
    if os.path.exists(_DEBUG_KEYSTORE_PATH):
        return _DEBUG_KEYSTORE_PATH

    # Try to find the Android debug keystore
    android_sdk = os.environ.get("ANDROID_SDK_ROOT", os.path.expanduser("~/Library/Android/sdk"))
    sdk_key = os.path.join(android_sdk, "debug.keystore")
    if os.path.exists(sdk_key):
        return sdk_key

    # Generate a new one using keytool
    keystore_dir = os.path.dirname(_DEBUG_KEYSTORE_PATH)
    os.makedirs(keystore_dir, exist_ok=True)

    try:
        subprocess.run([
            "keytool", "-genkeypair",
            "-alias", _DEBUG_KEY_ALIAS,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-keystore", _DEBUG_KEYSTORE_PATH,
            "-storepass", _DEBUG_STORE_PASS,
            "-keypass", _DEBUG_KEY_PASS,
            "-dname", f"CN=Android Debug,O=Android,C=US",
        ], check=True, capture_output=True, timeout=30)
        return _DEBUG_KEYSTORE_PATH
    except Exception as e:
        print(f"  [!] [Repacker] Failed to generate debug keystore: {e}")
        return None


def _find_apksigner():
    """Find the apksigner tool from Android SDK.
    Prefers a JVM-direct invocation form: (java_exe, apksigner_jar) tuple.
    Falls back to the apksigner binary/.bat path (string) for non-Windows.
    The .bat form is DEADLOCK-PRONE on Windows: subprocess.run(<bat>,
    capture_output=True, timeout=N) kills only cmd.exe on timeout while the
    java.exe grandchild keeps the stdout pipe open, hanging communicate().
    """
    android_sdk = os.environ.get("ANDROID_SDK_ROOT", r"D:\Android\sdk" if os.path.isdir(r"D:\Android\sdk") else os.path.expanduser("~/Library/Android/sdk"))
    build_tools = os.path.join(android_sdk, "build-tools")

    # Preferred: direct java -jar invocation (Windows-safe, no cmd wrapper)
    if os.path.isdir(build_tools):
        import shutil as sh
        java = sh.which("java") or os.environ.get("JAVA_BIN") or ""
        if java and os.path.isfile(java):
            for v in sorted(os.listdir(build_tools), reverse=True):
                jar = os.path.join(build_tools, v, "lib", "apksigner.jar")
                if os.path.isfile(jar):
                    return [java, "-jar", jar]

    if os.path.isdir(build_tools):
        versions = sorted(os.listdir(build_tools), reverse=True)
        for v in versions:
            signer = os.path.join(build_tools, v, "apksigner")
            if os.path.isfile(signer):
                return signer
            # Try .bat for Windows
            signer_bat = signer + ".bat"
            if os.path.isfile(signer_bat):
                return signer_bat
    # Check PATH
    import shutil as sh
    return sh.which("apksigner")


def _find_jarsigner():
    """Find jarsigner (Java JDK tool)."""
    import shutil as sh
    return sh.which("jarsigner")


def _sign_apk(apk_path):
    """Sign an APK with the debug key.
    Tries apksigner first, falls back to jarsigner.
    """
    keystore = _ensure_debug_keystore()
    if not keystore:
        print("  [!] [Repacker] No keystore available — APK will be unsigned")
        return False

    # Try apksigner (preferred — supports v2/v3 signing)
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
            print(f"  [+] [Repacker] Signed with apksigner")
            return True
        except Exception as e:
            print(f"  [!] [Repacker] apksigner failed: {e}, trying jarsigner")

    # Fall back to jarsigner (v1 signing only)
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
            # Replace unsigned with signed
            shutil.move(apk_path + ".signed", apk_path)
            print(f"  [+] [Repacker] Signed with jarsigner (v1)")
            return True
        except Exception as e:
            print(f"  [!] [Repacker] jarsigner failed: {e}")

    print("  [!] [Repacker] No signing tool available — APK will be unsigned")
    return False


def repackage_with_decrypted_dex(original_apk, decrypted_dex_paths, output_dir=None):
    """Create a new APK with decrypted DEX files replacing the encrypted ones.
    
    Args:
        original_apk: Path to the original packed APK (never modified)
        decrypted_dex_paths: List of paths to decrypted DEX files
        output_dir: Directory for the output APK (default: temp dir)
    
    Returns:
        Path to the repackaged APK (new file), or None on failure.
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="repacked_apk_")

    base_name = os.path.basename(original_apk)
    name_stem = os.path.splitext(base_name)[0]
    output_apk = os.path.join(output_dir, f"{name_stem}_unpacked.apk")

    print(f"  [*] [Repacker] Repackaging: {base_name} → {os.path.basename(output_apk)}")

    # Step 1: Copy original APK to output path
    shutil.copy2(original_apk, output_apk)

    # Step 2: Identify which files in the APK are encrypted DEX (to remove)
    all_files = list_apk_files(original_apk)
    files_to_remove = []
    for fpath in all_files:
        # Remove files in assets/ that look like encrypted DEX
        if fpath.startswith("assets/"):
            data = read_apk_file_bytes(original_apk, fpath)
            if data:
                # Check if it's high-entropy and NOT a valid DEX (encrypted)
                from common import compute_file_entropy_in_apk
                ent = compute_file_entropy_in_apk(original_apk, fpath)
                size = get_file_size_in_apk(original_apk, fpath)
                if ent > 6.5 and size > 512 and not is_valid_dex(data):
                    # Check if it has embedded DEX (will be replaced)
                    offset = find_dex_magic_offset(data)
                    if offset > 0:
                        files_to_remove.append(fpath)  # DEX embedded, replace
                    elif size > 10000:  # Large encrypted file
                        files_to_remove.append(fpath)  # Likely encrypted DEX

    # Also remove packer-specific files
    packer_files = [f for f in all_files if any(
        pat in f.lower() for pat in ["libjiagu", "libchaosvmp", "libshell",
                                      "libsecexe", "libsecmain", "libexec",
                                      "libdexhelper", "libtup", "libshella"]
    )]
    files_to_remove = list(set(files_to_remove + packer_files))

    if files_to_remove:
        print(f"  [+] [Repacker] Removing {len(files_to_remove)} packer files from APK")

    # Step 3: Create new APK with replacements
    # We can't modify a zip in-place, so create a new one
    temp_apk = output_apk + ".tmp"
    
    with zipfile.ZipFile(output_apk, "r") as zin:
        with zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                # Skip files that should be removed
                if item.filename in files_to_remove:
                    continue
                # Skip existing classes*.dex (will be replaced)
                if item.filename.startswith("classes") and item.filename.endswith(".dex"):
                    continue
                # Skip META-INF signature files (will re-sign)
                if item.filename.startswith("META-INF/") and (
                    item.filename.endswith(".RSA") or
                    item.filename.endswith(".DSA") or
                    item.filename.endswith(".EC") or
                    item.filename.endswith(".SF") or
                    item.filename.endswith(".MF")
                ):
                    continue
                # Copy the file as-is
                data = zin.read(item.filename)
                zout.writestr(item, data)

            # Step 4: Add decrypted DEX files
            for i, dex_path in enumerate(decrypted_dex_paths):
                if not os.path.isfile(dex_path):
                    continue
                with open(dex_path, "rb") as f:
                    dex_data = f.read()
                if not is_valid_dex(dex_data):
                    print(f"  [!] [Repacker] Skipping invalid DEX: {dex_path}")
                    continue
                dex_name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
                zout.writestr(dex_name, dex_data)
                print(f"  [+] [Repacker] Added {dex_name} ({len(dex_data)} bytes)")

    # Replace original with temp
    shutil.move(temp_apk, output_apk)

    # Step 5: Re-sign the APK
    _sign_apk(output_apk)

    # Step 6: Verify
    if os.path.isfile(output_apk) and os.path.getsize(output_apk) > 0:
        print(f"  [+] [Repacker] Repackaged APK: {output_apk}")
        return output_apk
    else:
        print(f"  [!] [Repacker] Repackaging failed")
        return None
