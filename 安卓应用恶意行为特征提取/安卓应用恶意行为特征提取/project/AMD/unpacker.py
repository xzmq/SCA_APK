"""
unpacker.py - F-E-lite: Static DEX reconstruction for packed APKs.

Strategy:
  1. Locate candidate encrypted DEX files in the APK (assets/, res/raw/, or .so)
  2. Extract decryption keys from the packer stub Application class (via jadx MCP)
  3. Attempt decryption using DES/AES/RC4/XOR (reuses extract_c2_iocs.py framework)
  4. Validate decrypted data by checking DEX magic bytes
  5. Also try "embedded DEX" extraction (DEX magic at non-zero offset in assets files)

Returns: list of decrypted DEX file paths (empty if all attempts fail).
"""
import os
import sys
import re
import json
import zipfile
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import UNPACKING_TIMEOUT
from common import (
    list_apk_files, read_apk_file_bytes, compute_file_entropy_in_apk,
    get_file_size_in_apk, shannon_entropy_bytes, save_json,
)
from packer_signatures import (
    DEX_MAGIC_BYTES, is_valid_dex, find_dex_magic_offset,
    get_packer_dex_location, PACKER_INDICATORS,
)
from jadx_extractor import get_class_source, get_android_manifest, get_all_classes


def try_static_unpack(apk_path, packing_assessment, output_dir=None):
    """Main entry: attempt static DEX reconstruction.
    Returns list of decrypted DEX file paths.

    Sets module-level attributes for pipeline use:
      try_static_unpack._last_detail: str   — "existing_valid" | "hidden_in_assets" | "embedded" | "decrypted" | ""
      try_static_unpack._last_sources: list  — source locations of each DEX file
    """
    import tempfile
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="unpacked_dex_")

    try_static_unpack._last_detail = ""
    try_static_unpack._last_sources = []

    packer_name = packing_assessment.get("packer_name", "")
    dex_location = packing_assessment.get("dex_location", "assets/")

    print(f"  [*] [Unpacker] Static unpack attempt: packer={packer_name or 'unknown'}, dex_loc={dex_location}")

    # Step 0: Check if APK already has valid (non-stub) DEX files in root
    # Some packers (e.g., Tencent Legu) do method-level VMP, not DEX encryption.
    # In that case, classes.dex/classes2.dex are already the real DEX files.
    existing_dex = _check_existing_valid_dex(apk_path, output_dir)
    if existing_dex:
        print(f"  [+] [Unpacker] APK already has {len(existing_dex)} valid DEX file(s) — no unpacking needed")
        try_static_unpack._last_detail = "existing_valid"
        try_static_unpack._last_sources = [os.path.basename(p) for p in existing_dex]
        return existing_dex

    # Step 0.5: Check for hidden DEX in assets/ (ZIP files containing DEX)
    # Some packers (e.g., Ijiami) store the real DEX inside a ZIP in assets/.
    # The ZIP file itself may have a non-standard name (e.g., "polacin.io").
    hidden_dex = _extract_hidden_dex_from_assets(apk_path, output_dir)
    if hidden_dex:
        print(f"  [+] [Unpacker] Extracted {len(hidden_dex)} hidden DEX file(s) from assets/")
        try_static_unpack._last_detail = "hidden_in_assets"
        try_static_unpack._last_sources = [os.path.basename(p) for p in hidden_dex]
        return hidden_dex

    # Step 1: Locate candidate encrypted DEX files
    candidates = _find_encrypted_dex_candidates(apk_path, dex_location)
    if not candidates:
        print("  [!] [Unpacker] No encrypted DEX candidates found in APK")
        return []

    print(f"  [+] [Unpacker] Found {len(candidates)} candidate(s):")
    for c in candidates:
        print(f"      {c['path']} (size={c['size']}, entropy={c['entropy']:.2f}, dex_offset={c['dex_offset']})")

    decrypted_dex_paths = []

    # Step 2: Try "embedded DEX" extraction first (no decryption needed)
    for candidate in candidates:
        if candidate["dex_offset"] > 0:
            dex_path = _extract_embedded_dex(apk_path, candidate, output_dir)
            if dex_path:
                decrypted_dex_paths.append(dex_path)
                print(f"  [+] [Unpacker] Extracted embedded DEX (offset={candidate['dex_offset']}): {dex_path}")

    if decrypted_dex_paths:
        try_static_unpack._last_detail = "embedded"
        try_static_unpack._last_sources = [c["path"] for c in candidates if c["dex_offset"] > 0]
    if decrypted_dex_paths:
        try_static_unpack._last_detail = "decrypted"
        try_static_unpack._last_sources = [c["path"] for c in candidates]

    return decrypted_dex_paths

    # Step 3: Extract decryption keys from stub Application class
    key_info = _extract_stub_decryption_keys(apk_path, packing_assessment)
    if not key_info or (not key_info["string_keys"] and not key_info["byte_keys"]):
        print("  [!] [Unpacker] No decryption keys found in stub code")
        return []

    print(f"  [+] [Unpacker] Extracted keys: {len(key_info['string_keys'])} string, "
          f"{len(key_info['byte_keys'])} byte[], {len(key_info['algorithms'])} algorithms")

    # Step 4: Try decryption for each candidate
    for candidate in candidates:
        dex_path = _try_decrypt_dex_candidate(apk_path, candidate, key_info, output_dir)
        if dex_path:
            decrypted_dex_paths.append(dex_path)
            print(f"  [+] [Unpacker] Decrypted DEX: {dex_path}")

    return decrypted_dex_paths


def _check_existing_valid_dex(apk_path, output_dir):
    """Check if the APK already has valid (non-stub) DEX files in the root.
    A valid DEX is >100KB with proper header. Stub DEX files from packers
    are typically <50KB. If we find valid large DEX files, they're the real
    application DEX — no unpacking needed.
    Returns list of extracted DEX file paths, or empty list if not found.
    """
    import struct
    MIN_VALID_DEX_SIZE = 100 * 1024  # 100KB — stubs are typically <50KB

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_names = [n for n in zf.namelist()
                         if n.startswith("classes") and n.endswith(".dex")]
            valid_dex = []
            for name in sorted(dex_names):
                data = zf.read(name)
                if len(data) < MIN_VALID_DEX_SIZE:
                    continue
                if data[:4] != b'dex\n':
                    continue
                declared_size = struct.unpack("<I", data[32:36])[0]
                if declared_size == len(data):
                    out_path = os.path.join(output_dir, name.replace("/", "_"))
                    with open(out_path, "wb") as f:
                        f.write(data)
                    valid_dex.append(out_path)
                    print(f"      {name}: {len(data)} bytes (valid)")
            return valid_dex
    except Exception:
        return []


def _extract_hidden_dex_from_assets(apk_path, output_dir):
    """Scan APK assets/ for ZIP files that contain hidden DEX files.
    Some packers (e.g., Ijiami) store the real DEX inside a ZIP file
    in assets/ with a non-standard name (e.g., "polacin.io").
    Also checks for raw DEX magic at the start of asset files.
    Returns list of extracted DEX file paths, or empty list if not found.
    """
    import struct
    import io
    MIN_DEX_SIZE = 10 * 1024  # 10KB — skip tiny fragments

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            asset_names = [n for n in zf.namelist() if n.startswith("assets/")]
            extracted = []

            for asset_name in sorted(asset_names):
                try:
                    data = zf.read(asset_name)
                    if len(data) < MIN_DEX_SIZE:
                        continue

                    # Case 1: ZIP file containing DEX
                    if data[:2] == b'PK':
                        try:
                            with zipfile.ZipFile(io.BytesIO(data)) as inner:
                                for iname in inner.namelist():
                                    idata = inner.read(iname)
                                    if len(idata) < MIN_DEX_SIZE:
                                        continue
                                    if idata[:4] != b'dex\n':
                                        continue
                                    decl = struct.unpack("<I", idata[32:36])[0]
                                    if decl == len(idata):
                                        base = os.path.basename(asset_name)
                                        out_path = os.path.join(
                                            output_dir, f"hidden_{base}_{iname.replace('/', '_')}"
                                        )
                                        with open(out_path, "wb") as f:
                                            f.write(idata)
                                        extracted.append(out_path)
                                        print(f"      {asset_name} -> {iname}: {len(idata)} bytes (hidden DEX)")
                        except Exception:
                            pass

                    # Case 2: Raw DEX at start of file
                    elif data[:4] == b'dex\n':
                        decl = struct.unpack("<I", data[32:36])[0]
                        if decl == len(data) and len(data) >= MIN_DEX_SIZE:
                            base = os.path.basename(asset_name)
                            out_path = os.path.join(output_dir, f"hidden_{base}.dex")
                            with open(out_path, "wb") as f:
                                f.write(data)
                            extracted.append(out_path)
                            print(f"      {asset_name}: {len(data)} bytes (raw DEX in assets)")

                except Exception:
                    continue

            # Deduplicate by size — only keep DEX files >100KB
            # (smaller ones are likely packer runtime, not the real app DEX)
            MIN_RETURN_SIZE = 100 * 1024  # 100KB
            large_dex = [p for p in extracted if os.path.getsize(p) >= MIN_RETURN_SIZE]
            if large_dex:
                large_dex.sort(key=lambda p: os.path.getsize(p), reverse=True)
                seen_sizes = set()
                unique = []
                for p in large_dex:
                    sz = os.path.getsize(p)
                    if sz not in seen_sizes:
                        seen_sizes.add(sz)
                        unique.append(p)
                return unique

            return []
    except Exception:
        return []


def _find_encrypted_dex_candidates(apk_path, dex_location="assets/"):
    """Find candidate encrypted DEX files in the APK.
    Heuristics:
    - Files in assets/ or res/raw/ with high entropy (>6.5) and size > 1KB
    - Files with no standard resource extension (.dat, .bin, .enc, no extension)
    - Files where DEX magic bytes appear at non-zero offsets (embedded DEX)
    - .so files that may contain embedded DEX
    """
    candidates = []
    all_files = list_apk_files(apk_path)

    # Search in dex_location (usually assets/) and also res/raw/ and lib/
    search_prefixes = (dex_location, "res/raw/", "lib/")
    # Extensions that suggest encrypted/hidden DEX
    suspicious_exts = ('.dat', '.bin', '.enc', '.jar', '.zip', '.dat1', '.dat2')

    for fpath in all_files:
        if not any(fpath.startswith(p) for p in search_prefixes):
            continue
        # Skip standard resources
        if fpath.endswith(('.png', '.jpg', '.xml', '.arsc', '.ttf', '.otf', '.mp3', '.wav', '.mp4')):
            continue

        size = get_file_size_in_apk(apk_path, fpath)
        if size < 512:  # too small to be a DEX
            continue

        ent = compute_file_entropy_in_apk(apk_path, fpath)
        if ent < 6.0:
            continue

        data = read_apk_file_bytes(apk_path, fpath)
        dex_offset = find_dex_magic_offset(data) if data else -1

        # Also check for DEX magic at common packer offsets (1024, 4096, etc.)
        if dex_offset < 0 and data:
            for offset in [0, 1024, 4096, 8192, 0x1000, 0x2000]:
                if offset + 8 <= len(data) and is_valid_dex(data[offset:offset+8]):
                    dex_offset = offset
                    break

        candidates.append({
            "path": fpath,
            "size": size,
            "entropy": ent,
            "dex_offset": dex_offset,  # >0 means DEX is embedded at this offset
        })

    return candidates


def _extract_embedded_dex(apk_path, candidate, output_dir):
    """Extract a DEX that is embedded at a non-zero offset in a file.
    This handles packers that simply prepend a header to the DEX.
    """
    if candidate["dex_offset"] <= 0:
        return None

    data = read_apk_file_bytes(apk_path, candidate["path"])
    if not data:
        return None

    dex_data = data[candidate["dex_offset"]:]
    if not is_valid_dex(dex_data):
        return None

    # Write extracted DEX
    base_name = os.path.splitext(os.path.basename(candidate["path"]))[0]
    dex_path = os.path.join(output_dir, f"{base_name}_extracted.dex")
    with open(dex_path, "wb") as f:
        f.write(dex_data)
    return dex_path


def _extract_stub_decryption_keys(apk_path, packing_assessment):
    """Extract decryption keys from the packer's stub Application class.
    Uses jadx MCP to decompile the stub, then reuses the key extraction
    framework from extract_c2_iocs.py.
    """
    # 1. Find the Application class from manifest
    app_class = ""
    try:
        manifest = get_android_manifest()
        # Search for android:name in <application> tag
        m = re.search(r'<application[^>]*android:name="([^"]+)"', manifest)
        if m:
            app_class = m.group(1)
    except Exception:
        pass

    if not app_class:
        # Try common stub class names
        stub_names = ["com.shell.SuperApplication", "com.qihoo.util.StubApplication",
                      "StubApplication", "ProxyApplication", "ShellApplication"]
        for name in stub_names:
            try:
                source = get_class_source(name)
                if source:
                    app_class = name
                    break
            except Exception:
                pass

    if not app_class:
        print("  [!] [Unpacker] No Application class found in manifest")
        return None

    print(f"  [*] [Unpacker] Decompiling stub Application class: {app_class}")

    # 2. Decompile the Application class via jadx MCP
    source = ""
    try:
        source = get_class_source(app_class) or ""
    except Exception:
        pass

    if not source:
        print(f"  [!] [Unpacker] Could not decompile {app_class}")
        return None

    # 3. Reuse key extraction from extract_c2_iocs.py
    try:
        from extract_c2_iocs import (
            _extract_crypto_keys_from_source,
            _extract_byte_array_keys_from_source,
            _parse_cipher_algorithm,
        )
    except ImportError:
        print("  [!] [Unpacker] Cannot import key extraction from extract_c2_iocs")
        return None

    str_keys = _extract_crypto_keys_from_source(source)
    byte_keys, byte_ivs = _extract_byte_array_keys_from_source(source)

    # 4. Search for Cipher.getInstance calls
    cipher_re = re.compile(r'Cipher\.getInstance\(\s*"([^"]+)"\s*\)')
    algo_strings = cipher_re.findall(source)
    algorithms = []
    for a in algo_strings:
        parsed = _parse_cipher_algorithm(a)
        if parsed[0]:  # algo is non-empty
            algorithms.append(parsed)

    # 5. Also search in referenced classes (loaders, helpers)
    # Look for class references in the source that might contain keys
    class_refs = re.findall(r'Class\.forName\("([^"]+)"\)', source)
    for ref_class in class_refs[:5]:
        try:
            ref_source = get_class_source(ref_class) or ""
            if ref_source:
                extra_str = _extract_crypto_keys_from_source(ref_source)
                extra_byte, extra_iv = _extract_byte_array_keys_from_source(ref_source)
                str_keys.extend(extra_str)
                byte_keys.extend(extra_byte)
                byte_ivs.extend(extra_iv)
                extra_algos = cipher_re.findall(ref_source)
                for a in extra_algos:
                    parsed = _parse_cipher_algorithm(a)
                    if parsed[0]:
                        algorithms.append(parsed)
        except Exception:
            pass

    # Deduplicate
    seen_str = set()
    unique_str = []
    for k, h in str_keys:
        if k not in seen_str:
            seen_str.add(k)
            unique_str.append((k, h))

    seen_byte = set()
    unique_byte = []
    for k, h in byte_keys:
        if k not in seen_byte:
            seen_byte.add(k)
            unique_byte.append((k, h))

    return {
        "string_keys": unique_str,
        "byte_keys": unique_byte,
        "byte_ivs": byte_ivs,
        "algorithms": algorithms,
        "source_class": app_class,
    }


def _try_decrypt_dex_candidate(apk_path, candidate, key_info, output_dir):
    """Try to decrypt an encrypted DEX file using extracted keys.
    Reuses _try_decrypt / _try_xor_decrypt from extract_c2_iocs.py.
    """
    from extract_c2_iocs import _try_decrypt, _try_xor_decrypt, _derive_key

    data = read_apk_file_bytes(apk_path, candidate["path"])
    if not data:
        return None

    # If DEX magic is at offset, extract directly (no decryption needed)
    if candidate["dex_offset"] > 0:
        dex_data = data[candidate["dex_offset"]:]
        if is_valid_dex(dex_data):
            return _save_dex(dex_data, candidate["path"], output_dir)

    # Try each algorithm + key combination
    hex_data = data.hex()

    for algo, mode, padding in key_info["algorithms"]:
        if not algo:
            continue

        # Determine expected key length
        if algo == "DES":
            key_len = 8
        elif algo == "AES":
            key_len = 16
        elif algo == "RC4":
            key_len = len(key_info["string_keys"][0][0].encode()) if key_info["string_keys"] else 16
        else:
            continue

        # Try byte[] keys
        for key_bytes, _hint in key_info["byte_keys"]:
            if algo == "DES" and len(key_bytes) != 8:
                continue
            if algo == "AES" and len(key_bytes) not in (16, 24, 32):
                continue

            try:
                from extract_c2_iocs import _try_decrypt as _decrypt
                result = _decrypt(hex_data, algo, mode, [key_bytes], padding)
                if result:
                    result_bytes = result.encode("utf-8", errors="ignore")
                    if is_valid_dex(result_bytes):
                        return _save_dex(result_bytes, candidate["path"], output_dir)
                    # Also try raw bytes
                    raw = bytes.fromhex(hex_data)
                    # Try direct decryption returning bytes
            except Exception:
                continue

        # Try string keys
        for key_str, _hint in key_info["string_keys"]:
            key_bytes = _derive_key(key_str, key_len)
            candidates_keys = [key_bytes]
            if algo == "AES":
                for kl in (24, 32):
                    candidates_keys.append(_derive_key(key_str, kl))

            try:
                result = _try_decrypt(hex_data, algo, mode, candidates_keys, padding)
                if result:
                    result_bytes = result.encode("utf-8", errors="ignore")
                    if is_valid_dex(result_bytes):
                        return _save_dex(result_bytes, candidate["path"], output_dir)
            except Exception:
                continue

    # XOR fallback
    xor_key_pool = []
    for kb, _ in key_info["byte_keys"]:
        if kb and kb not in xor_key_pool:
            xor_key_pool.append(kb)
    for ks, _ in key_info["string_keys"]:
        kb = ks.encode("utf-8")
        if kb and kb not in xor_key_pool:
            xor_key_pool.append(kb)

    if xor_key_pool:
        try:
            result = _try_xor_decrypt(hex_data, xor_key_pool)
            if result:
                result_bytes = result.encode("utf-8", errors="ignore")
                if is_valid_dex(result_bytes):
                    return _save_dex(result_bytes, candidate["path"], output_dir)
        except Exception:
            pass

    # Try raw XOR on binary data (not hex)
    for key in xor_key_pool:
        try:
            kl = len(key)
            pt = bytes(data[i] ^ key[i % kl] for i in range(len(data)))
            if is_valid_dex(pt):
                return _save_dex(pt, candidate["path"], output_dir)
        except Exception:
            continue

    return None


def _save_dex(dex_data, source_path, output_dir):
    """Save decrypted DEX data to a file."""
    base_name = os.path.splitext(os.path.basename(source_path))[0]
    # Generate hash for unique naming
    dex_hash = hashlib.md5(dex_data[:1024]).hexdigest()[:8]
    dex_path = os.path.join(output_dir, f"{base_name}_{dex_hash}_decrypted.dex")
    with open(dex_path, "wb") as f:
        f.write(dex_data)
    return dex_path
