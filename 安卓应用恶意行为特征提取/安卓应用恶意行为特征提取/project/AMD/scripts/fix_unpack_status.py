#!/usr/bin/env python3
"""Fix unpacking_method for APKs that have valid DEX in the APK root
but were incorrectly marked as 'failed' because the old unpacker
only searched assets/ for encrypted DEX.

Usage: python3 scripts/fix_unpack_status.py <apk_dir> <output_dir>
"""
import json
import os
import struct
import sys
import zipfile
import glob

MIN_VALID_DEX_SIZE = 100 * 1024  # 100KB — stubs are typically <50KB


def has_valid_dex(apk_path):
    """Check if APK has valid (non-stub) DEX files in root."""
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_names = [n for n in zf.namelist()
                         if n.startswith("classes") and n.endswith(".dex")]
            for name in dex_names:
                data = zf.read(name)
                if len(data) < MIN_VALID_DEX_SIZE:
                    continue
                if data[:4] != b'dex\n':
                    continue
                declared = struct.unpack("<I", data[32:36])[0]
                if declared == len(data):
                    return True, len(dex_names)
        return False, 0
    except Exception:
        return False, 0


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 scripts/fix_unpack_status.py <apk_dir> <output_dir>")
        sys.exit(1)

    apk_dir = sys.argv[1]
    output_dir = sys.argv[2]

    fixed = 0
    skipped = 0
    total = 0

    for json_path in sorted(glob.glob(os.path.join(output_dir, "*.json"))):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            unpack = data.get("unpacking_info", {})
            if unpack.get("unpacking_method") != "failed":
                continue

            total += 1
            apk_hash = os.path.basename(json_path).replace(".json", "")
            apk_path = os.path.join(apk_dir, apk_hash + ".apk")
            if not os.path.exists(apk_path):
                continue

            valid, dex_count = has_valid_dex(apk_path)
            if valid:
                unpack["unpacking_method"] = "static_not_needed"
                unpack["unpacked_dex_count"] = dex_count
                unpack["note"] = "DEX files already valid in APK root — packer does method-level VMP, not DEX encryption"
                data["unpacking_info"] = unpack

                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)

                fixed += 1
                print(f"  [FIXED] {apk_hash[:16]}... {dex_count} DEX files")
            else:
                skipped += 1

        except Exception as e:
            print(f"  [ERROR] {json_path}: {e}")

    print(f"\nDone: {fixed} fixed, {skipped} still failed, {total} total checked")


if __name__ == "__main__":
    main()
