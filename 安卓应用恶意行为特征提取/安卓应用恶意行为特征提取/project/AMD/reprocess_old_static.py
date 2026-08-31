#!/usr/bin/env python3
"""Re-run the latest unpacker on samples that were processed by the old pipeline.

Targets samples in malradar-0 where unpacking_result.status == 'success'
and method == 'static' but dex_sources is empty (old pipeline lacked
_extract_hidden_dex_from_assets and source metadata).

Updates unpacking_result with fresh metadata. If new DEX files are found,
also updates unpacked_dex_files and unpacked_dex_count.
"""
import json, os, glob, sys, tempfile

OUTPUT_DIR = "/Users/yqh/knowledge_graph/output/malradar-0"
INPUT_DIR = "/Users/yqh/Downloads/malradar-0"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    files = sorted(glob.glob(os.path.join(OUTPUT_DIR, "*.json")))
    targets = []
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        ur = data.get("unpacking_result", {})
        if ur.get("status") == "success" and ur.get("method") == "static" and not ur.get("dex_sources"):
            targets.append((f, data))

    print(f"Found {len(targets)} samples to re-process with latest unpacker\n")

    updated = 0
    found_more = 0
    for f, data in targets:
        apk_sha = data.get("apk_sha256", "")
        apk_path = data.get("apk_path", "")
        if not apk_path or not os.path.isfile(apk_path):
            cand = os.path.join(INPUT_DIR, apk_sha + ".apk")
            if os.path.isfile(cand):
                apk_path = cand
            else:
                print(f"  [!] APK not found for {apk_sha[:20]}... — skipping")
                continue

        pa = data.get("code_analysis", {}).get("_packing_assessment", {})
        ur = data.get("unpacking_result", {})

        try:
            from unpacker import try_static_unpack
            tmp_dir = tempfile.mkdtemp(prefix="reunpack_")
            dex_paths = try_static_unpack(apk_path, pa if isinstance(pa, dict) else {}, tmp_dir)

            detail = getattr(try_static_unpack, "_last_detail", "")
            sources = getattr(try_static_unpack, "_last_sources", [])

            old_count = ur.get("unpacked_dex_count", 0)
            if dex_paths:
                ur["unpacked_dex_count"] = len(dex_paths)
                ur["unpacked_dex_files"] = [
                    {"path": os.path.basename(p), "size_bytes": os.path.getsize(p)}
                    for p in dex_paths
                ]
                ur["dex_source_detail"] = detail
                ur["dex_sources"] = sources
                ur["status"] = "success"
                ur["method"] = "static"
                if len(dex_paths) > old_count:
                    found_more += 1
                    print(f"  [+] {apk_sha[:20]}... NEW DEX: {old_count} -> {len(dex_paths)} (detail={detail})")
                else:
                    print(f"  [=] {apk_sha[:20]}... same DEX count {len(dex_paths)} (detail={detail})")
            else:
                if old_count > 0:
                    # Old code succeeded but new code found nothing — keep old counts,
                    # but note that detail is empty. This is unlikely.
                    ur["dex_source_detail"] = detail or ur.get("dex_source_detail", "")
                    ur["dex_sources"] = sources or ur.get("dex_sources", [])
                    print(f"  [!] {apk_sha[:20]}... new unpacker found nothing (old had {old_count}) — keeping old")
                else:
                    print(f"  [!] {apk_sha[:20]}... unpacker returned no DEX")

            data["unpacking_result"] = ur
            with open(f, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            updated += 1

        except Exception as e:
            print(f"  [x] {apk_sha[:20]}... error: {e}")

    print(f"\nDone. Updated {updated} files. Found additional DEX in {found_more} samples.")


if __name__ == "__main__":
    main()