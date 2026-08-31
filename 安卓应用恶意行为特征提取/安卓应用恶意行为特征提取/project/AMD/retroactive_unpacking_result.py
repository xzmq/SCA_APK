#!/usr/bin/env python3
"""Retroactively add unpacking_result field to existing JSONs.

For each JSON:
- If unpacking_info exists → build unpacking_result from it
- Elif code_analysis._packing_assessment exists → build from that
- Else → set status=not_packed
"""
import json, os, glob, sys

OUTPUT_DIR = "/Users/yqh/knowledge_graph/output/malradar-0"


def build_from_unpacking_info(ui, pa=None):
    """Build unpacking_result from existing unpacking_info dict."""
    method = ui.get("unpacking_method", "failed")
    if method == "static_not_needed":
        status = "success"
        method = "static"
        detail = "existing_valid"
    elif method == "static":
        status = "success"
        detail = "hidden_in_assets"
    elif method == "dynamic":
        status = "success"
        detail = "memory_dump"
    elif method == "failed":
        status = "failed"
        detail = ""
    else:
        status = "failed"
        detail = ""

    return {
        "is_packed": ui.get("was_packed", True),
        "packer_name": ui.get("packer_name", ""),
        "confidence": ui.get("confidence", 0),
        "threshold_exceeded": True,
        "status": status,
        "method": method,
        "attempted_methods": ["static"] if method == "static" else (["static", "dynamic"] if status == "failed" else [method]),
        "unpacked_dex_files": [],
        "unpacked_dex_count": ui.get("unpacked_dex_count", 0),
        "original_dex_count": ui.get("original_dex_count", 0),
        "dex_sources": [],
        "dex_source_detail": detail,
        "indicators": ui.get("indicators", []),
        "errors": [] if status == "success" else [{"method": "dynamic", "error": "Not available or failed"}],
        "repacked": status == "success",
    }


def build_from_packing_assessment(pa, original_dex_count=0):
    """Build unpacking_result from _packing_assessment only (no unpacking was attempted)."""
    confidence = pa.get("confidence", 0)
    is_packed = pa.get("is_packed", False)
    threshold_exceeded = confidence >= 60

    if not is_packed:
        status = "not_packed"
        method = "not_packed"
    elif threshold_exceeded:
        status = "not_attempted"
        method = "not_attempted"
    else:
        status = "not_attempted"
        method = "not_attempted"

    return {
        "is_packed": is_packed,
        "packer_name": pa.get("packer_name", ""),
        "confidence": confidence,
        "threshold_exceeded": threshold_exceeded,
        "status": status,
        "method": method,
        "attempted_methods": [],
        "unpacked_dex_files": [],
        "unpacked_dex_count": 0,
        "original_dex_count": original_dex_count,
        "dex_sources": [],
        "dex_source_detail": "",
        "indicators": pa.get("indicators", []),
        "errors": [],
        "repacked": False,
    }


def build_not_packed(original_dex_count=0):
    """Build unpacking_result for non-packed APKs."""
    return {
        "is_packed": False,
        "packer_name": "",
        "confidence": 0,
        "threshold_exceeded": False,
        "status": "not_packed",
        "method": "not_packed",
        "attempted_methods": [],
        "unpacked_dex_files": [],
        "unpacked_dex_count": 0,
        "original_dex_count": original_dex_count,
        "dex_sources": [],
        "dex_source_detail": "",
        "indicators": [],
        "errors": [],
        "repacked": False,
    }


def main():
    files = sorted(glob.glob(os.path.join(OUTPUT_DIR, "*.json")))
    updated = 0
    skipped = 0
    errors = 0

    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            if "unpacking_result" in data:
                skipped += 1
                continue

            ui = data.get("unpacking_info")
            ca = data.get("code_analysis", {})
            pa = ca.get("_packing_assessment", {}) if isinstance(ca, dict) else {}
            original_dex_count = ca.get("dex_count", 0) if isinstance(ca, dict) else 0

            if ui and isinstance(ui, dict):
                result = build_from_unpacking_info(ui, pa)
            elif pa and isinstance(pa, dict) and pa.get("is_packed", False):
                result = build_from_packing_assessment(pa, original_dex_count)
            else:
                result = build_not_packed(original_dex_count)

            data["unpacking_result"] = result

            with open(f, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            updated += 1

        except Exception as e:
            print(f"  [!] Error: {os.path.basename(f)}: {e}")
            errors += 1

    print(f"\nTotal: {len(files)} files")
    print(f"Updated: {updated}")
    print(f"Skipped (already has field): {skipped}")
    print(f"Errors: {errors}")


if __name__ == "__main__":
    main()
