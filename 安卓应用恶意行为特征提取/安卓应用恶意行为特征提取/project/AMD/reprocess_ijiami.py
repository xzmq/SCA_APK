#!/usr/bin/env python3
"""Re-process 6 Ijiami APKs that had 0 behaviors due to failed unpacking.
Now that unpacker.py has _extract_hidden_dex_from_assets(), these will
get proper analysis with the real DEX extracted from assets/polacin.io.
"""
import sys, os, time, json, subprocess, multiprocessing

if __name__ == "__main__":
    multiprocessing.set_start_method("fork", force=True)

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, BASE_DIR)

    from run_pipeline import process_single_apk, compute_output_path

    SCRIPTS = {
        "sub01": os.path.join(BASE_DIR, "extract_apk_metadata.py"),
        "sub02": os.path.join(BASE_DIR, "extract_code_behavior.py"),
        "sub03": os.path.join(BASE_DIR, "extract_c2_iocs.py"),
        "sub04": os.path.join(BASE_DIR, "extract_risk_profile.py"),
    }

    INPUT_BASE = "/Users/yqh/Downloads/malradar-0"
    OUTPUT_DIR = "/Users/yqh/knowledge_graph/output/malradar-0"

    IJAMI_APKS = [
        "4a271ea970d1edf9b088cada7d1f0a6654260f3d6a0f72f3c9a109c0c96f9ad8.apk",
        "5c2f69ec20f38b5e6a173c661cb5db05b01ed44ac0d16a0408233ecd0c18a139.apk",
        "5f798a80247b1520f98fe08d784743d18556be5f132a7e5d355373f42f32b93b.apk",
        "5f9f60e56c86c99c596bd96d43b183608d8ca94c54852055bf77f0a2a21acc70.apk",
        "89f9ae917deee7f168f62a3fce9e5e0dd6742fb1b8979bcd9907d29af8196e7d.apk",
        "b00c3409b3d46712758ac75221dc3ce705d711757fbd6847d5d088f98fa26995.apk",
    ]

    for idx, apk_name in enumerate(IJAMI_APKS, 1):
        apk_path = os.path.join(INPUT_BASE, apk_name)
        final_path = compute_output_path(apk_path, INPUT_BASE, OUTPUT_DIR)

        if os.path.exists(final_path):
            print(f"\n[{idx}/{len(IJAMI_APKS)}] Already exists, skip: {apk_name[:20]}...")
            continue

        print(f"\n{'='*60}")
        print(f"[{idx}/{len(IJAMI_APKS)}] Processing: {apk_name[:20]}...")
        print(f"{'='*60}")

        try:
            master = process_single_apk(apk_path, final_path, SCRIPTS, BASE_DIR)
            if master:
                mb = master.get("malicious_behavior", {})
                true_count = sum(1 for k, v in mb.items() if isinstance(v, bool) and v)
                ui = master.get("unpacking_info", {})
                print(f"  -> Behaviors: {true_count}, Method: {ui.get('unpacking_method','N/A')}, DEX: {ui.get('unpacked_dex_count',0)}")
            else:
                print("  -> No master result")
        except Exception as e:
            print(f"  -> ERROR: {e}")

        time.sleep(5)

    print("\nDone!")
