"""
run_pipeline.py - Main pipeline orchestrator.
jadx MCP lifecycle per APK: launch jadx-gui → extract features → save output → close jadx-gui.
Usage:
  Single APK:  python run_pipeline.py <apk_path> <output_dir>
  Batch dir:   python run_pipeline.py <input_dir> <output_dir>
"""
import os
import sys
import json
import time
import subprocess
import shutil
import tempfile
import concurrent.futures

sys.stderr.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import launch_jadx_gui, kill_jadx_gui, clear_jadx_cache, compute_file_hashes, load_apk_report_mapping
from config import JADX_GUI_PATH, JADX_CLI_PATH, JADX_GUI_PLUGIN_PORT, JADX_MCP_READY_TIMEOUT, JADX_MCP_POLL_INTERVAL, REPORT_MAPPING_XLSX, REPORT_MD_DIR, UNPACKING_CONFIDENCE_THRESHOLD, ADB_BIN


def _jadx_cli_direct_cmd(jadx_cli):
    """Build a JVM-direct jadx CLI command (bypasses the .bat wrapper).

    On Windows, subprocess.run(<x>.bat, capture_output=True, timeout=N) makes
    cmd.exe the direct child; on timeout Python kills only cmd, the java.exe
    grandchild survives holding the stdout pipe and communicate() blocks
    forever (observed agent stall). Calling java.exe directly makes the
    timed-out child the JVM itself, so the kill closes the pipe cleanly.
    Returns a command list, or None if a direct call cannot be constructed.
    """
    try:
        if not (jadx_cli and os.path.isfile(jadx_cli) and jadx_cli.lower().endswith(".bat")):
            return None
        lib_dir = os.path.normpath(os.path.join(os.path.dirname(jadx_cli), "..", "lib"))
        if not os.path.isdir(lib_dir):
            return None
        jar = None
        for f in sorted(os.listdir(lib_dir)):
            if f.startswith("jadx-") and f.endswith("-all.jar"):
                jar = os.path.join(lib_dir, f)
                break
        if not jar:
            return None
        java = shutil.which("java") or os.environ.get("JAVA_BIN") or ""
        if not (java and os.path.isfile(java)):
            return None
        return [java, "-Xmx1500m",
                "-Djdk.util.zip.disableZip64ExtraFieldValidation=true",
                "-cp", jar, "jadx.cli.JadxCLI"]
    except Exception:
        return None


def _run_jadx_cli_decompile(jadx_cli, out_dir, apk, timeout=300):
    """Run jadx CLI decompilation with the deadlock-safe direct-JVM command.
    Returns True on success, False on timeout/failure."""
    direct = _jadx_cli_direct_cmd(jadx_cli)
    cmd = direct if direct else [jadx_cli]
    try:
        subprocess.run(
            cmd + ["-d", out_dir, "--no-res", "-q", "--show-bad-code", apk],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return True
    except subprocess.TimeoutExpired:
        print(f"  [!] jadx CLI decompilation timed out ({timeout}s), continuing without decompiled source")
        return False
    except Exception as e:
        print(f"  [!] jadx CLI decompilation failed: {e}")
        return False


def find_all_apks(input_path):
    """Recursively find all .apk files in a directory."""
    apks = []
    for root, dirs, files in os.walk(input_path):
        for f in files:
            if f.lower().endswith(".apk"):
                apks.append(os.path.join(root, f))
    return sorted(apks)


def compute_output_path(apk_path, input_base, output_dir):
    """Compute output JSON path based on input mode."""
    apk_name = os.path.splitext(os.path.basename(apk_path))[0] + ".json"
    if os.path.isfile(input_base):
        return os.path.join(output_dir, apk_name)
    rel = os.path.relpath(os.path.dirname(apk_path), input_base)
    if rel == ".":
        return os.path.join(output_dir, apk_name)
    return os.path.join(output_dir, rel, apk_name)


def clear_none_recursive(obj):
    """Recursively replace None with proper defaults."""
    if obj is None:
        return ""
    if isinstance(obj, dict):
        return {k: clear_none_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [clear_none_recursive(item) for item in obj]
    return obj


def run_single_script(script_path, args, timeout=300):
    """Run a single Python script, return (exit_code, stdout, elapsed_seconds)."""
    start = time.time()
    cmd = [sys.executable, script_path] + args
    sys.stderr.write(f"[*] Running: {os.path.basename(script_path)} {' '.join(args[:3])}\n")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace", env=env)
        elapsed = round(time.time() - start, 1)
        output = result.stdout.strip().replace('\ufffd', '?')
        if output:
            for line in output.split('\n')[-5:]:
                sys.stderr.write(f"  {line}\n")
        if result.returncode != 0 and result.stderr:
            errout = result.stderr.strip().replace('\ufffd', '?')
            for line in errout.split('\n')[:5]:
                sys.stderr.write(f"  [!] stderr: {line}\n")
        return result.returncode, output, elapsed
    except subprocess.TimeoutExpired:
        elapsed = round(time.time() - start, 1)
        print(f"  [!] Script timed out after {timeout}s")
        return 1, "", elapsed
    except Exception as e:
        elapsed = round(time.time() - start, 1)
        print(f"  [!] Script error: {e}")
        return 1, str(e), elapsed


def _run_script_task(script_path, args, timeout):
    """Worker for concurrent sub-script execution. Returns (script_path, exit_code, elapsed)."""
    start = time.time()
    cmd = [sys.executable, script_path] + args
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace", env=env)
        elapsed = round(time.time() - start, 1)
        output = result.stdout.strip().replace('\ufffd', '?')
        if output:
            for line in output.split('\n')[-5:]:
                sys.stderr.write(f"  [sub-{os.path.basename(script_path)}] {line}\n")
        if result.returncode != 0 and result.stderr:
            errout = result.stderr.strip().replace('\ufffd', '?')
            for line in errout.split('\n')[:5]:
                sys.stderr.write(f"  [!] sub-{os.path.basename(script_path)} stderr: {line}\n")
        return script_path, result.returncode, elapsed
    except subprocess.TimeoutExpired:
        elapsed = round(time.time() - start, 1)
        sys.stderr.write(f"  [!] Script timed out after {timeout}s: {script_path}\n")
        return script_path, 1, elapsed
    except Exception as e:
        elapsed = round(time.time() - start, 1)
        sys.stderr.write(f"  [!] Script error: {e}: {script_path}\n")
        return script_path, 1, elapsed


def wait_jadx_mcp_ready(timeout=JADX_MCP_READY_TIMEOUT, interval=JADX_MCP_POLL_INTERVAL):
    """Wait for jadx plugin to be ready by polling HTTP health endpoint on port 8650."""
    try:
        import requests as _req
    except ImportError:
        print("[!] requests library not available for health check")
        return False

    port = JADX_GUI_PLUGIN_PORT
    health_url = f"http://127.0.0.1:{port}/health"
    deadline = time.time() + timeout
    poll_count = 0
    while time.time() < deadline:
        try:
            r = _req.get(health_url, timeout=2)
            if r.status_code == 200:
                print(f"  [+] jadx plugin health check passed on port {port}")
                return True
        except Exception:
            pass
        poll_count += 1
        if poll_count % 10 == 0:
            remaining = round(deadline - time.time(), 0)
            print(f"  [*] Waiting for jadx plugin on port {port}... ({remaining}s remaining)")
        time.sleep(interval)
    print(f"[!] jadx plugin did not become ready on port {port} in {timeout}s")
    return False


def merge_outputs(output_dir, apk_path):
    """Merge all sub-agent JSON outputs into master_output.json."""
    master = {
        "apk_sha256": "",
        "apk_path": apk_path,
    }

    import hashlib
    try:
        h = hashlib.sha256()
        with open(apk_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        master["apk_sha256"] = h.hexdigest()
    except Exception:
        master["apk_sha256"] = ""

    merge_fields = [
        "file_basic", "certificate_analysis", "permissions", "components",
        "code_analysis", "malicious_behavior", "native_analysis",
        "c2_communication", "iocs",
        "data_classification", "risk_dimension_scores",
        "advertisement_analysis", "attack_profile",
    ]

    for field_name in merge_fields:
        json_path = os.path.join(output_dir, field_name + ".json")
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                master[field_name] = clear_none_recursive(data)
                print(f"  [+] Merged: {field_name}")
            except Exception as e:
                print(f"  [!] Failed to merge {field_name}: {e}")
                master[field_name] = {}
        else:
            master[field_name] = {}
            print(f"  [!] Missing: {field_name}")

    return master


def _cross_validate(master):
    """F2: Cross-field consistency validation (main agent review).
    Checks structural consistency across the 13 top-level fields.
    Returns a validation report dict with warnings (non-blocking).
    """
    warnings = []

    mb = master.get("malicious_behavior", {})
    c2 = master.get("c2_communication", {})
    iocs = master.get("iocs", {})
    comps = master.get("components", {})
    risk = master.get("risk_dimension_scores", {})
    ap = master.get("attack_profile", {})
    dc = master.get("data_classification", [])

    # Rule 1: null scan (should be clean after clear_none_recursive, but verify)
    def _scan_nulls(obj, path=""):
        if obj is None:
            warnings.append(f"null value found at {path}")
        elif isinstance(obj, dict):
            for k, v in obj.items():
                _scan_nulls(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _scan_nulls(v, f"{path}[{i}]")
    _scan_nulls(master)

    # Rule 2: iocs.c2_urls should NOT duplicate c2_servers[].url (deduplicated)
    # New semantics: iocs.c2_urls only contains extra URLs from decrypted results
    c2_urls_in_servers = set()
    for srv in c2.get("c2_servers", []):
        url = srv.get("url", "")
        if url:
            c2_urls_in_servers.add(url)
    c2_urls_in_iocs = set(iocs.get("c2_urls", []))
    duplicate_urls = c2_urls_in_servers & c2_urls_in_iocs
    if duplicate_urls:
        warnings.append(
            f"iocs.c2_urls contains {len(duplicate_urls)} URLs that duplicate c2_servers[].url "
            f"(should only contain extra URLs from decrypted results)"
        )

    # Rule 3: iocs.c2_ips should be superset of c2_servers[].ip
    c2_ips_in_servers = set()
    for srv in c2.get("c2_servers", []):
        ip = srv.get("ip", "")
        if ip:
            c2_ips_in_servers.add(ip)
    iocs_c2_ips = set(iocs.get("c2_ips", []))
    missing_ips = c2_ips_in_servers - iocs_c2_ips
    if missing_ips:
        warnings.append(
            f"iocs.c2_ips missing {len(missing_ips)} IPs from c2_servers[].ip"
        )

    # Rule 4: has_c2_communication vs c2_communication.has_c2 consistency
    mb_has_c2 = mb.get("has_c2_communication", False)
    c2_has_c2 = c2.get("has_c2", False)
    c2_servers_count = len(c2.get("c2_servers", []))
    if mb_has_c2 and not c2_has_c2 and c2_servers_count == 0:
        warnings.append(
            "malicious_behavior.has_c2_communication=true but c2_communication.has_c2=false "
            "and c2_servers is empty (may indicate dynamic URL resolution)"
        )

    # Rule 5: sms intercept consistency (components vs malicious_behavior)
    sms_recv_suspicious = any(
        r.get("has_sms_intercept", False)
        for r in comps.get("suspicious_receivers", [])
    )
    mb_sms_broadcast = mb.get("sms_intercept_via_broadcast", False)
    mb_sms_observer = mb.get("sms_intercept_via_content_observer", False)
    if sms_recv_suspicious and not (mb_sms_broadcast or mb_sms_observer):
        warnings.append(
            "components.suspicious_receivers has SMS intercept but "
            "malicious_behavior sms_intercept flags are both false"
        )

    # Rule 6: risk_level consistency (risk_dimension_scores.total vs attack_profile.overall_judgment)
    total_risk_level = risk.get("total", {}).get("risk_level", "")
    overall_risk_label = ap.get("overall_judgment", {}).get("risk_label", "")
    if total_risk_level and overall_risk_label:
        # Normalize: both should indicate similar severity
        level_map = {"RED": 4, "ORANGE": 3, "YELLOW": 2, "GREEN": 1}
        total_score = level_map.get(total_risk_level.upper(), 0)
        # overall_judgment.risk_label may contain "RED"/"ORANGE"/etc.
        label_upper = overall_risk_label.upper()
        for k, v in level_map.items():
            if k in label_upper:
                overall_score = v
                break
        else:
            overall_score = 0
        if total_score and overall_score and abs(total_score - overall_score) >= 2:
            warnings.append(
                f"risk_dimension_scores.total.risk_level={total_risk_level} "
                f"and attack_profile.overall_judgment.risk_label={overall_risk_label} "
                f"differ by >=2 severity levels"
            )

    # Rule 7: data_classification entries should roughly match malicious_behavior true count
    mb_true_count = sum(1 for v in mb.values() if isinstance(v, bool) and v)
    dc_count = len(dc) if isinstance(dc, list) else 0
    if mb_true_count > 0 and dc_count == 0:
        warnings.append(
            f"malicious_behavior has {mb_true_count} true flags but "
            f"data_classification is empty"
        )

    report = {
        "total_warnings": len(warnings),
        "warnings": warnings,
    }
    print(f"  [+] Cross-validation: {len(warnings)} warnings")
    for w in warnings[:5]:
        print(f"      [!] {w}")
    if len(warnings) > 5:
        print(f"      ... and {len(warnings) - 5} more")
    return report


def _fill_is_packed(master):
    """F-B: Set file_basic.is_packed from code_analysis packing assessment.
    Spec sub01 requires: is_packed = python 静态检测（结合子02 的 is_packed_and_repackaged）
    """
    code = master.get("code_analysis", {})
    fb = master.get("file_basic", {})
    if not isinstance(fb, dict):
        fb = {}

    pa = code.get("_packing_assessment", {})
    if pa and isinstance(pa, dict):
        fb["is_packed"] = pa.get("is_packed", False)
    elif code.get("is_packed_and_repackaged"):
        fb["is_packed"] = True
    elif fb.get("file_entropy", 0) > 7.5 and code.get("has_dynamic_dex_loading"):
        fb["is_packed"] = True
    else:
        fb["is_packed"] = False

    master["file_basic"] = fb


def _apply_packing_degradation(master):
    """F-D: When packing is detected, mark analysis as potentially incomplete
    and upward-adjust risk score.
    """
    code = master.get("code_analysis", {})
    pa = code.get("_packing_assessment", {})
    if not isinstance(pa, dict):
        return

    confidence = pa.get("confidence", 0)
    if confidence < 40:
        return

    vr = master.setdefault("validation_report", {"total_warnings": 0, "warnings": []})
    warnings = vr.setdefault("warnings", [])

    if confidence >= 60:
        packer_name = pa.get("packer_name", "未知")
        warnings.append(
            f"⚠️ 检测到加固保护(confidence={confidence}%, packer={packer_name})，"
            f"静态分析结果可能不完整——真实恶意代码在加密DEX中"
        )
        # Upward adjust risk score
        ap = master.get("attack_profile", {})
        oj = ap.get("overall_judgment", {})
        old_score = oj.get("risk_score", 0)
        new_score = min(old_score + 2, 10)
        oj["risk_score"] = new_score
        summary = oj.get("summary", "")
        if "加固保护" not in summary:
            oj["summary"] = f"⚠️加固保护:{packer_name} " + summary
        ap["overall_judgment"] = oj
        master["attack_profile"] = ap
        vr["total_warnings"] = len(warnings)
    elif confidence >= 40:
        warnings.append(
            f"检测到疑似加固特征(confidence={confidence}%)，分析完整性可能受影响"
        )
        vr["total_warnings"] = len(warnings)


def process_single_apk(apk_path, final_output_path, scripts, base_dir):
    """Process a single APK through the full pipeline.

    jadx MCP lifecycle:
      1. launch jadx-gui with target APK
      2. wait for MCP ready
      3. sub01/sub02/sub03 run in parallel (all access same jclass MCP)
      4. sub04 runs after (aggregates 01-03 output)
      5. merge all JSON into final output
      6. close jadx-gui + clear cache
    """
    print(f"\n{'='*60}")
    print(f"Processing APK: {os.path.basename(apk_path)}")
    print(f"Output: {final_output_path}")
    print(f"{'='*60}")

    tmp_dir = tempfile.mkdtemp()
    start = time.time()

    try:
        # ── Phase 0: Pre-jadx static lookups (no jadx required) ──
        print("\n[Phase 0] Preprocessing (hash, report mapping from Excel)...")
        apk_hashes = compute_file_hashes(apk_path)
        apk_sha256 = apk_hashes["sha256"]
        print(f"  [+] SHA256: {apk_sha256[:16]}...")
        report_md_path, malware_family = load_apk_report_mapping(apk_sha256, REPORT_MAPPING_XLSX, REPORT_MD_DIR)
        known_behaviors_info = None

        if report_md_path:
            print(f"  [+] Report MD found: {os.path.basename(report_md_path)}")
            from common import parse_report_behaviors
            known_behaviors_info, report_keywords, _ = parse_report_behaviors(report_md_path)
            if report_keywords:
                print(f"  [+] Report keywords ({len(report_keywords)}): {report_keywords[:8]}")
            if known_behaviors_info:
                names = [b["name"] for b in known_behaviors_info]
                print(f"  [+] Known behaviors ({len(known_behaviors_info)}): {names}")
                # Save known_behaviors to tmp_dir for sub04 LLM context
                kb_path = os.path.join(tmp_dir, "known_behaviors.json")
                with open(kb_path, "w", encoding="utf-8") as f:
                    json.dump(known_behaviors_info, f, ensure_ascii=False, indent=2)
                print(f"  [+] Saved known_behaviors.json to tmp_dir")
        else:
            print("  [-] No report mapping found for this SHA256")

        if malware_family:
            print(f"  [+] Malware family: {malware_family}")

        # ── Phase 0.5: jadx CLI full decompilation (deterministic) ──
        print(f"\n[Phase 0.5] jadx CLI full decompilation (deterministic source)...")
        jadx_decompiled_dir = os.path.join(tmp_dir, "jadx_decompiled")
        jadx_cli = JADX_CLI_PATH
        if not os.path.isfile(jadx_cli):
            jadx_cli = JADX_GUI_PATH.replace("/bin/jadx-gui", "/bin/jadx")
        if not os.path.isfile(jadx_cli):
            jadx_cli = JADX_GUI_PATH.replace("jadx-gui", "jadx")
        if _run_jadx_cli_decompile(jadx_cli, jadx_decompiled_dir, apk_path, timeout=300):
            total_java = sum(1 for _ in __import__('pathlib').Path(jadx_decompiled_dir).rglob("*.java"))
            print(f"  [+] Decompiled: {total_java} Java source files")
        else:
            jadx_decompiled_dir = ""

        # ── Phase 1: Launch jadx-gui with current APK ──
        print(f"\n[Phase 1] Launching jadx-gui with: {os.path.basename(apk_path)}")
        jadx_ready = False
        try:
            launch_jadx_gui(JADX_GUI_PATH, apk_path)
            ready = wait_jadx_mcp_ready()
            if ready:
                jadx_ready = True
                print(f"  [+] jadx-gui connected and ready")
            else:
                print("[!] jadx MCP did not become ready — will attempt extraction with androguard fallback")
        except Exception as e:
            print(f"[!] jadx-gui launch failed: {e}")
            print("[!] Falling back to androguard-only mode for this APK")

        # ── Phase 2: Parallel feature extraction (sub01, sub02, sub03) ──
        print("\n[Phase 2] Running sub-agents in parallel (sub01, sub02, sub03)...")
        script_tasks = [
            ("sub01", [apk_path, tmp_dir, malware_family if malware_family else ""]),
            ("sub02", [apk_path, tmp_dir, report_md_path if report_md_path else ""]),
            ("sub03", [apk_path, tmp_dir, jadx_decompiled_dir]),
        ]
        completed_scripts = set()

        with concurrent.futures.ProcessPoolExecutor(max_workers=3) as executor:
            futures = {}
            for sub_name, sub_args in script_tasks:
                script = scripts[sub_name]
                if not os.path.exists(script):
                    print(f"  [!] Script not found: {script}")
                    continue
                print(f"  [*] Starting {sub_name}...")
                fut = executor.submit(_run_script_task, script, sub_args, 1200)
                futures[fut] = sub_name

            for fut in concurrent.futures.as_completed(futures):
                sub_name = futures[fut]
                try:
                    _, rc, elapsed = fut.result()
                    if rc == 0:
                        print(f"  [+] {sub_name} completed ({elapsed}s)")
                        completed_scripts.add(sub_name)
                    else:
                        print(f"  [!] {sub_name} failed (exit {rc})")
                        completed_scripts.add(sub_name)
                except Exception as e:
                    print(f"  [!] {sub_name} exception: {e}")

        completed_count = len(completed_scripts)
        print(f"  [+] Phase 2 done: {completed_count}/3 sub-agents finished")

        # ── Phase 2.5: Unpacking if packing detected ──
        unpacking_info = None
        unpacking_result = {
            "is_packed": False,
            "packer_name": "",
            "confidence": 0,
            "threshold_exceeded": False,
            "status": "not_packed",
            "method": "not_packed",
            "attempted_methods": [],
            "unpacked_dex_files": [],
            "unpacked_dex_count": 0,
            "original_dex_count": 0,
            "dex_sources": [],
            "dex_source_detail": "",
            "indicators": [],
            "errors": [],
            "repacked": False,
        }
        try:
            code_analysis_path = os.path.join(tmp_dir, "code_analysis.json")
            if os.path.exists(code_analysis_path):
                with open(code_analysis_path, "r", encoding="utf-8") as f:
                    code_analysis = json.load(f)
                pa = code_analysis.get("_packing_assessment", {})
                confidence = pa.get("confidence", 0)
                is_packed = pa.get("is_packed", False)
                packer_name = pa.get("packer_name", "")
                indicators = pa.get("indicators", [])

                unpacking_result["is_packed"] = is_packed
                unpacking_result["packer_name"] = packer_name
                unpacking_result["confidence"] = confidence
                unpacking_result["indicators"] = indicators
                unpacking_result["original_dex_count"] = code_analysis.get("dex_count", 0)
                unpacking_result["threshold_exceeded"] = (confidence >= UNPACKING_CONFIDENCE_THRESHOLD)

                if is_packed and confidence >= UNPACKING_CONFIDENCE_THRESHOLD:
                    print(f"\n[Phase 2.5] Packing detected (confidence={confidence}%, packer={packer_name})")
                    print(f"  [*] Attempting unpacking...")

                    decrypted_dex = []
                    unpack_method = "failed"

                    # Try F-E-lite: static DEX reconstruction
                    try:
                        from unpacker import try_static_unpack
                        print("  [*] [F-E-lite] Static DEX reconstruction...")
                        decrypted_dex = try_static_unpack(apk_path, pa, tmp_dir)
                        unpacking_result["attempted_methods"].append("static")
                        if decrypted_dex:
                            unpack_method = "static"
                            print(f"  [+] [F-E-lite] Success: {len(decrypted_dex)} DEX files")
                            detail = getattr(try_static_unpack, "_last_detail", "")
                            sources = getattr(try_static_unpack, "_last_sources", [])
                            unpacking_result["dex_source_detail"] = detail
                            unpacking_result["dex_sources"] = sources
                    except Exception as e:
                        print(f"  [!] [F-E-lite] Failed: {e}")
                        unpacking_result["attempted_methods"].append("static")
                        unpacking_result["errors"].append({"method": "static", "error": str(e)})

                    # Try F-E-full: dynamic Frida dump (if static failed)
                    if not decrypted_dex:
                        try:
                            from dynamic_unpacker import try_dynamic_unpack, start_emulator_if_needed, check_dynamic_environment
                            env = check_dynamic_environment()
                            if not env["device_connected"] and env["adb_available"]:
                                start_emulator_if_needed()
                            print("  [*] [F-E-full] Dynamic Frida DEX dump...")
                            decrypted_dex = try_dynamic_unpack(apk_path, pa, tmp_dir)
                            unpacking_result["attempted_methods"].append("dynamic")
                            if decrypted_dex:
                                unpack_method = "dynamic"
                                print(f"  [+] [F-E-full] Success: {len(decrypted_dex)} DEX files")
                                unpacking_result["dex_source_detail"] = "memory_dump"
                                unpacking_result["dex_sources"] = [os.path.basename(p) for p in decrypted_dex]
                            else:
                                unpacking_result["errors"].append({"method": "dynamic", "error": "No DEX files dumped"})
                        except Exception as e:
                            print(f"  [!] [F-E-full] Failed: {e}")
                            unpacking_result["attempted_methods"].append("dynamic")
                            unpacking_result["errors"].append({"method": "dynamic", "error": str(e)})

                    # If unpacking succeeded, repackage and re-run sub01-03
                    if decrypted_dex:
                        from repacker import repackage_with_decrypted_dex
                        print("  [*] [Repacker] Repackaging APK with decrypted DEX...")
                        repacked_apk = repackage_with_decrypted_dex(apk_path, decrypted_dex, tmp_dir)

                        # Build DEX file details
                        dex_files_info = []
                        for dex_path in decrypted_dex:
                            try:
                                dex_size = os.path.getsize(dex_path)
                            except Exception:
                                dex_size = 0
                            dex_files_info.append({
                                "path": os.path.basename(dex_path),
                                "size_bytes": dex_size,
                            })
                        unpacking_result["unpacked_dex_files"] = dex_files_info
                        unpacking_result["unpacked_dex_count"] = len(decrypted_dex)

                        if repacked_apk:
                            unpacking_info = {
                                "was_packed": True,
                                "packer_name": packer_name,
                                "confidence": confidence,
                                "unpacking_method": unpack_method,
                                "unpacked_dex_count": len(decrypted_dex),
                                "original_dex_count": code_analysis.get("dex_count", 0),
                                "repacked_apk_path": repacked_apk,
                                "indicators": indicators,
                            }
                            unpacking_result["repacked"] = True
                            unpacking_result["status"] = "success"
                            unpacking_result["method"] = unpack_method

                            # Re-decompile the unpacked APK with jadx CLI (deterministic)
                            print("  [*] [Phase 2.5] Re-decompiling unpacked APK with jadx CLI...")
                            unpacked_decompiled_dir = os.path.join(tmp_dir, "jadx_decompiled_unpacked")
                            if _run_jadx_cli_decompile(jadx_cli, unpacked_decompiled_dir, repacked_apk, timeout=300):
                                total_java = sum(1 for _ in __import__('pathlib').Path(unpacked_decompiled_dir).rglob("*.java"))
                                print(f"  [+] Unpacked decompilation: {total_java} Java source files")
                            else:
                                unpacked_decompiled_dir = ""

                            # Reload jadx with repackaged APK
                            print("  [*] Reloading jadx-gui with repackaged APK...")
                            kill_jadx_gui()
                            time.sleep(2)
                            launch_jadx_gui(JADX_GUI_PATH, repacked_apk)
                            ready = wait_jadx_mcp_ready()
                            if ready:
                                print("  [+] jadx-gui reloaded with repackaged APK")
                                # Re-run sub01/sub02/sub03 on repackaged APK
                                # sub03 gets the unpacked decompiled source for deterministic crypto analysis
                                print("  [*] Re-running sub01/sub02/sub03 on repackaged APK...")
                                re_run_tasks = [
                                    ("sub01-re", [repacked_apk, tmp_dir, malware_family if malware_family else ""]),
                                    ("sub02-re", [repacked_apk, tmp_dir, report_md_path if report_md_path else ""]),
                                    ("sub03-re", [repacked_apk, tmp_dir, unpacked_decompiled_dir]),
                                ]
                                with concurrent.futures.ProcessPoolExecutor(max_workers=3) as executor:
                                    futures = {}
                                    for sub_name, sub_args in re_run_tasks:
                                        script_key = sub_name.split("-")[0]
                                        script = scripts[script_key]
                                        fut = executor.submit(_run_script_task, script, sub_args, 1200)
                                        futures[fut] = sub_name
                                    for fut in concurrent.futures.as_completed(futures):
                                        sub_name = futures[fut]
                                        try:
                                            _, rc, elapsed = fut.result()
                                            print(f"  [{'+' if rc == 0 else '!'}] {sub_name} ({elapsed}s, exit={rc})")
                                        except Exception as e:
                                            print(f"  [!] {sub_name} exception: {e}")
                            else:
                                print("  [!] jadx-gui reload failed — using original results")
                        else:
                            print("  [!] Repackaging failed — using original results")
                    else:
                        print("  [!] Unpacking failed — analysis may be incomplete (see F-D degradation)")
                        unpacking_info = {
                            "was_packed": True,
                            "packer_name": packer_name,
                            "confidence": confidence,
                            "unpacking_method": "failed",
                            "unpacked_dex_count": 0,
                            "original_dex_count": code_analysis.get("dex_count", 0),
                            "indicators": indicators,
                        }
                        unpacking_result["status"] = "failed"
                        unpacking_result["method"] = "failed"
                elif is_packed:
                    unpacking_result["status"] = "not_attempted"
                    unpacking_result["method"] = "not_attempted"
        except Exception as e:
            print(f"  [!] Phase 2.5 error: {e}")
            unpacking_result["errors"].append({"method": "pipeline", "error": str(e)})

        if unpacking_info:
            process_single_apk._unpacking_info = unpacking_info
        else:
            process_single_apk._unpacking_info = None
        process_single_apk._unpacking_result = unpacking_result

        # ── Phase 3: sub04 aggregation (depends on 01-03 output) ──
        print("\n[Phase 3] Running sub-agent 04 (aggregation)...")
        rc, out, elapsed = run_single_script(scripts["sub04"], [tmp_dir, apk_path], timeout=1200)
        if rc == 0:
            print(f"  [+] sub04 completed ({elapsed}s)")
        else:
            print(f"  [!] sub04 failed (exit {rc})")

        # ── Phase 4: Merge and save final output ──
        print("\n[Phase 4] Merging outputs and saving final JSON...")
        master = merge_outputs(tmp_dir, apk_path)

        # F2: Cross-field consistency validation
        print("  [*] Cross-validating field consistency...")
        validation_report = _cross_validate(master)
        master["validation_report"] = validation_report

        # F-B: Fill file_basic.is_packed from code_analysis packing assessment
        _fill_is_packed(master)

        # F-D: Apply packing degradation (adjust risk score if packed)
        _apply_packing_degradation(master)

        # Record unpacking info if applicable
        if hasattr(process_single_apk, '_unpacking_info') and process_single_apk._unpacking_info:
            master["unpacking_info"] = process_single_apk._unpacking_info

        # Always record unpacking_result
        if hasattr(process_single_apk, '_unpacking_result'):
            master["unpacking_result"] = process_single_apk._unpacking_result

        out_dir = os.path.dirname(final_output_path)
        os.makedirs(out_dir, exist_ok=True)
        with open(final_output_path, "w", encoding="utf-8") as f:
            json.dump(master, f, ensure_ascii=False, indent=2)
        print(f"  [+] Final output saved: {final_output_path}")

        elapsed_total = round(time.time() - start, 1)
        print(f"  [+] APK processing complete ({elapsed_total}s)")
        return master

    finally:
        # ── Cleanup: close jadx-gui + clear cache ──
        print("\n[Cleanup] Closing jadx-gui and clearing cache...")
        kill_jadx_gui()
        clear_jadx_cache()
        try:
            shutil.rmtree(tmp_dir)
            print(f"  [+] Temp directory cleaned: {tmp_dir}")
        except Exception:
            pass
        print("  [+] jadx lifecycle cleanup complete — ready for next APK")


def _output_is_valid(path):
    """Return True if path exists and parses as JSON."""
    if not os.path.exists(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            json.load(f)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _apk_lock_path(apk_path, output_dir):
    import hashlib
    digest = hashlib.sha1(
        (os.path.abspath(apk_path) + "|" + os.path.abspath(output_dir)).encode()
    ).hexdigest()[:16]
    lock_dir = os.path.join(tempfile.gettempdir(), "amd_apk_locks")
    os.makedirs(lock_dir, exist_ok=True)
    return os.path.join(lock_dir, f"{digest}.lock")


def _try_acquire_lock(lock_path):
    try:
        f = open(lock_path, "a+")
        if sys.platform == "win32":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except Exception:
        try:
            f.close()
        except Exception:
            pass
        return None


def _release_lock(lock):
    if lock is None:
        return
    try:
        if sys.platform == "win32":
            import msvcrt
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        lock.close()
    except Exception:
        pass


def main():
    if len(sys.argv) < 3:
        print("Usage: run_pipeline.py <apk_path|input_dir> <output_dir>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_dir = sys.argv[2]
    os.makedirs(output_dir, exist_ok=True)
    base_dir = os.path.dirname(os.path.abspath(__file__))

    scripts = {
        "sub01": os.path.join(base_dir, "extract_apk_metadata.py"),
        "sub02": os.path.join(base_dir, "extract_code_behavior.py"),
        "sub03": os.path.join(base_dir, "extract_c2_iocs.py"),
        "sub04": os.path.join(base_dir, "extract_risk_profile.py"),
    }

    # Determine input mode
    if os.path.isfile(input_path) and input_path.lower().endswith(".apk"):
        apks = [input_path]
        input_base = input_path
    elif os.path.isdir(input_path):
        apks = find_all_apks(input_path)
        input_base = input_path
    else:
        print(f"[!] Invalid input: {input_path}")
        sys.exit(1)

    if not apks:
        print("[!] No APK files found.")
        sys.exit(1)

    print("=" * 60)
    print("Android APK Static Analysis Pipeline")
    print("=" * 60)
    print(f"Input:    {input_path}")
    print(f"Output:   {output_dir}")
    print(f"APKs:     {len(apks)}")
    print(f"jadx MCP lifecycle per APK: launch → extract → save → close")
    print("=" * 60)

    pipeline_start = time.time()
    results = []
    skipped = 0

    # Parallel-safe loop: two agents may scan the same directory concurrently.
    # Use a per-APK non-blocking file lock so only one agent processes any given
    # APK; APKs locked by the other agent are requeued and resolved on pass 2.
    deferred = []
    for idx, apk in enumerate(apks, 1):
        final_path = compute_output_path(apk, input_base, output_dir)
        if _output_is_valid(final_path):
            print(f"\n[{idx}/{len(apks)}] SKIP (already exists): {os.path.basename(apk)}")
            skipped += 1
            continue

        lock = _try_acquire_lock(_apk_lock_path(apk, output_dir))
        if lock is None:
            print(f"\n[{idx}/{len(apks)}] DEFER (locked by another agent): {os.path.basename(apk)}")
            deferred.append(apk)
            continue

        try:
            if _output_is_valid(final_path):
                print(f"\n[{idx}/{len(apks)}] SKIP (completed meanwhile): {os.path.basename(apk)}")
                skipped += 1
                continue
            print(f"\n{'#'*60}")
            print(f"[{idx}/{len(apks)}] Processing: {os.path.basename(apk)}")
            print(f"{'#'*60}")
            master = process_single_apk(apk, final_path, scripts, base_dir)
            results.append((apk, final_path, master))
        finally:
            _release_lock(lock)

    # Pass 2: resolve any APKs that were locked by another agent during pass 1.
    for idx, apk in enumerate(deferred, 1):
        final_path = compute_output_path(apk, input_base, output_dir)
        if _output_is_valid(final_path):
            print(f"\n[defer {idx}/{len(deferred)}] SKIP (completed by other agent): {os.path.basename(apk)}")
            skipped += 1
            continue
        print(f"\n{'#'*60}")
        print(f"[defer {idx}/{len(deferred)}] Processing: {os.path.basename(apk)}")
        print(f"{'#'*60}")
        master = process_single_apk(apk, final_path, scripts, base_dir)
        results.append((apk, final_path, master))

    total_time = round(time.time() - pipeline_start, 1)
    print(f"\n{'='*60}")
    print("All APKs processed")
    print(f"{'='*60}")
    print(f"Total APKs: {len(apks)}, Processed: {len(results)}, Skipped: {skipped}")
    print(f"Total time: {total_time}s")
    print(f"Output directory: {output_dir}")

    # Shut down emulator if it was started by this pipeline
    try:
        from dynamic_unpacker import stop_emulator_if_started
        adb_cmd = shutil.which("adb") or ADB_BIN
        stop_emulator_if_started(adb_cmd)
    except Exception as e:
        print(f"[!] Emulator shutdown: {e}")

    print("=" * 60)


if __name__ == "__main__":
    main()
