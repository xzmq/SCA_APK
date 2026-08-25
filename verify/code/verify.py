import json
import os
import re
import sys
import time
import threading
import concurrent.futures
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "task", "code"))

from openai import OpenAI

API_BASE = "https://dashscope.aliyuncs.com/compatible-mode/v1"
API_KEY = "sk-ws-H.ELIXPIR.ZYRS.MEYCIQCaF_ecIL7AiymvGXvp_gJvsQxkOnO3sqRaLv2TFUF48wIhAK2ooqHqPXwZlfmShiTJNhsLIzrxusz6eYGcESln7RnD"
MODEL = "qwen3.7-plus"

RESULT_BASE = os.path.join("D:", os.sep, "SCA_APK", "vul_code_result")
OUTPUT_DIR = os.path.join("D:", os.sep, "SCA_APK", "verify", "output")

BEHAVIOR_KEYWORDS = {
    "c2_communication": ["socket", "urlconnection", "httpurlconnection", "okhttpclient", "newcall", "retrofit", "getresponsecode", "connect"],
    "sms_fraud": ["sendtextmessage", "senddatamessage", "smsmanager", "sms_received", "sms_deliver", "abortbroadcast", "sendmultiparttextmessage", "1066", "1069", "smspay", "wap", "billing", "subscribe"],
    "device_fingerprinting": ["getdeviceid", "getimei", "getsubscriberid", "getline1number", "getconfigurednetworks", "android_id", "build.serial", "getmacaddress", "telephonymanager", "getmeid", "getserial", "settings.secure", "getsimserialnumber", "getsimcountryiso"],
    "location_tracking": ["getlastknownlocation", "requestlocationupdates", "locationmanager", "fusedlocationproviderclient", "getlastlocation", "getallproviders", "getlatitude", "getlongitude"],
    "keylogging": ["onaccessibilityevent", "getprimaryclip", "addprimaryclipchangedlistener", "type_view_text_changed", "type_view_focused", "dispatchkeyevent", "clipboardmanager", "getprimaryclip"],
    "ransomware": ["cipher", "dofinal", "locknow", "resetpassword", "devicepolicymanager", "encrypt", "decrypt", "listfiles", "ransom", "bitcoin", "btc", "赎金", "解锁"],
    "banking_trojan": ["addview", "windowmanager", "type_application_overlay", "type_system_alert", "password", "passwd", "login", "signin", "cvv", "银行卡", "密码", "账号", "验证码", "layoutparams", "type_phone"],
    "ad_fraud": ["interstitialad", "loadad", "showad", "adview", "banner", "ad_click", "autoclick", "clickad", "simulateclick", "mobileads", "adview"],
    "persistence": ["startservice", "startforegroundservice", "startforeground", "boot_completed", "wakelock", "foreground_service", "alarmmanager", "setrepeating", "setservice"],
    "root_exploitation": ["runtime", "exec", "/system/bin/su", "/system/xbin/su", "superuser", "magisk", "busybox", "superuser", "/sbin/su"],
    "dynamic_code_loading": ["dexclassloader", "pathclassloader", "loadclass", "loaddex", "classloader", "inmemorydexclassloader"],
    "code_execution": ["runtime", "exec", "processbuilder", "start", "/system/bin/sh", "chmod", "busybox", "runtime.exec", "processbuilder.start"],
    "anti_detection": ["isdebuggerconnected", "ptrace", "tracerpid", "/proc/self/status", "qemu", "goldfish", "ranchu", "ro.kernel.qemu", "dexprotector", "bangcle", "jiagu", "tencentprotect", "360jiagu", "isdebuggerconnected", "debug.waitforthreads"],
    "social_spread": ["setaction", "setpackage", "android.intent.action.send", "com.tencent.mm", "com.tencent.mobileqq", "com.whatsapp", "contactscontract", "action.send"],
    "silent_install_uninstall": ["createsession", "packageinstaller", "install_packages", "application/vnd.android.package-archive", "uninstall", "action.delete", "uninstall_package", "install_session", "action.install"],
    "screen_capture": ["mediaprojection", "createscreencaptureintent", "createvirtualdisplay", "takescreenshot", "surfacecontrol", "virtualdisplay"],
    "camera_capture": ["camera", "opencamera", "takepicture", "image_capture", "camera.parameters", "cameramanager", "cameradevice", "capture"],
    "mic_recording": ["audiorecord", "startrecording", "mediarecorder", "setaudiosource", "audiosource.mic", "voice_call", "voice_uplink", "voice_downlink", "prepare"],
    "call_operations": ["action.call", "action.dial", "call_phone", "killbackgroundprocesses", "forcestoppackage", "killprocess", "calllog", "call_log", "voice_call", "voice.uplink", "voice.downlink", "callrecord", "tel:"],
    "browser_data_theft": ["browser/bookmarks", "browser/history", "browsercontract", "browser.bookmarks", "read_history_bookmarks"],
    "calendar_theft": ["com.android.calendar", "calendarcontract", "calendarcontract.events", "calendarcontract"],
    "wifi_password_theft": ["presharedkey", "wificonfiguration", "allowedkeymanagement", "getconfigurednetworks", "wifiManager"],
    "file_access": ["listfiles", "fileinputstream", "fileoutputstream", "getexternalstoragedirectory", "file", "listfiles", "getAbsolutePath", "createNewFile", "delete"],
    "overlay_attack": ["addview", "windowmanager", "type_application_overlay", "type_system_alert", "type_phone", "layoutparams"],
    "icon_hiding": ["setcomponentenabledsetting", "hideicon", "dont_hide_app_icon", "component_enabled_state_disabled", "packagemanager", "setcomponentenabled"],
    "process_kill": ["killbackgroundprocesses", "forcestoppackage", "killprocess", "activitymanager"],
    "device_reboot": ["reboot", "action.reboot", "/system/bin/reboot", "powermanager"],
    "settings_modify": ["putstring", "settings.system", "settings.secure", "settings.global", "write_settings"],
    "crypto_wallet_detection": ["bc1", "0x", "bitcoin", "btc", "eth", "xmr", "trx", "wallet", "blockchain", "metamask"],
}

client = OpenAI(base_url=API_BASE, api_key=API_KEY, timeout=60)

VERIFY_PROMPT = """你是 Android 安全审计专家。请判断以下代码片段是否真正实现了标注的恶意行为。

恶意行为: {behavior_key}
行为描述: {behavior_description}
类路径: {class_path}
方法签名: {method_signature}

代码片段:
```java
{code_snippet}
```

请判断这段代码是否真正实现了"{behavior_key}"行为，输出 JSON（不要输出其他内容）：
{{
  "match": true 或 false,
  "reason": "中文说明判断理由",
  "actual_behavior": "如果代码做的是其他行为，填写实际行为名；否则留空"
}}

判断标准：
- true：代码确实实现了该恶意行为
- false：代码与该行为无关，或代码是第三方标准库的正常 API，或代码用途合法
- 如果代码确实包含该行为的 API 但用途合法（如 OAuth 用的 Cipher 加密），应判 false

只输出 JSON。"""

log_lock = threading.Lock()

def log(msg):
    with log_lock:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        print(line, flush=True)

def collect_all_results():
    all_results = []
    for dir_name in ["malradar-1", "malradar-2", "malradar-3"]:
        dir_path = os.path.join(RESULT_BASE, dir_name)
        if not os.path.isdir(dir_path):
            continue
        for fname in sorted(os.listdir(dir_path)):
            if not fname.endswith("_vul_code.json"):
                continue
            sha = fname.replace("_vul_code.json", "")
            fpath = os.path.join(dir_path, fname)
            all_results.append((sha, dir_name, fpath))
    return all_results

def extract_pairs(json_data, sha, source_dir):
    pairs = []
    behaviors = json_data.get("行为列表", json_data.get("\u884c\u4e3a\u5217\u8868", []))
    for bh in behaviors:
        bh_key = bh.get("行为", bh.get("\u884c\u4e3a", ""))
        codes = bh.get("恶意代码", bh.get("\u6076\u610f\u4ee3\u7801", []))
        for code in codes:
            pairs.append({
                "apk_sha256": sha,
                "source_dir": source_dir,
                "behavior": bh_key,
                "class_path": code.get("class_path", ""),
                "method_signature": code.get("method_signature", ""),
                "malicious_code_snippet": code.get("malicious_code_snippet", ""),
                "behavior_description": code.get("behavior_description", ""),
            })
    return pairs

def stage1_check(pair):
    behavior = pair["behavior"]
    snippet = pair["malicious_code_snippet"].lower()
    keywords = BEHAVIOR_KEYWORDS.get(behavior, [])
    hit_keywords = [kw for kw in keywords if kw.lower() in snippet]

    issues = []
    llm_needed = False

    if not hit_keywords:
        issues.append("E01_RULE_MISS")
        llm_needed = True

    if len(pair["malicious_code_snippet"].strip()) < 20:
        issues.append("E03_SHORT_SNIPPET")
        llm_needed = True

    desc = pair["behavior_description"]
    if not desc or "GLM" in desc or "分析失败" in desc:
        issues.append("E05_EMPTY_DESC")
        llm_needed = True

    return {
        "passed": not llm_needed,
        "issues": issues,
        "hit_keywords": hit_keywords,
    }

def call_llm_verify(pair):
    snippet = pair["malicious_code_snippet"][:2000]
    desc = pair["behavior_description"][:300] if pair["behavior_description"] else "无"
    prompt = VERIFY_PROMPT.format(
        behavior_key=pair["behavior"],
        behavior_description=desc,
        class_path=pair["class_path"],
        method_signature=pair["method_signature"],
        code_snippet=snippet,
    )

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "你是 Android 安全审计专家，只输出 JSON。"},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=500,
        )
        content = resp.choices[0].message.content.strip()
        usage = resp.usage

        if content.startswith("```"):
            lines = content.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            content = "\n".join(lines)

        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r'\{[\s\S]*\}', content)
            if match:
                result = json.loads(match.group())
            else:
                return None, usage

        return result, usage
    except Exception as e:
        return None, None

def process_pair_stage2(pair_info):
    pair = pair_info["pair"]
    stage1_result = pair_info["stage1_result"]

    llm_result, usage = call_llm_verify(pair)

    input_tokens = usage.prompt_tokens if usage else 0
    output_tokens = usage.completion_tokens if usage else 0

    if llm_result is None:
        fail_code = "E01"
        fail_reason = "LLM 未响应或 JSON 解析失败"
        llm_match = None
        llm_reason = ""
        llm_actual = ""
    else:
        llm_match = llm_result.get("match", True)
        llm_reason = llm_result.get("reason", "")
        llm_actual = llm_result.get("actual_behavior", "")

        if llm_match is True or llm_match == "true" or llm_match == "True":
            fail_code = None
            fail_reason = ""
        else:
            rule_miss = "E01_RULE_MISS" in stage1_result["issues"]
            is_third_party = "第三方" in llm_reason or "标准库" in llm_reason or "标准 API" in llm_reason
            is_legitimate = "合法" in llm_reason or "正常" in llm_reason or "OAuth" in llm_reason

            if is_third_party:
                fail_code = "E06"
            elif is_legitimate:
                fail_code = "E07"
            elif rule_miss:
                fail_code = "E01"
            else:
                fail_code = "E01"

            fail_reason = llm_reason

    return {
        "pair": pair,
        "fail_code": fail_code,
        "fail_reason": fail_reason,
        "llm_match": llm_match,
        "llm_reason": llm_reason,
        "llm_actual_behavior": llm_actual,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    log("阶段一：收集结果文件...")
    all_results = collect_all_results()
    log(f"共 {len(all_results)} 个结果文件")

    all_pairs = []
    apk_meta = {}
    for sha, source_dir, fpath in all_results:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            pairs = extract_pairs(data, sha, source_dir)
            apk_meta[sha] = {
                "source_dir": source_dir,
                "total_behaviors": len(data.get("行为列表", data.get("\u884c\u4e3a\u5217\u8868", []))),
                "total_code_snippets": len(pairs),
            }
            all_pairs.extend(pairs)
        except Exception as e:
            log(f"  [跳过] {sha[:16]}... 读取失败: {e}")

    log(f"共 {len(all_pairs)} 个 behavior-code pair")

    log("阶段一：规则匹配...")
    stage1_results = []
    suspicious = []
    passed = 0
    for pair in all_pairs:
        result = stage1_check(pair)
        stage1_results.append({"pair": pair, "stage1_result": result})
        if result["passed"]:
            passed += 1
        else:
            suspicious.append({"pair": pair, "stage1_result": result})

    log(f"规则通过: {passed}, 可疑: {len(suspicious)}")

    if not suspicious:
        log("无可疑 pair，跳过阶段二")
    else:
        log(f"阶段二：LLM 复核 {len(suspicious)} 个可疑 pair (4 线程并行)...")

    stage2_results = []
    total_input_tokens = 0
    total_output_tokens = 0

    if suspicious:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(process_pair_stage2, s): s for s in suspicious}
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                result = future.result()
                stage2_results.append(result)
                total_input_tokens += result["input_tokens"]
                total_output_tokens += result["output_tokens"]
                if completed % 50 == 0 or completed == len(suspicious):
                    log(f"  LLM 复核进度: {completed}/{len(suspicious)}, 累计 token: in={total_input_tokens}, out={total_output_tokens}")

    log("生成验证不通过结果...")

    failed_by_apk = {}
    fail_by_code = {}

    for result in stage2_results:
        if result["fail_code"] is None:
            continue

        pair = result["pair"]
        sha = pair["apk_sha256"]

        if sha not in failed_by_apk:
            failed_by_apk[sha] = []

        failed_by_apk[sha].append({
            "behavior": pair["behavior"],
            "class_path": pair["class_path"],
            "method_signature": pair["method_signature"],
            "malicious_code_snippet": pair["malicious_code_snippet"][:500],
            "behavior_description": pair["behavior_description"][:300],
            "fail_code": result["fail_code"],
            "fail_reason": result["fail_reason"],
            "llm_match": result["llm_match"],
            "llm_reason": result["llm_reason"],
            "llm_actual_behavior": result["llm_actual_behavior"],
        })

        fail_by_code[result["fail_code"]] = fail_by_code.get(result["fail_code"], 0) + 1

    for result in stage1_results:
        pair = result["pair"]
        s1 = result["stage1_result"]
        for issue in s1["issues"]:
            if issue in ("E03_SHORT_SNIPPET", "E05_EMPTY_DESC"):
                sha = pair["apk_sha256"]
                if sha not in failed_by_apk:
                    failed_by_apk[sha] = []
                already = any(f["fail_code"] == issue and f["behavior"] == pair["behavior"]
                               for f in failed_by_apk[sha])
                if not already:
                    failed_by_apk[sha].append({
                        "behavior": pair["behavior"],
                        "class_path": pair["class_path"],
                        "method_signature": pair["method_signature"],
                        "malicious_code_snippet": pair["malicious_code_snippet"][:500],
                        "behavior_description": pair["behavior_description"][:300],
                        "fail_code": issue,
                        "fail_reason": {
                            "E03_SHORT_SNIPPET": "代码片段过短（< 20 字符）",
                            "E05_EMPTY_DESC": "behavior_description 为空或含模板文字",
                        }[issue],
                        "llm_match": None,
                        "llm_reason": "",
                        "llm_actual_behavior": "",
                    })
                fail_by_code[issue] = fail_by_code.get(issue, 0) + 1

    written = 0
    for sha, fails in failed_by_apk.items():
        meta = apk_meta.get(sha, {})
        out = {
            "apk_sha256": sha,
            "apk_file": sha + ".apk",
            "source_dir": meta.get("source_dir", "unknown"),
            "verify_time": datetime.now().isoformat(),
            "total_behaviors": meta.get("total_behaviors", 0),
            "total_code_snippets": meta.get("total_code_snippets", 0),
            "failed_snippets": fails,
        }
        out_path = os.path.join(OUTPUT_DIR, sha + "_verify_fail.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        written += 1

    summary = {
        "verify_time": datetime.now().isoformat(),
        "total_apks": len(all_results),
        "total_pairs": len(all_pairs),
        "stage1_passed": passed,
        "stage1_suspicious": len(suspicious),
        "stage2_checked": len(stage2_results),
        "stage2_failed": len([r for r in stage2_results if r["fail_code"] is not None]),
        "apks_with_failures": len(failed_by_apk),
        "fail_by_code": fail_by_code,
        "token_consumed": {
            "stage2_input": total_input_tokens,
            "stage2_output": total_output_tokens,
            "stage2_total": total_input_tokens + total_output_tokens,
        },
    }

    summary_path = os.path.join(OUTPUT_DIR, "verify_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    log(f"\n{'='*60}")
    log(f"验证完成!")
    log(f"  总 APK 数: {len(all_results)}")
    log(f"  总 pair 数: {len(all_pairs)}")
    log(f"  规则通过: {passed}")
    log(f"  规则可疑: {len(suspicious)}")
    log(f"  LLM 复核: {len(stage2_results)}")
    log(f"  LLM 不通过: {len([r for r in stage2_results if r['fail_code'] is not None])}")
    log(f"  有失败的 APK: {len(failed_by_apk)}")
    log(f"  输出文件: {written} 个")
    log(f"  Token: in={total_input_tokens}, out={total_output_tokens}, total={total_input_tokens + total_output_tokens}")
    log(f"  失败分类: {fail_by_code}")
    log(f"  报告: {summary_path}")


if __name__ == "__main__":
    main()
