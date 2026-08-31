"""
llm_synthesis.py - LLM synthesis orchestration for sub04 dynamic fields.
Calls the LLM gateway directly (OpenAI-compatible API) with the sub04 field
spec embedded as the system prompt, parses the LLM JSON response, and merges
with Python-computed skeleton.

Gateway config is read from the opencode.json in the workspace root
(D:/SCA_APK/.opencode/opencode.json) — provider "gateway", models glm-5.2 /
glm-5.3 / qwen3.7-plus. Env vars override: LLM_GATEWAY_BASE_URL,
LLM_GATEWAY_API_KEY, LLM_SYNTHESIS_MODEL.

Output: writes data_classification.json, risk_dimension_scores.json,
attack_profile.json to the tmp_dir, consolidated by run_pipeline.py into
a single master JSON.
"""
import os
import sys
import json
import re
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import LLM_SYNTHESIS_TIMEOUT
from common import save_json, load_json

# ── Gateway configuration ─────────────────────────────────────────────────────

_OPENCODE_CONFIG_CANDIDATES = [
    r"D:\SCA_APK\.opencode\opencode.json",
    os.path.join(os.path.expanduser("~"), ".config", "opencode", "opencode.json"),
]


def _load_gateway_config():
    """Resolve gateway baseURL/apiKey/model from opencode.json, env overrides win."""
    base_url = os.environ.get("LLM_GATEWAY_BASE_URL", "")
    api_key = os.environ.get("LLM_GATEWAY_API_KEY", "")
    model = os.environ.get("LLM_SYNTHESIS_MODEL", "")

    if not (base_url and api_key):
        for cfg_path in _OPENCODE_CONFIG_CANDIDATES:
            try:
                if not os.path.isfile(cfg_path):
                    continue
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                provider = cfg.get("provider", {}).get("gateway", {})
                opts = provider.get("options", {})
                if not base_url and opts.get("baseURL"):
                    base_url = opts["baseURL"]
                if not api_key and opts.get("apiKey"):
                    api_key = opts["apiKey"]
                models = provider.get("models", {})
                if not model and models:
                    # Prefer glm-5.3, then glm-5.2, then first available
                    for pref in ("glm-5.3", "glm-5.2"):
                        if pref in models:
                            model = pref
                            break
                    if not model:
                        model = next(iter(models))
                if base_url and api_key:
                    break
            except Exception:
                continue

    return base_url, api_key, model


# ── sub04 field spec system prompt (rebuilt from 规格md/sub04) ────────────────

SUB04_SYSTEM_PROMPT = """你是安卓恶意软件分析流水线中的 sub04 合成专家。你的任务基于上游 sub01-03 的静态提取结果（sub01_03_context）与 Python 预计算的骨架（python_skeleton），合成最终特征 JSON 中的 3 个顶级字段：data_classification、risk_dimension_scores、attack_profile。

在响应正文中返回单个 JSON 对象（包含这 3 个键），不要输出 markdown 代码块以外的多余文字，不要写文件。

## 全局铁律
1. 严禁 null：字符串 ""、数字 0、布尔 false、数组 []、对象 {}。
2. 判断必须基于 sub01_03_context 中的实际证据，不得凭空捏造。
3. attack_profile.c2_flow.destinations_summary 已由 Python 计算（在 python_skeleton.c2_flow_destinations_summary 中），请原样保留该子对象。

## 字段规格

### 1. data_classification（数组，每项对象）
对应用行为涉及的敏感数据/恶意行为逐条分类。malicious_behavior 中为 true 的行为字段必须生成对应条目（参考映射：data_exfiltration→数据外传/CRITICAL、sms_delete_capability→短信删除/HIGH、call_forwarding→呼叫转移劫持/HIGH、has_c2_communication→C2通信/CRITICAL、dynamic_code_loading→动态DEX加载隐藏载荷/HIGH、encryption_hardcoded_key→硬编码加密/HIGH），再加上短信窃取、设备信息采集、加密混淆、持久化驻留、反检测对抗、钓鱼攻击等命中的行为。每项字段：
- category（string）：主分类，如 数据外传/隐私窃取/短信拦截/广告欺诈
- subcategory（string）：子分类
- is_confirmed（boolean）：是否有确凿证据
- evidence（string）：证据描述（引用代码位置、行为等）
- risk_level（string）：RED/ORANGE/YELLOW/GREEN

### 2. risk_dimension_scores（对象，6 维度 + total）
每个维度：{"score": 0-10, "out_of": 10, "risk_level": RED/ORANGE/YELLOW/GREEN, "evidence": 字符串或数组}。维度与评分依据：
- data_exfiltration：对外发送数据的通信点、URL、上传行为、mb.data_exfiltration
- c2_remote_control：C2 地址、mb.has_c2_communication、远控指令、mb.dynamic_code_loading
- data_steal：敏感隐私读取、mb.sms_delete_capability、mb.call_forwarding、mb.data_exfiltration
- encryption_obfuscation：加解密、混淆方案、mb.encryption_hardcoded_key
- persistence：开机自启、服务自启、保活
- anti_detection：防杀、检测规避、壳、Root 隐藏
- total：{"score": 0-10（6 维度综合）, "risk_level": RED/ORANGE/YELLOW/GREEN}（无 description 字段）

### 3. attack_profile（对象，除 destinations_summary 外全部由你合成）
- developer_subject（string）：开发者/签名证书主体（从 certificate_analysis 引用）
- app_function_summary（string）：应用功能总结
- distribution_form（string）：分发途径/形态
- core_framework（string）：核心框架（Android SDK/插件化框架/React Native 等）
- development_language（string）：开发语言
- obfuscation_solution（string）：混淆/加固方案
- network_stack（string）：网络协议栈（OkHttp/HttpURLConnection/Socket 等）
- encryption_library（string）：加密库
- c2_flow（object）：{"decryption_step": string, "destinations_summary": 保留 Python 预计算值}
- overall_judgment（object）：{"risk_label": 恶意/风险/正常, "risk_score": number, "summary": string 总体结论}
- malware_family_indicators（数组）：[{"indicator": string, "detail": string}]
- attack_chains（数组）：[{"chain_id": string, "name": string, "steps": [{"step_order": number(1起), "behavior": string, "target": string}], "description": string}]
- behavior_tags（数组）：[{"tag": string, "category": string 网络行为/文件行为/隐私行为/进程行为等, "confidence": integer 0-100, "evidence": string}]

## 输出格式
{"data_classification": [...], "risk_dimension_scores": {...}, "attack_profile": {...}}"""


def _build_context_bundle(tmp_dir, apk_path, apk_sha256, malware_family,
                          known_behaviors=None):
    """Build the context bundle for the LLM subagent.
    Loads all sub01-03 JSON outputs + Phase A Python skeleton.
    """
    sub01_03_fields = [
        "file_basic", "certificate_analysis", "permissions", "components",
        "code_analysis", "malicious_behavior", "native_analysis",
        "c2_communication", "iocs",
    ]
    context = {}
    for field_name in sub01_03_fields:
        json_path = os.path.join(tmp_dir, field_name + ".json")
        context[field_name] = load_json(json_path)

    # Load Phase A skeleton (advertisement_analysis already computed by Python)
    skeleton = {}
    adv_path = os.path.join(tmp_dir, "advertisement_analysis.json")
    if os.path.exists(adv_path):
        skeleton["advertisement_analysis"] = load_json(adv_path)

    # Build risk_score_inputs: summarize behavior flags + counts for LLM
    mb = context.get("malicious_behavior", {})
    c2 = context.get("c2_communication", {})
    perms = context.get("permissions", {})
    code = context.get("code_analysis", {})

    behavior_flags = {}
    for k, v in mb.items():
        if isinstance(v, bool):
            behavior_flags[k] = v

    skeleton["risk_score_inputs"] = {
        "behavior_flags": behavior_flags,
        "c2_server_count": len(c2.get("c2_servers", [])),
        "c2_has_c2": c2.get("has_c2", False),
        "dangerous_perm_count": perms.get("dangerous_perm_count", 0),
        "total_perm_count": perms.get("total_perm_count", 0),
        "is_code_obfuscated": code.get("is_code_obfuscated", False),
        "anti_analysis": code.get("anti_analysis", []),
        "is_packed": code.get("is_packed_and_repackaged", False),
        "encrypted_c2_count": len(c2.get("encrypted_c2_indicators", [])),
        "native_lib_count": context.get("native_analysis", {}).get("native_library_count", 0),
    }

    # c2_flow.destinations_summary (already computed by Python in attack_profile skeleton)
    ap_path = os.path.join(tmp_dir, "attack_profile_skeleton.json")
    if os.path.exists(ap_path):
        ap_skel = load_json(ap_path)
        if "c2_flow" in ap_skel:
            skeleton["c2_flow_destinations_summary"] = ap_skel["c2_flow"].get(
                "destinations_summary", {})

    bundle = {
        "task": "sub04_synthesis",
        "apk_path": apk_path,
        "apk_sha256": apk_sha256,
        "malware_family": malware_family or "",
        "known_behaviors": known_behaviors or [],
        "sub01_03_context": context,
        "python_skeleton": skeleton,
        "output_instructions": {
            "required_fields": [
                "data_classification",
                "risk_dimension_scores",
                "attack_profile"
            ],
            "output_format": "Return a single JSON object in the response text. Do NOT write files.",
            "rules": [
                "No null values — use defaults (\"\" / 0 / false / [] / {})",
                "attack_profile.c2_flow.destinations_summary is pre-computed by Python; preserve it",
                "Base scores and judgments on actual evidence in sub01_03_context"
            ]
        }
    }
    return bundle


def _extract_json_from_response(text):
    """Extract JSON object from LLM response text.
    Tries multiple strategies:
    1. Direct JSON parse of entire text
    2. Markdown code fence extraction (```json ... ``` or ``` ... ```)
    3. First { to last } substring
    """
    if not text:
        return None

    # Strategy 1: direct parse
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Strategy 2: markdown code fence
    fence_patterns = [
        re.compile(r'```json\s*\n(.*?)\n\s*```', re.DOTALL),
        re.compile(r'```\s*\n(.*?)\n\s*```', re.DOTALL),
        re.compile(r'```json(.*?)```', re.DOTALL),
        re.compile(r'```(.*?)```', re.DOTALL),
    ]
    for pat in fence_patterns:
        m = pat.search(text)
        if m:
            try:
                return json.loads(m.group(1).strip())
            except (json.JSONDecodeError, ValueError):
                continue

    # Strategy 3: first { to last }
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        try:
            return json.loads(text[first:last + 1])
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def _merge_llm_output(tmp_dir, llm_json, skeleton):
    """Merge LLM output with Python skeleton and save 3 field JSONs.
    The LLM returns data_classification, risk_dimension_scores, attack_profile.
    Python skeleton provides advertisement_analysis (already saved) and
    c2_flow.destinations_summary (merged into attack_profile).
    """
    # data_classification
    dc = llm_json.get("data_classification", [])
    if not isinstance(dc, list):
        dc = []
    save_json(dc, os.path.join(tmp_dir, "data_classification.json"))

    # risk_dimension_scores
    rds = llm_json.get("risk_dimension_scores", {})
    if not isinstance(rds, dict):
        rds = {}
    # Normalize `total` to the spec shape {score, risk_level} — LLMs
    # occasionally hallucinate extra keys (e.g. out_of, description).
    # Spec (sub04 §3.2 变更说明): total.description 已删除；total 无 out_of。
    if isinstance(rds.get("total"), dict):
        rds["total"] = {
            "score": rds["total"].get("score", 0),
            "risk_level": rds["total"].get("risk_level", ""),
        }
    save_json(rds, os.path.join(tmp_dir, "risk_dimension_scores.json"))

    # attack_profile — merge destinations_summary from skeleton
    ap = llm_json.get("attack_profile", {})
    if not isinstance(ap, dict):
        ap = {}

    # Preserve Python-computed destinations_summary if LLM didn't include it
    dest_sum = skeleton.get("c2_flow_destinations_summary")
    if dest_sum:
        if "c2_flow" not in ap:
            ap["c2_flow"] = {}
        if not ap["c2_flow"].get("destinations_summary"):
            ap["c2_flow"]["destinations_summary"] = dest_sum
        else:
            # Merge: prefer LLM values but fill missing from skeleton
            for k, v in dest_sum.items():
                if k not in ap["c2_flow"]["destinations_summary"]:
                    ap["c2_flow"]["destinations_summary"][k] = v

    save_json(ap, os.path.join(tmp_dir, "attack_profile.json"))


def _call_llm_gateway(user_prompt, timeout):
    """Call the LLM gateway via OpenAI-compatible API.
    Returns (response_text, None) on success or (None, error_message).
    """
    base_url, api_key, model = _load_gateway_config()
    if not (base_url and api_key and model):
        return None, "gateway config unresolved (set LLM_GATEWAY_BASE_URL / LLM_GATEWAY_API_KEY / LLM_SYNTHESIS_MODEL)"

    try:
        from openai import OpenAI
    except ImportError:
        return None, "openai SDK not installed (pip install openai)"

    try:
        client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout, max_retries=1)
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SUB04_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
        text = resp.choices[0].message.content or ""
        return text, None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def run_sub04_llm_synthesis(tmp_dir, apk_path, apk_sha256, malware_family,
                            known_behaviors=None):
    """Main entry: orchestrate LLM synthesis for sub04 dynamic fields.
    Returns True on success, False on failure (Python skeleton used as fallback).
    """
    print("  [*] [LLM] Building context bundle for sub04 synthesis...")
    context = _build_context_bundle(
        tmp_dir, apk_path, apk_sha256, malware_family, known_behaviors
    )
    request_path = os.path.join(tmp_dir, "sub04_llm_request.json")
    save_json(context, request_path)
    print(f"  [+] [LLM] Context bundle saved: {request_path}")

    base_url, api_key, _ = _load_gateway_config()
    if not (base_url and api_key):
        print(f"  [!] [LLM] Gateway config not found (checked: {_OPENCODE_CONFIG_CANDIDATES})")
        return False

    # Embed the context bundle directly in the user prompt
    # (replaces the old opencode-agent "read the file" step)
    bundle_text = json.dumps(context, ensure_ascii=False, indent=1)
    user_prompt = (
        "以下是本次 APK 分析的完整上下文包（JSON）：\n\n"
        f"{bundle_text}\n\n"
        "请按系统提示词中的字段规格，合成 data_classification、"
        "risk_dimension_scores、attack_profile 三个字段，"
        "在正文中返回单个 JSON 对象（包含这 3 个键）。"
        "严格遵守无 null 规则；attack_profile.c2_flow.destinations_summary "
        "已由 Python 计算（见 python_skeleton.c2_flow_destinations_summary），"
        "请保留该子对象。"
    )

    print(f"  [*] [LLM] Calling gateway directly (timeout={LLM_SYNTHESIS_TIMEOUT}s)...")
    start = time.time()
    text, err = _call_llm_gateway(user_prompt, timeout=LLM_SYNTHESIS_TIMEOUT)
    elapsed = round(time.time() - start, 1)

    if text is None:
        print(f"  [!] [LLM] gateway call failed ({elapsed}s): {err}")
        return False

    print(f"  [+] [LLM] gateway call completed ({elapsed}s, {len(text)} chars)")

    # Extract JSON from response
    llm_json = _extract_json_from_response(text)
    if llm_json is None:
        print("  [!] [LLM] Failed to extract JSON from LLM response")
        # Save raw response for debugging
        raw_path = os.path.join(tmp_dir, "sub04_llm_raw_response.txt")
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"      Raw response saved to: {raw_path}")
        return False

    # Merge with skeleton and save
    skeleton = context.get("python_skeleton", {})
    _merge_llm_output(tmp_dir, llm_json, skeleton)
    print("  [+] [LLM] sub04 dynamic fields synthesized and saved:")
    print("      - data_classification.json")
    print("      - risk_dimension_scores.json")
    print("      - attack_profile.json")
    return True
