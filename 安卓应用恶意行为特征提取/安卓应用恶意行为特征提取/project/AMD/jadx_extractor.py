"""
jadx_extractor.py - HTTP-based wrapper for jadx-gui plugin API.
Communication: requests GET/POST to http://127.0.0.1:8650 (jadx-gui plugin port).
FALLBACK: every function catches all exceptions and returns safe defaults.
"""
import time
import os
import sys

try:
    import requests as _req
except ImportError:
    _req = None


# ── Configured from config.py at runtime ───────────────────────────────────────
try:
    from config import JADX_GUI_PLUGIN_PORT as _plugin_port
    JADX_PLUGIN_BASE = f"http://127.0.0.1:{_plugin_port}"
except ImportError:
    JADX_PLUGIN_BASE = "http://127.0.0.1:8650"


def _set_base_url(port: int):
    global JADX_PLUGIN_BASE
    JADX_PLUGIN_BASE = f"http://127.0.0.1:{port}"


_client_available = False


def _is_available() -> bool:
    """Check if jadx plugin HTTP endpoint is reachable."""
    global _client_available
    if _client_available:
        return True
    if _req is None:
        return False
    try:
        r = _req.get(f"{JADX_PLUGIN_BASE}/health", timeout=2)
        if r.status_code == 200:
            _client_available = True
            return True
    except Exception:
        pass
    return False


def _call(endpoint: str, params: dict = None, timeout: float = 60) -> dict:
    """Call a jadx plugin endpoint via HTTP GET."""
    if not _is_available() or _req is None:
        return {}
    try:
        url = f"{JADX_PLUGIN_BASE}/{endpoint.lstrip('/')}"
        r = _req.get(url, params=params or {}, timeout=timeout)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return {"_raw": r.text}
    except Exception:
        pass
    return {}


def _call_post(endpoint: str, params: dict = None, timeout: float = 30) -> dict:
    """Call a jadx plugin endpoint via HTTP POST."""
    if not _is_available() or _req is None:
        return {}
    try:
        url = f"{JADX_PLUGIN_BASE}/{endpoint.lstrip('/')}"
        r = _req.post(url, params=params or {}, timeout=timeout)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return {"_raw": r.text}
    except Exception:
        pass
    return {}


# ── Health check / readiness ──────────────────────────────────────────────────

def poll_jadx_ready(timeout: int = 180, interval: int = 3) -> bool:
    """Poll jadx plugin HTTP endpoint until service is ready."""
    if _req is None:
        return False
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = _req.get(f"{JADX_PLUGIN_BASE}/health", timeout=2)
            if r.status_code == 200:
                _client_available = True
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def get_cache_stats() -> dict:
    """Get decompilation cache statistics."""
    return _call("cache-stats")


def clear_cache():
    """Clear jadx decompilation cache."""
    _call_post("clear-cache")


# ── Manifest ──────────────────────────────────────────────────────────────────

def get_android_manifest() -> str:
    """Get full AndroidManifest.xml content."""
    r = _call("manifest")
    if not r:
        raise RuntimeError("jadx plugin not available or returned empty manifest")
    content = r.get("content", r.get("xml", r.get("_raw", "")))
    if not content:
        raise RuntimeError("jadx manifest content empty")
    return content


def get_main_activity() -> str:
    """Get main activity class name from manifest."""
    r = _call("main-activity")
    if isinstance(r, str):
        return r
    if isinstance(r, dict):
        return r.get("activity", r.get("main_activity", r.get("class_name", "")))
    return ""


def get_manifest_component(component_type: str, only_exported: bool = False) -> list:
    """Get manifest component (activity/service/receiver/provider)."""
    r = _call("manifest-component", {"component_type": component_type, "only_exported": only_exported})
    if isinstance(r, dict) and r.get("components"):
        return r["components"]
    if isinstance(r, list):
        return r
    return []


# ── Classes & Methods ─────────────────────────────────────────────────────────

def get_all_classes(offset: int = 0, count: int = 0) -> list:
    """Get all class names in the APK."""
    r = _call("all-classes", {"offset": offset, "count": count})
    if isinstance(r, dict):
        for key in ("classes", "class_names", "result"):
            if isinstance(r.get(key), list):
                return r[key]
    if isinstance(r, list):
        return r
    raw = r.get("_raw", "") if isinstance(r, dict) else ""
    if raw:
        lines = [l.strip() for l in raw.split("\n") if l.strip()]
        return [l for l in lines if not l.startswith("{")]
    return []


def get_package_tree() -> list:
    """Get package tree with class counts."""
    r = _call("package-tree")
    if isinstance(r, dict) and r.get("packages"):
        return r["packages"]
    if isinstance(r, list):
        return r
    return []


def get_class_source(class_name: str) -> str:
    """Get Java source code for a specific class."""
    r = _call("class-source", {"class_name": class_name})
    if not r:
        return ""
    return r.get("source", r.get("_raw", r.get("response", "")))


def get_methods_of_class(class_name: str) -> list:
    """Get all method names in a class."""
    r = _call("methods-of-class", {"class_name": class_name})
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        for key in ("methods", "method_names"):
            if isinstance(r.get(key), list):
                return r[key]
    return []


def get_fields_of_class(class_name: str) -> list:
    """Get all field names in a class."""
    r = _call("fields-of-class", {"class_name": class_name})
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        for key in ("fields", "field_names"):
            if isinstance(r.get(key), list):
                return r[key]
    return []


def get_method_by_name(class_name: str, method_name: str, method_signature: str = None) -> str:
    """Get source code of a specific method."""
    params = {"class_name": class_name, "method_name": method_name}
    if method_signature:
        params["method_signature"] = method_signature
    r = _call("method-by-name", params)
    if not r:
        return ""
    code = r.get("code", r.get("source", ""))
    if code:
        decl = r.get("decl", "")
        return f"{decl}\n{code}" if decl else code
    return r.get("_raw", "")


# ── Search ────────────────────────────────────────────────────────────────────

def search_classes_by_keyword(search_term: str, package: str = "", search_in: str = "code",
                               offset: int = 0, count: int = 50) -> list:
    """Search classes by keyword across the APK."""
    r = _call("search-classes-by-keyword", {
        "search_term": search_term,
        "package": package,
        "search_in": search_in,
        "offset": offset,
        "count": count,
    }, timeout=300)
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        for key in ("matches", "results", "classes"):
            if isinstance(r.get(key), list):
                return r[key]
    return []


def search_method_by_name(method_name: str) -> list:
    """Search for a method name across all classes."""
    r = _call("search-method-by-name", {"method_name": method_name})
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        for key in ("methods", "results", "matches"):
            if isinstance(r.get(key), list):
                return r[key]
    return []


def get_xrefs_to_class(class_name: str, offset: int = 0, count: int = 50) -> list:
    """Find all references to a class."""
    r = _call("xrefs-to-class", {"class_name": class_name, "offset": offset, "count": count})
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        return r.get("references", r.get("xrefs", []))
    return []


def get_xrefs_to_method(class_name: str, method_name: str, offset: int = 0, count: int = 50) -> list:
    """Find all references to a method."""
    r = _call("xrefs-to-method", {
        "class_name": class_name, "method_name": method_name,
        "offset": offset, "count": count,
    })
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        return r.get("references", r.get("xrefs", []))
    return []


def get_xrefs_to_field(class_name: str, field_name: str, offset: int = 0, count: int = 50) -> list:
    """Find all references to a field."""
    r = _call("xrefs-to-field", {
        "class_name": class_name, "field_name": field_name,
        "offset": offset, "count": count,
    })
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        return r.get("references", r.get("xrefs", []))
    return []


# ── Strings & Resources ───────────────────────────────────────────────────────

def get_strings(offset: int = 0, count: int = 0) -> list:
    """Get strings from strings.xml resources."""
    r = _call("strings", {"offset": offset, "count": count})
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        return r.get("strings", r.get("values", []))
    raw = r.get("_raw", "") if isinstance(r, dict) else ""
    if raw:
        return [l.strip() for l in raw.split("\n") if l.strip()]
    return []


def get_resource_file(resource_name: str) -> str:
    """Get resource file content."""
    r = _call("resource-file", {"resource_name": resource_name})
    return r.get("content", r.get("_raw", r.get("response", "")))


def get_all_resource_file_names(offset: int = 0, count: int = 0) -> list:
    """Get all resource file names."""
    r = _call("all-resource-file-names", {"offset": offset, "count": count})
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        return r.get("files", r.get("resources", []))
    raw = r.get("_raw", "") if isinstance(r, dict) else ""
    if raw:
        return [l.strip() for l in raw.split("\n") if l.strip()]
    return []


def get_main_application_classes_names() -> list:
    """Get main application classes from Manifest package."""
    r = _call("main-application-classes-names")
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        return r.get("classes", r.get("class_names", []))
    raw = r.get("_raw", "") if isinstance(r, dict) else ""
    if raw:
        return [l.strip() for l in raw.split("\n") if l.strip()]
    return []


def get_main_application_classes_code(offset: int = 0, count: int = 0) -> list:
    """Get main application classes' source code."""
    r = _call("main-application-classes-code", {"offset": offset, "count": count})
    if isinstance(r, list):
        return r
    if isinstance(r, dict):
        return r.get("classes", r.get("code", []))
    return []


# ── Smali ──────────────────────────────────────────────────────────────────────

def get_smali_of_class(class_name: str) -> str:
    """Get smali representation of a class."""
    r = _call("smali-of-class", {"class_name": class_name})
    return r.get("smali", r.get("_raw", r.get("response", "")))


# ── High-level helpers ────────────────────────────────────────────────────────

def extract_all_classes_paginated(batch_size: int = 200) -> list:
    """Paginate through all classes in the APK. Returns full list."""
    all_classes = []
    offset = 0
    while True:
        batch = get_all_classes(offset=offset, count=batch_size)
        if not batch:
            break
        all_classes.extend(batch)
        if len(batch) < batch_size:
            break
        offset += batch_size
    return all_classes


def _get_caller_apk_path():
    """Get _apk_path from the calling module's globals via sys._getframe()."""
    try:
        frame = sys._getframe(1)
        while frame is not None:
            apk = frame.f_globals.get("_apk_path")
            if apk:
                return apk
            frame = frame.f_back
        return None
    except Exception:
        return None


def search_code_for_pattern(patterns: list, max_results_per_pattern: int = 50, apk_path: str = None) -> dict:
    """
    Search code for multiple patterns. Returns {pattern: [match_results]}.
    PRIMARY: jadx plugin HTTP search.
    FALLBACK: if jadx unavailable, search DEX strings via androguard when apk_path available.
    """
    results = {}
    # Try jadx first
    for pat in patterns:
        try:
            matches = search_classes_by_keyword(
                search_term=pat,
                search_in="code",
                count=max_results_per_pattern,
            )
            results[pat] = matches if matches else []
        except Exception:
            results[pat] = []

    # Determine apk_path: explicit arg > caller module's _apk_path
    effective_apk = apk_path or _get_caller_apk_path()

    # If jadx returned all-empty and we have apk_path, use androguard fallback
    if all(not v for v in results.values()) and effective_apk:
        results = _search_code_fallback(patterns, effective_apk)

    return results


def _search_code_fallback(patterns: list, apk_path: str) -> dict:
    """
    FALLBACK: search APK DEX strings when jadx plugin is unavailable.
    Searches androguard-extracted DEX strings for each pattern.
    Returns {pattern: [{"string": ..., "source": "DEX"}, ...]}.
    """
    results = {p: [] for p in patterns}
    try:
        import importlib
        ag_mod = importlib.import_module("androguard_extractor")
        strings = ag_mod.get_strings(apk_path, limit=0)
        for s in strings:
            s_str = str(s)
            for p in patterns:
                if p in s_str and p not in " ".join(r["string"][:30] for r in results[p]):
                    results[p].append({"string": s_str[:120], "source": "DEX_fallback"})
    except Exception:
        pass
    return results
