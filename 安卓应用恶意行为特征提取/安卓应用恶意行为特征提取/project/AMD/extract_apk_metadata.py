"""
extract_apk_metadata.py - APK metadata: file_basic, certificate_analysis, permissions, components.
Usage: python extract_apk_metadata.py <apk_path> <output_dir>
"""
import os
import sys
import re
import json
import math
import struct
import hashlib
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import androguard_extractor
from config import *
from common import *
from jadx_extractor import (
    get_android_manifest, get_main_activity, get_class_source,
    get_strings, search_code_for_pattern, get_all_classes,
    get_methods_of_class, get_fields_of_class, get_manifest_component,
)


# ── file_basic ─────────────────────────────────────────────────────────────────

def extract_file_basic(apk_path: str, perm_map: dict, malware_family: str = "") -> dict:
    result = dict(FILE_BASIC_DEFAULT)

    # Hashes & size
    hashes = compute_file_hashes(apk_path)
    result["sha256"] = hashes["sha256"]
    result["md5"] = hashes["md5"]
    result["sha1"] = hashes["sha1"]
    result["file_size_bytes"] = os.path.getsize(apk_path)

    # Entropy
    with open(apk_path, "rb") as f:
        apk_bytes = f.read()
    result["file_entropy"] = shannon_entropy_bytes(apk_bytes)

    # Malware family: caller passes resolved string (from Excel lookup or fallback)
    if isinstance(malware_family, str) and malware_family:
        result["malware_family"] = malware_family

    # Package name, app_label, version, SDK via jadx MCP first, then androguard fallback
    try:
        manifest = get_android_manifest()
        _parse_manifest_jadx(result, manifest, perm_map)
    except Exception as e:
        print(f"  [!] jadx manifest failed: {e}, falling back to androguard")

    # Always run androguard fallback to fill in missing or unresolved fields
    _parse_manifest_androguard(apk_path, result)

    # Package name entropy
    if result["package_name"]:
        result["package_name_entropy"] = shannon_entropy_string(result["package_name"])

    return result


def _resolve_string_resource(strings_result, key: str) -> str:
    """Resolve @string/XXX to actual value from JADX strings.xml output."""
    if isinstance(strings_result, dict):
        items = strings_result.get("strings", strings_result.get("values", []))
    elif isinstance(strings_result, list):
        items = strings_result
    else:
        return ""
    for s in items:
        if isinstance(s, dict) and s.get("name") == key and s.get("value"):
            return s["value"]
    return ""


def _parse_manifest_jadx(result: dict, manifest_text: str, perm_map: dict):
    """Parse manifest text from jadx MCP to extract file_basic fields."""
    import re

    # Package name
    m = re.search(r'package="([^"]+)"', manifest_text)
    if m:
        result["package_name"] = m.group(1)

    # Version code
    m = re.search(r'android:versionCode="([^"]+)"', manifest_text)
    if m:
        try:
            result["version_code"] = int(m.group(1))
        except ValueError:
            result["version_code"] = 0

    # Version name
    m = re.search(r'android:versionName="([^"]+)"', manifest_text)
    if m:
        result["version_name"] = m.group(1)

    # minSdkVersion / targetSdkVersion
    m = re.search(r'android:minSdkVersion="([^"]+)"', manifest_text)
    if m:
        try:
            result["min_sdk_version"] = int(m.group(1))
        except ValueError:
            result["min_sdk_version"] = 0

    m = re.search(r'android:targetSdkVersion="([^"]+)"', manifest_text)
    if m:
        try:
            result["target_sdk_version"] = int(m.group(1))
        except ValueError:
            result["target_sdk_version"] = 0

    # App label - try direct value first
    m = re.search(r'<application[^>]*android:label="([^"]+)"', manifest_text, re.DOTALL)
    if m:
        label_raw = m.group(1)
        if label_raw.startswith("@string/"):
            string_key = label_raw[len("@string/"):]
            try:
                strings = get_strings()
                resolved = _resolve_string_resource(strings, string_key)
                result["app_label"] = resolved if resolved else label_raw
            except Exception:
                result["app_label"] = label_raw
        else:
            result["app_label"] = label_raw
    else:
        # Fallback: get first meaningful string from strings.xml
        try:
            strings = get_strings()
            for s in strings:
                if isinstance(s, dict) and s.get("value"):
                    val = s["value"]
                    if len(val) > 2 and not val.startswith("//"):
                        result["app_label"] = val
                        break
        except Exception:
            pass


def _parse_manifest_androguard(apk_path: str, result: dict):
    """Fallback: fill in missing manifest fields via androguard.
    Only overwrites fields that are currently empty or unresolved (e.g. @string/XXX).
    """
    try:
        info = androguard_extractor.analyze_apk(apk_path)
        if info and isinstance(info, dict):
            pn = info.get("package_name", info.get("package", ""))
            if pn and (not result["package_name"] or result["package_name"] == ""):
                result["package_name"] = pn
            vc = info.get("version_code", 0)
            if vc and not result["version_code"]:
                result["version_code"] = vc
            vn = info.get("version_name", "")
            if vn and not result["version_name"]:
                result["version_name"] = vn
            ms = info.get("min_sdk_version", info.get("min_sdk", 0))
            if ms and not result["min_sdk_version"]:
                result["min_sdk_version"] = ms
            ts = info.get("target_sdk_version", info.get("target_sdk", 0))
            if ts and not result["target_sdk_version"]:
                result["target_sdk_version"] = ts
    except Exception:
        pass

    try:
        # Resolve app_label: if still unresolved (@string/...), use androguard
        label_needs_resolution = (result["app_label"] == FILE_BASIC_DEFAULT["app_label"]
                                  or str(result["app_label"]).startswith("@"))
        if label_needs_resolution:
            app_info = androguard_extractor.get_app_info(apk_path)
            if app_info and isinstance(app_info, dict):
                label = app_info.get("app_label", app_info.get("label", ""))
                if label:
                    result["app_label"] = label
    except Exception:
        pass


# ── certificate_analysis ───────────────────────────────────────────────────────

def extract_certificate_analysis(apk_path: str) -> dict:
    result = dict(CERT_ANALYSIS_DEFAULT)

    # Parse certificates from APK using Python's cryptography
    try:
        certs = _parse_apk_signatures(apk_path)
    except Exception:
        certs = []

    if not certs:
        # Fallback to androguard
        try:
            cert_info = androguard_extractor.get_certificates(apk_path)
            if cert_info:
                return _convert_androguard_cert(cert_info)
        except Exception:
            pass
        return result

    # Use the first certificate
    cert = certs[0]
    result["is_self_signed"] = cert.get("is_self_signed", False)
    result["is_debug_certificate"] = cert.get("is_debug_certificate", False)
    result["signing_algorithm"] = cert.get("signing_algorithm", "")
    result["public_key_type"] = cert.get("public_key_type", "")
    result["public_key_bit_length"] = cert.get("public_key_bit_length", 0)
    result["subject"] = cert.get("subject", "")
    result["issuer"] = cert.get("issuer", "")
    result["subject_common_name"] = cert.get("subject_common_name", "")
    result["subject_organization"] = cert.get("subject_organization", "")
    result["subject_country"] = cert.get("subject_country", "")
    result["valid_from"] = cert.get("valid_from", "")
    result["valid_until"] = cert.get("valid_until", "")
    result["valid_days"] = cert.get("valid_days", 0)
    result["public_key_hash"] = cert.get("public_key_hash", "")
    result["fingerprint_sha256"] = cert.get("fingerprint_sha256", "")
    result["fingerprint_sha1"] = cert.get("fingerprint_sha1", "")
    result["subject_anomaly"] = cert.get("subject_anomaly", False)

    # Signer certificates list
    result["signer_certificates"] = []
    for c in certs:
        result["signer_certificates"].append({
            "serial_number": c.get("serial_number", ""),
            "subject_cn": c.get("subject_common_name", ""),
            "issuer_cn": c.get("issuer_common_name", ""),
        })

    return result


def _parse_apk_signatures(apk_path: str) -> list:
    """Parse APK signature block and extract certificate info."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, rsa as rsa_mod
    import zipfile as zf

    certs = []
    with zf.ZipFile(apk_path, "r") as archive:
        # Find signature files in META-INF/
        sig_files = [n for n in archive.namelist() if n.startswith("META-INF/") and
                     (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))]

        for sig_file in sig_files:
            try:
                der_data = archive.read(sig_file)
                cert = x509.load_der_x509_certificate(der_data)
                certs.append(_process_certificate(cert))
            except Exception:
                continue

    # If no traditional sig files, try trying to extract from Android APK signature scheme v2/v3
    if not certs:
        try:
            with open(apk_path, "rb") as f:
                apk_data = f.read()
            # Try to find X.509 certificate structures in the APK
            certs = _extract_certs_from_apk_bytes(apk_data)
        except Exception:
            pass

    return certs


def _process_certificate(cert) -> dict:
    """Process an x509 certificate into our analysis dict."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    result = {}

    # Subject / Issuer
    subject_str = cert.subject.rfc4514_string()
    issuer_str = cert.issuer.rfc4514_string()
    result["subject"] = subject_str
    result["issuer"] = issuer_str
    result["is_self_signed"] = (subject_str == issuer_str)

    # CN, O, C
    result["subject_common_name"] = _get_dn_field(cert.subject, "commonName")
    result["subject_organization"] = _get_dn_field(cert.subject, "organizationName")
    result["subject_country"] = _get_dn_field(cert.subject, "countryName")
    issuer_cn = _get_dn_field(cert.issuer, "commonName")
    result["issuer_common_name"] = issuer_cn

    # Serial number
    result["serial_number"] = format(cert.serial_number, "x")

    # Dates
    result["valid_from"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat()
    result["valid_until"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat()
    delta = cert.not_valid_after - cert.not_valid_before
    result["valid_days"] = delta.days

    # Debug certificate detection
    cn = result["subject_common_name"]
    result["is_debug_certificate"] = bool("androiddebug" in cn.lower()) if cn else False

    # Public key info
    pub_key = cert.public_key()
    pk_bytes = pub_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    result["public_key_hash"] = hashlib.sha256(pk_bytes).hexdigest()

    if isinstance(pub_key, rsa.RSAPublicKey):
        result["public_key_type"] = "RSA"
        result["public_key_bit_length"] = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        result["public_key_type"] = "EC"
        result["public_key_bit_length"] = pub_key.key_size
    else:
        result["public_key_type"] = "Unknown"
        result["public_key_bit_length"] = 0

    # Signing algorithm
    result["signing_algorithm"] = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid.dotted_string)

    # Fingerprints
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    result["fingerprint_sha256"] = hashlib.sha256(cert_der).hexdigest().upper()
    result["fingerprint_sha1"] = hashlib.sha1(cert_der).hexdigest().upper()

    # Subject anomaly detection
    result["subject_anomaly"] = _check_subject_anomaly(result)

    return result


def _get_dn_field(name, field_oid: str) -> str:
    """Get a specific field from X500Name."""
    try:
        from cryptography.x509.oid import NameOID
        oid_map = {
            "commonName": NameOID.COMMON_NAME,
            "organizationName": NameOID.ORGANIZATION_NAME,
            "countryName": NameOID.COUNTRY_NAME,
            "stateOrProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
            "localityName": NameOID.LOCALITY_NAME,
        }
        oid = oid_map.get(field_oid)
        if oid:
            attrs = name.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else ""
    except Exception:
        pass
    return ""


def _check_subject_anomaly(cert_info: dict) -> bool:
    """Check if certificate subject has anomalous values."""
    cn = cert_info.get("subject_common_name", "")
    org = cert_info.get("subject_organization", "")
    if not cn and not org:
        return True
    if cn and len(cn) > 30:
        ent = shannon_entropy_string(cn)
        if ent > 4.0:
            return True
    return False


def _extract_certs_from_apk_bytes(apk_data: bytes) -> list:
    """Try to extract X.509 certs from raw APK bytes for v2/v3 signatures."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    certs = []
    seen_fp = set()
    marker = b'\x30\x82'
    idx = 0
    while idx < len(apk_data) - 2:
        pos = apk_data.find(marker, idx)
        if pos == -1:
            break
        try:
            cert = x509.load_der_x509_certificate(apk_data[pos:pos + 8192])
            fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            if fp not in seen_fp:
                seen_fp.add(fp)
                certs.append(_process_certificate(cert))
        except Exception:
            pass
        idx = pos + 1
        if len(certs) >= 5:
            break
    return certs


def _convert_androguard_cert(cert_info) -> dict:
    """Convert androguard certificate output to our format."""
    result = dict(CERT_ANALYSIS_DEFAULT)
    if isinstance(cert_info, dict):
        for k in ("signing_algorithm", "fingerprint_sha256", "fingerprint_sha1",
                  "subject", "issuer", "is_self_signed"):
            result[k] = cert_info.get(k, result.get(k))
        certs_list = cert_info.get("certificates", [])
        if certs_list and isinstance(certs_list[0], dict):
            c = certs_list[0]
            for k in ("subject_common_name", "subject_organization", "subject_country",
                      "public_key_type", "public_key_bit_length", "valid_from",
                      "valid_until", "valid_days", "public_key_hash", "subject_anomaly",
                      "is_debug_certificate"):
                result[k] = c.get(k, result.get(k))
            result["signer_certificates"] = [{
                "serial_number": c.get("serial_number", ""),
                "subject_cn": c.get("subject_common_name", ""),
                "issuer_cn": c.get("issuer_common_name", c.get("issuer", "")),
            }]
        elif result["subject"] and result["issuer"] and result["subject"] == result["issuer"]:
            result["is_self_signed"] = True
    return result


# ── permissions ────────────────────────────────────────────────────────────────

def extract_permissions(apk_path: str, manifest_text: str, perm_map: dict) -> dict:
    result = dict(PERMISSIONS_DEFAULT)

    # Extract raw permission names
    raw_perms = _extract_permissions_from_manifest(manifest_text)
    if not raw_perms:
        raw_perms = _extract_permissions_androguard(apk_path)

    perms_set = set(p for p in raw_perms if p)
    result["total_perm_count"] = len(perms_set)

    # all_permissions with protection_level
    all_perms = []
    dangerous_count = 0
    for perm in sorted(perms_set):
        level = perm_map.get(perm, "normal")
        is_dangerous = "dangerous" in level.lower() if level else False
        if is_dangerous:
            dangerous_count += 1
        all_perms.append({
            "name": perm,
            "protection_level": level,
            "is_dangerous": is_dangerous,
        })
    result["all_permissions"] = all_perms
    result["dangerous_perm_count"] = dangerous_count

    # Malicious permission combos
    result["malicious_perm_combos"] = _check_malicious_combos(perms_set)

    # High-signal permissions
    result["high_signal_permissions"] = _check_high_signal_permissions(perms_set, perm_map)

    # Custom permissions
    result["custom_permissions"] = _extract_custom_permissions(manifest_text)

    # Uses features
    result["uses_features"] = _extract_uses_features(manifest_text, apk_path)

    return result


def _extract_permissions_from_manifest(manifest_text: str) -> list:
    """Extract permission names from manifest text."""
    import re
    perms = []
    for m in re.finditer(r'<uses-permission[^>]*android:name="([^"]+)"', manifest_text):
        perms.append(m.group(1))
    return perms


def _extract_permissions_androguard(apk_path: str) -> list:
    """Fallback: extract permissions via androguard."""
    import re
    try:
        perms_raw = androguard_extractor.get_permissions(apk_path)
        if perms_raw:
            if isinstance(perms_raw, list):
                return [str(p) for p in perms_raw]
            elif isinstance(perms_raw, dict):
                return list(perms_raw.keys())
    except Exception:
        pass
    return []


def _check_malicious_combos(perms_set: set) -> list:
    """Check which malicious permission combos are triggered."""
    results = []
    for combo in MALICIOUS_PERM_COMBOS:
        required = combo["required_perms"]
        # Match against full permission names (android.permission.XXX)
        triggered = all(
            any(rp in p for p in perms_set)
            for rp in required
        )
        results.append({
            "attack_type": combo["attack_type"],
            "required_perms": required,
            "is_triggered": triggered,
            "risk_level": combo["risk_level"],
            "description": "",  # Will be filled by LLM
        })
    return results


def _check_high_signal_permissions(perms_set: set, perm_map: dict) -> list:
    """Check which high-signal permissions are present."""
    results = []
    for perm in sorted(perms_set):
        short = perm.split(".")[-1] if "." in perm else perm
        if short in HIGH_SIGNAL_PERMISSIONS:
            level = perm_map.get(perm, "normal")
            is_dangerous = "dangerous" in level.lower() if level else False
            results.append({
                "name": perm,
                "protection_level": level,
                "is_dangerous": is_dangerous,
                "malicious_usage": HIGH_SIGNAL_MALICIOUS_USAGE.get(short, ""),
                "malicious_signal": True,
            })
    return results


def _extract_custom_permissions(manifest_text: str) -> list:
    """Extract custom <permission> declarations from manifest."""
    import re
    results = []
    for m in re.finditer(r'<permission\b([^>]*)/>', manifest_text):
        attrs = m.group(1)
        name_m = re.search(r'android:name="([^"]+)"', attrs)
        prot_m = re.search(r'android:protectionLevel="([^"]+)"', attrs)
        name = name_m.group(1) if name_m else ""
        if name and name.startswith("android."):
            continue
        results.append({
            "name": name,
            "protection_level": prot_m.group(1) if prot_m else "",
        })
    return results


def _extract_uses_features(manifest_text: str, apk_path: str) -> list:
    """Extract uses-feature declarations."""
    import re
    results = []
    for m in re.finditer(r'<uses-feature\b([^>]*)/>', manifest_text):
        attrs = m.group(1)
        name_m = re.search(r'android:name="([^"]+)"', attrs)
        req_m = re.search(r'android:required="([^"]+)"', attrs)
        name = name_m.group(1) if name_m else ""
        required = req_m.group(1).lower() == "true" if req_m else True
        if name:
            results.append({"name": name, "required": required})
    if not results:
        try:
            features = androguard_extractor.get_uses_features(apk_path)
            if features:
                for f in features:
                    if isinstance(f, dict):
                        results.append({"name": f.get("name", ""), "required": f.get("required", True)})
                    elif isinstance(f, str):
                        results.append({"name": f, "required": True})
        except Exception:
            pass
    return results


# ── components ─────────────────────────────────────────────────────────────────

def _normalize_jadx_components(jadx_components: list) -> list:
    """Convert JADX manifest-component API output to our internal format."""
    import json as _json
    result = []
    for c in jadx_components:
        if not isinstance(c, dict):
            continue
        cls = c.get("name", c.get("class_name", c.get("class", "")))
        exported = c.get("exported", None)
        if isinstance(exported, bool):
            exported = "true" if exported else "false"
        has_filter = bool(c.get("intent_filters", []))
        full_block_parts = []
        if has_filter:
            for filt in c.get("intent_filters", []):
                if isinstance(filt, dict):
                    for act in filt.get("actions", []):
                        full_block_parts.append(act)
        result.append({
            "class_name": cls,
            "raw_block": _json.dumps(c, ensure_ascii=False)[:500],
            "exported_explicit": exported,
            "permission": c.get("permission", "") or "",
            "has_intent_filter": has_filter,
            "full_block": " ".join(full_block_parts),
        })
    return result


def extract_components(apk_path: str, manifest_text: str) -> dict:
    result = dict(COMPONENTS_DEFAULT)
    activities, services, receivers, providers = [], [], [], []

    # PRIMARY: Try JADX manifest-component API (structured output)
    try:
        activities = _normalize_jadx_components(get_manifest_component("activity"))
        services = _normalize_jadx_components(get_manifest_component("service"))
        receivers = _normalize_jadx_components(get_manifest_component("receiver"))
        providers = _normalize_jadx_components(get_manifest_component("provider"))
    except Exception:
        pass

    # SECONDARY: regex on manifest text (with re.DOTALL for multi-line XML)
    if not activities and not services and not receivers:
        try:
            activities = _get_component_list("activity", manifest_text)
            services = _get_component_list("service", manifest_text)
            receivers = _get_component_list("receiver", manifest_text)
            providers = _get_component_list("provider", manifest_text)
        except Exception:
            pass

    # ALWAYS FALLBACK per-component (independently, not AND)
    if not activities:
        try:
            activities = androguard_extractor.get_activities(apk_path)
        except Exception:
            pass
    if not services:
        try:
            services = androguard_extractor.get_services(apk_path)
        except Exception:
            pass
    if not receivers:
        try:
            receivers = androguard_extractor.get_receivers(apk_path)
        except Exception:
            pass
    if not providers:
        try:
            providers = androguard_extractor.get_providers(apk_path)
        except Exception:
            pass

    # Main activity
    main_activity = ""
    try:
        main_activity = get_main_activity()
    except Exception:
        pass

    # Analyze each component type for suspiciousness
    result["suspicious_activities"] = _analyze_suspicious_activities(activities, main_activity, manifest_text)
    result["suspicious_services"] = _analyze_suspicious_services(services, manifest_text)
    result["suspicious_receivers"] = _analyze_suspicious_receivers(receivers, manifest_text)
    result["suspicious_providers"] = _analyze_suspicious_providers(providers, manifest_text)

    # Export summary
    summary = result["component_export_summary"]
    summary["activity_total"] = len(activities)
    summary["activity_exported"] = sum(1 for a in activities if _is_exported(a, "activity"))
    summary["service_total"] = len(services)
    summary["service_exported"] = sum(1 for s in services if _is_exported(s, "service"))
    summary["service_accessibility_count"] = _count_accessibility_services(services, manifest_text)
    summary["receiver_total"] = len(receivers)
    summary["receiver_exported"] = sum(1 for r in receivers if _is_exported(r, "receiver"))
    summary["provider_total"] = len(providers)

    return result


def _get_component_list(component_type: str, manifest_text: str) -> list:
    """Extract components from manifest text."""
    import re
    components = []
    pattern = rf'<{component_type}\\b[^>]*>'

    # Find all component blocks - use re.DOTALL for multi-line XML
    for m in re.finditer(pattern, manifest_text, re.DOTALL):
        block = m.group(0)

        name_m = re.search(r'android:name="([^"]+)"', block)
        exported_m = re.search(r'android:exported="([^"]+)"', block)
        perm_m = re.search(r'android:permission="([^"]+)"', block)

        comp = {
            "class_name": name_m.group(1) if name_m else "",
            "raw_block": block.replace("\n", " ")[:500],
            "exported_explicit": exported_m.group(1) if exported_m else None,
            "permission": perm_m.group(1) if perm_m else "",
        }

        # Check for intent-filter within the component block
        start = m.end()
        close_tag = f'</{component_type}>'
        close_pos = manifest_text.find(close_tag, start)
        if close_pos == -1:
            close_pos = start
        component_block = manifest_text[start:close_pos + len(close_tag)]
        comp["has_intent_filter"] = "<intent-filter" in component_block
        comp["full_block"] = component_block
        components.append(comp)

    return components


def _is_exported(comp: dict, component_type: str) -> bool:
    """Determine if a component is exported."""
    explicit = comp.get("exported_explicit")
    if explicit is not None:
        return explicit.lower() == "true"
    # If no explicit value, has intent-filter implies exported for activities/providers
    if component_type in ("activity", "provider") and comp.get("has_intent_filter"):
        return True
    # Receivers with intent-filter are exported by default
    if component_type == "receiver" and comp.get("has_intent_filter"):
        return True
    return False


def _count_accessibility_services(services: list, manifest_text: str) -> int:
    """Count services that are AccessibilityService."""
    count = 0
    for svc in services:
        block = svc.get("full_block", svc.get("raw_block", ""))
        if "BIND_ACCESSIBILITY_SERVICE" in block or "AccessibilityService" in svc.get("class_name", ""):
            count += 1
    return count


def _analyze_suspicious_activities(activities: list, main_activity: str, manifest_text: str) -> list:
    """Analyze activities for suspicious characteristics."""
    import re
    suspicious = []
    for act in activities:
        cls = act.get("class_name", "")
        if not cls:
            continue
        exported = _is_exported(act, "activity")
        full_block = act.get("full_block", act.get("raw_block", ""))

        is_main = (cls == main_activity or cls.lstrip(".") == main_activity.lstrip("."))
        is_hidden = not is_main and not ("<action" in full_block and "android.intent.action.MAIN" in full_block)
        is_transparent = ("theme" in full_block.lower() and ("translucent" in full_block.lower() or "transparent" in full_block.lower()))
        hide_from_recent = ("excludeFromRecents" in full_block and "true" in full_block)

        is_suspicious = False
        reasons = []

        if is_transparent:
            is_suspicious = True
            reasons.append("Activity使用透明主题，可能用于钓鱼覆盖层或隐藏操作")
        if hide_from_recent:
            is_suspicious = True
            reasons.append("Activity从最近任务中隐藏，降低用户发现应用运行的概率")
        if exported and is_main and hide_from_recent:
            is_suspicious = True
            reasons.append("主入口Activity被导出且从最近任务中隐藏")
        if is_hidden and re.search(r'[0-9a-f]{8,}', cls):
            is_suspicious = True
            reasons.append(f"类名含长十六进制序列({cls})，疑似混淆命名")

        if is_suspicious:
            suspicious.append({
                "class_name": cls,
                "is_exported": exported,
                "is_main_entry": is_main,
                "is_hidden": is_hidden,
                "is_transparent": is_transparent,
                "hide_from_recent_tasks": hide_from_recent,
                "suspicion_reason": "; ".join(reasons),
            })

    return suspicious


def _analyze_suspicious_services(services: list, manifest_text: str) -> list:
    """Analyze services for suspicious characteristics."""
    suspicious = []
    for svc in services:
        cls = svc.get("class_name", "")
        if not cls:
            continue
        exported = _is_exported(svc, "service")
        full_block = svc.get("full_block", svc.get("raw_block", ""))

        is_accessibility = "BIND_ACCESSIBILITY_SERVICE" in full_block or "AccessibilityService" in cls
        is_device_admin = "BIND_DEVICE_ADMIN" in full_block or "DeviceAdmin" in cls

        # Check source code for keepalive logic
        has_keepalive = False
        is_foreground = False
        has_dynamic_loading = False
        has_jni = False
        try:
            source = get_class_source(cls)
            if source:
                if "START_STICKY" in source or "startForeground" in source or "AlarmManager" in source:
                    has_keepalive = True
                if "startForeground" in source:
                    is_foreground = True
                if "DexClassLoader" in source or "PathClassLoader" in source or "loadClass" in source:
                    has_dynamic_loading = True
                if "System.loadLibrary" in source or "native " in source.lower():
                    has_jni = True
        except Exception:
            pass

        is_suspicious = False
        reasons = []

        if has_keepalive:
            is_suspicious = True
            reasons.append("Service具备保活逻辑(START_STICKY/AlarmManager/前台服务)")
        if is_accessibility:
            is_suspicious = True
            reasons.append("为AccessibilityService，可读取屏幕内容并实现自动化点击")
        if is_device_admin:
            is_suspicious = True
            reasons.append("为DeviceAdminReceiver，可阻止用户卸载并提升持久化能力")
        if has_dynamic_loading:
            is_suspicious = True
            reasons.append("Service进行动态代码加载(DexClassLoader/loadClass)")
        if exported and not is_device_admin:
            reasons.append("Service被导出，可被其他应用通过bindService/startService启动")

        if is_suspicious:
            suspicious.append({
                "class_name": cls,
                "is_exported": exported,
                "is_foreground": is_foreground,
                "has_keepalive_logic": has_keepalive,
                "is_accessibility_service": is_accessibility,
                "is_device_admin": is_device_admin,
                "has_dynamic_code_loading": has_dynamic_loading,
                "has_jni_call": has_jni,
                "suspicion_reason": "; ".join(reasons) if reasons else "Service具备可疑特征",
            })

    return suspicious


def _analyze_suspicious_receivers(receivers: list, manifest_text: str) -> list:
    """Analyze receivers for suspicious characteristics."""
    import re
    suspicious = []
    for recv in receivers:
        cls = recv.get("class_name", "")
        if not cls:
            continue
        exported = _is_exported(recv, "receiver")
        full_block = recv.get("full_block", recv.get("raw_block", ""))

        listens_boot = "BOOT_COMPLETED" in full_block or "ACTION_BOOT_COMPLETED" in full_block
        listens_sms = "SMS_RECEIVED" in full_block or "SMS_DELIVERED" in full_block
        listens_connectivity = "CONNECTIVITY_ACTION" in full_block or "CONNECTIVITY_CHANGE" in full_block
        listens_package = "PACKAGE_ADDED" in full_block or "PACKAGE_REPLACED" in full_block

        # Check source for abortBroadcast and dynamic registration
        aborts_broadcast = False
        is_dynamic = False
        try:
            source = get_class_source(cls)
            if source:
                aborts_broadcast = "abortBroadcast" in source
        except Exception:
            pass

        has_sms_intercept = (listens_sms and (aborts_broadcast or exported))
        intercept_mode = ""
        if has_sms_intercept:
            intercept_mode = "abort_broadcast" if aborts_broadcast else "broadcast"

        is_suspicious = False
        reasons = []
        risk_level = "LOW"

        if listens_boot:
            is_suspicious = True
            reasons.append("监听开机广播(BOOT_COMPLETED)，实现开机自启持久化")
            risk_level = "HIGH"
        if listens_sms:
            is_suspicious = True
            reasons.append("监听短信广播(SMS_RECEIVED)")
            if aborts_broadcast:
                reasons.append("调用abortBroadcast()终止系统广播，实现短信静默拦截")
                risk_level = "CRITICAL"
                intercept_mode = "abort_broadcast"
            if has_sms_intercept:
                risk_level = "HIGH" if risk_level != "CRITICAL" else risk_level
        if listens_connectivity:
            reasons.append("监听网络变化广播(CONNECTIVITY_ACTION)，用于按需触发C2通信")
        if listens_package:
            reasons.append("监听应用安装/替换广播(PACKAGE_ADDED)")

        # Check for dynamic receiver registration in code
        try:
            search_result = search_code_for_pattern(["registerReceiver"])
            for pat, results in search_result.items():
                if results and any(cls in str(r) for r in results):
                    is_dynamic = True
                    break
        except Exception:
            pass

        if is_suspicious:
            suspicious.append({
                "class_name": cls,
                "is_exported": exported,
                "listens_boot_completed": listens_boot,
                "listens_sms_received": listens_sms,
                "listens_connectivity_change": listens_connectivity,
                "listens_package_added": listens_package,
                "aborts_broadcast": aborts_broadcast,
                "has_sms_intercept": has_sms_intercept,
                "is_dynamic_only": is_dynamic and not recv.get("full_block"),
                "intercept_mode": intercept_mode,
                "is_dynamic": is_dynamic,
                "suspicion_reason": "; ".join(reasons),
                "risk_level": risk_level,
            })

    return suspicious


def _analyze_suspicious_providers(providers: list, manifest_text: str) -> list:
    """Analyze providers for suspicious characteristics."""
    known_sdk_prefixes = [
        "com.facebook", "com.google", "com.firebase", "com.crashlytics",
        "com.tencent", "com.bugsense", "com.bugly",
    ]
    suspicious = []
    for prov in providers:
        cls = prov.get("class_name", "")
        if not cls:
            continue
        exported = _is_exported(prov, "provider")
        full_block = prov.get("full_block", prov.get("raw_block", ""))

        read_perm_m = re.search(r'android:readPermission="([^"]+)"', full_block)
        write_perm_m = re.search(r'android:writePermission="([^"]+)"', full_block)
        read_perm = read_perm_m.group(1) if read_perm_m else ""
        write_perm = write_perm_m.group(1) if write_perm_m else ""

        has_data_leak = exported and not read_perm and not write_perm
        is_sdk = any(cls.startswith(p) for p in known_sdk_prefixes)

        # Check source for arbitrary file read / RCE
        has_arbitrary_file_read = False
        has_rce_risk = False
        try:
            source = get_class_source(cls)
            if source:
                if "openFile" in source and (".." in source or "getPath" in source):
                    has_arbitrary_file_read = True
                if "call(" in source and ("exec" in source or "classLoader" in source):
                    has_rce_risk = True
        except Exception:
            pass

        is_suspicious = False
        reasons = []
        risk_level = "LOW"

        if has_data_leak:
            is_suspicious = True
            reasons.append("exported=true 且无 readPermission/writePermission 保护，任何外部应用均可直接查询此Provider的数据")
            risk_level = "HIGH"
        if has_arbitrary_file_read:
            is_suspicious = True
            reasons.append("自定义Provider覆写了openFile()存在路径遍历漏洞")
            risk_level = "CRITICAL"
        if has_rce_risk:
            is_suspicious = True
            reasons.append("Provider覆写了call()方法可能执行任意代码")
            risk_level = "CRITICAL"
        if is_sdk and has_data_leak:
            reasons.append("SDK内置Provider，exported=true 但无权限保护，属于SDK默认暴露面")
            risk_level = "MEDIUM" if not (has_arbitrary_file_read or has_rce_risk) else risk_level

        if is_suspicious:
            suspicious.append({
                "class_name": cls,
                "is_exported": exported,
                "read_permission": read_perm,
                "write_permission": write_perm,
                "has_data_leak_risk": has_data_leak,
                "has_arbitrary_file_read": has_arbitrary_file_read,
                "has_rce_risk": has_rce_risk,
                "is_sdk_provider": is_sdk,
                "suspicion_reason": "; ".join(reasons),
                "risk_level": risk_level,
            })

    return suspicious


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: extract_apk_metadata.py <apk_path> <output_dir>")
        sys.exit(1)

    apk_path = sys.argv[1]
    output_dir = sys.argv[2]
    os.makedirs(output_dir, exist_ok=True)

    print("[sub01] Starting sub-agent 01 extraction...")

    # Load resources
    perm_map = load_permission_mapping(PERMISSION_MAPPING_JSON)
    malware_family = ""

    # Priority 1: malware_family passed as CLI arg (from run_pipeline.py Excel lookup)
    if len(sys.argv) >= 4 and sys.argv[3]:
        malware_family = sys.argv[3]

    # Priority 2: direct Excel lookup via common.py (report_apk_mappings_new.xlsx)
    report_md_path = None
    if not malware_family:
        report_md_path, malware_family = load_apk_report_mapping(
            compute_file_hashes(apk_path)["sha256"],
            REPORT_MAPPING_XLSX,
            REPORT_MD_DIR,
        )

    # Priority 3: malradar fallback — when report_md_path exists but family is empty,
    # look up report_file basename in malradar {report_file: report_family} mapping
    if not malware_family and report_md_path:
        malradar_map = load_malware_family(MALWARE_FAMILY_XLSX)
        if malradar_map:
            # report_md_path ends with .md; malradar keys end with .pdf
            md_base = os.path.basename(report_md_path)
            pdf_base = os.path.splitext(md_base)[0] + ".pdf"
            if pdf_base in malradar_map:
                malware_family = malradar_map[pdf_base]
                print(f"  [+] Malware family (malradar fallback): {malware_family}")

    # Get manifest (shared for multiple extractions)
    manifest_text = ""
    try:
        manifest_text = get_android_manifest()
        print(f"  [+] JADX manifest obtained: {len(manifest_text)} chars")
    except Exception as e:
        print(f"  [!] JADX manifest get failed: {e}")

    # FALLBACK: if manifest_text still empty, get from androguard
    if not manifest_text:
        try:
            manifest_fb = androguard_extractor._open_apk(apk_path).get_android_manifest_xml()
            if manifest_fb is not None:
                try:
                    from xml.etree import ElementTree as _ET
                    manifest_text = _ET.tostring(manifest_fb, encoding="unicode")
                except Exception:
                    manifest_text = str(manifest_fb)
            if manifest_text:
                print(f"  [+] Androguard manifest fallback: {len(manifest_text)} chars")
        except Exception:
            pass
        if not manifest_text:
            print("  [!] No manifest available from jadx or androguard")

    # 1. file_basic
    print("  [*] Extracting file_basic...")
    file_basic = extract_file_basic(apk_path, perm_map, malware_family)
    save_json(file_basic, os.path.join(output_dir, "file_basic.json"))

    # 2. certificate_analysis
    print("  [*] Extracting certificate_analysis...")
    cert_analysis = extract_certificate_analysis(apk_path)
    save_json(cert_analysis, os.path.join(output_dir, "certificate_analysis.json"))

    # 3. permissions
    print("  [*] Extracting permissions...")
    permissions = extract_permissions(apk_path, manifest_text, perm_map)
    save_json(permissions, os.path.join(output_dir, "permissions.json"))

    # 4. components
    print("  [*] Extracting components...")
    components = extract_components(apk_path, manifest_text)
    save_json(components, os.path.join(output_dir, "components.json"))

    print("[sub01] Done.")


if __name__ == "__main__":
    main()
