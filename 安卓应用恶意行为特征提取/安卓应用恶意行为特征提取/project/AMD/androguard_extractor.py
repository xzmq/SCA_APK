"""
androguard_extractor.py - Fallback layer using androguard 4.1.3 Python library.
Used only when jadx MCP extraction fails or for supplementary data extraction.
"""
import os
import sys
import re
import hashlib
import zipfile
from xml.etree import ElementTree as ET

from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis


# ── Lazy APK singleton per call (no cross-call caching) ─────────────────────────

def _open_apk(apk_path: str) -> APK:
    """Open an APK with full analysis."""
    return APK(apk_path, skip_analysis=False)


def _get_apk_raw_bytes(apk_path: str) -> bytes:
    """Read APK file bytes."""
    with open(apk_path, "rb") as f:
        return f.read()


def _get_dex_objects(apk_path: str):
    """
    Yield (dex_name, DEX_obj, Analysis_obj) for each DEX in APK.
    """
    import zipfile
    apk = _open_apk(apk_path)
    dex_names = apk.get_dex_names()
    with zipfile.ZipFile(apk_path, "r") as zf:
        for dex_name in dex_names:
            try:
                dex_bytes = zf.read(dex_name)
                if not dex_bytes:
                    continue
                vm = DEX(dex_bytes)
                analysis = Analysis(vm)
                yield dex_name, vm, analysis
            except Exception:
                continue


# ── Sensitive API set for suspicious API detection ─────────────────────────────

_SENSITIVE_API_CLASSES = {
    # Network
    "java/net/HttpURLConnection",
    "java/net/URL",
    "java/net/Socket",
    "java/net/ServerSocket",
    "java/net/DatagramSocket",
    "okhttp3/OkHttpClient",
    "okhttp3/Request",
    "okhttp3/RequestBody",
    "org/apache/http/client/HttpClient",
    # SMS / Telephony
    "android/telephony/TelephonyManager",
    "android/telephony/SmsManager",
    "android/telephony/SmsMessage",
    "android/provider/Telephony$Sms",
    # Contacts / Call Log
    "android/provider/ContactsContract",
    "android/provider/CallLog",
    # Location
    "android/location/LocationManager",
    "android/location/Location",
    "android/location/GpsStatus",
    # Storage / File
    "android/os/Environment",
    "java/io/File",
    "java/io/FileInputStream",
    "java/io/FileOutputStream",
    # Content Resolver
    "android/content/ContentResolver",
    # Device Info
    "android/os/Build",
    "android/provider/Settings$Secure",
    "android/provider/Settings$System",
    # Runtime / Shell
    "java/lang/Runtime",
    "java/lang/ProcessBuilder",
    # Reflection / Dynamic loading
    "java/lang/Class",
    "java/lang/reflect/Method",
    "dalvik/system/DexClassLoader",
    "dalvik/system/PathClassLoader",
    "dalvik/system/BaseDexClassLoader",
    # Crypto
    "javax/crypto/Cipher",
    "javax/crypto/spec/SecretKeySpec",
    "java/security/MessageDigest",
    # Root / Anti-analysis
    "android/app/ActivityManager",
    "android/app/Debug",
    # Notification
    "android/app/NotificationManager",
    # Accessibility
    "android/view/accessibility/AccessibilityService",
    # Device Admin
    "android/app/admin/DeviceAdminReceiver",
}


# ── Individual extractor functions ──────────────────────────────────────────────

def analyze_apk(apk_path: str) -> dict:
    """Basic APK analysis: package name, version, SDK info."""
    apk = _open_apk(apk_path)
    return {
        "package_name": apk.get_package() or "",
        "package": apk.get_package() or "",
        "version_code": apk.get_androidversion_code(),
        "version_name": apk.get_androidversion_name() or "",
        "min_sdk_version": apk.get_min_sdk_version() or 0,
        "target_sdk_version": apk.get_target_sdk_version() or 0,
        "max_sdk_version": apk.get_max_sdk_version() or 0,
    }


def get_permissions(apk_path: str) -> list:
    """Extract all requested permissions from manifest."""
    apk = _open_apk(apk_path)
    return apk.get_permissions()


def get_activities(apk_path: str) -> list:
    """Extract activities from manifest. Returns list of dicts with component metadata."""
    return _extract_manifest_components(apk_path, "activity")


def get_services(apk_path: str) -> list:
    """Extract services from manifest."""
    return _extract_manifest_components(apk_path, "service")


def get_receivers(apk_path: str) -> list:
    """Extract receivers from manifest."""
    return _extract_manifest_components(apk_path, "receiver")


def get_providers(apk_path: str) -> list:
    """Extract providers from manifest."""
    return _extract_manifest_components(apk_path, "provider")


def _extract_manifest_components(apk_path: str, tag_name: str) -> list:
    """
    Extract manifest components as list of dicts compatible with sub01 format:
    {class_name, raw_block, exported_explicit, permission, has_intent_filter, full_block}
    """
    apk = _open_apk(apk_path)
    manifest = apk.get_android_manifest_xml()
    if manifest is None:
        return []

    components = []
    ns = "{http://schemas.android.com/apk/res/android}"

    # Iterate all elements with matching tag
    for elem in manifest.iter():
        # Check if this element's tag (without namespace in some cases) matches
        tag = elem.tag
        # lxml uses '{namespace}tag' format
        if tag == tag_name or tag.endswith("}" + tag_name):
            comp = _build_component_dict(elem, tag_name, ns)
            components.append(comp)

    return components


def _get_elem_tag_text(elem, tag_name, ns):
    """Get attribute value, supporting both namespaced and non-namespaced forms."""
    # Try namespaced form first
    attr_text = elem.get(ns + tag_name)
    if attr_text:
        return attr_text
    # Fallback to non-namespaced
    attr_text = elem.get(tag_name)
    if attr_text:
        return attr_text
    return None


def _get_elem_attr(elem, attr_name, ns):
    """Get element attribute value. Try namespaced then bare."""
    val = elem.get(ns + attr_name)
    if val is not None:
        return val
    val = elem.get(attr_name)
    if val is not None:
        return val
    return None


def _build_component_dict(elem, tag_name, ns):
    """Build component dict from lxml element."""
    # Class name
    class_name = _get_elem_attr(elem, "name", ns) or ""

    # Explicit exported value
    exported_val = _get_elem_attr(elem, "exported", ns)

    # Permission
    permission = _get_elem_attr(elem, "permission", ns) or ""

    # Intent-filter check
    has_intent_filter = False
    for child in elem:
        child_tag = child.tag
        if child_tag == "intent-filter" or child_tag.endswith("}intent-filter"):
            has_intent_filter = True
            break

    # Full block as XML string
    # ElementTree tostring returns bytes; decode to str
    try:
        full_block = ET.tostring(elem, encoding="unicode")
    except TypeError:
        # Python < 3.8 fallback
        full_block = ET.tostring(elem, encoding="utf-8").decode("utf-8")

    return {
        "class_name": class_name,
        "raw_block": full_block[:500] if full_block else "",
        "exported_explicit": exported_val,
        "permission": permission if permission else "",
        "has_intent_filter": has_intent_filter,
        "full_block": full_block if full_block else "",
    }


def get_app_info(apk_path: str) -> dict:
    """Get application-level metadata: label, icon, description."""
    apk = _open_apk(apk_path)
    app_name = apk.get_app_name() if hasattr(apk, "get_app_name") and apk.get_app_name() else ""
    return {
        "app_label": app_name if app_name else "",
        "label": app_name if app_name else "",
        "description": "",
    }


def get_certificates(apk_path: str) -> dict:
    """Get certificate/signer information from APK."""
    apk = _open_apk(apk_path)
    certs = []

    # Try v3, v2, then v1 signing schemes
    cert_objects = []
    try:
        cert_objects = apk.get_certificates_v3()
    except Exception:
        cert_objects = []
    if not cert_objects:
        try:
            cert_objects = apk.get_certificates_v2()
        except Exception:
            cert_objects = []
    if not cert_objects:
        try:
            cert_objects = apk.get_certificates_v1()
        except Exception:
            cert_objects = []

    for cert_obj in cert_objects:
        if cert_obj is None:
            continue
        info = _process_asn1crypto_certificate(cert_obj, apk)
        if info:
            certs.append(info)

    return {
        "is_signed": any(certs),
        "certificate_count": len(certs),
        "certificates": certs,
        # Keep backwards-compatible keys
        "signing_algorithm": certs[0].get("signing_algorithm", "") if certs else "",
        "fingerprint_sha256": certs[0].get("fingerprint_sha256", "") if certs else "",
        "fingerprint_sha1": certs[0].get("fingerprint_sha1", "") if certs else "",
        "subject": certs[0].get("subject", "") if certs else "",
        "issuer": certs[0].get("issuer", "") if certs else "",
        "is_self_signed": certs[0].get("is_self_signed", False) if certs else False,
    }


def _process_asn1crypto_certificate(cert_obj, apk) -> dict:
    """
    Process an asn1crypto.x509.Certificate or
    cryptography.x509.Certificate object into our dict format.
    """
    result = {}

    # Check type: asn1crypto vs cryptography
    cert_type_name = type(cert_obj).__module__
    is_asn1crypto = "asn1crypto" in cert_type_name
    is_cryptography = "cryptography" in cert_type_name

    if is_cryptography:
        result = _process_cert_cryptography(cert_obj)
    elif is_asn1crypto:
        # Convert asn1crypto cert to DER, then load via cryptography
        try:
            der_bytes = cert_obj.dump()
            from cryptography import x509
            crypto_cert = x509.load_der_x509_certificate(der_bytes)
            result = _process_cert_cryptography(crypto_cert)
        except Exception:
            # Fallback: parse asn1crypto fields directly
            result = _process_cert_asn1crypto_direct(cert_obj)
    else:
        # Try generic DER extraction
        try:
            der_bytes = cert_obj.dump()
            from cryptography import x509
            crypto_cert = x509.load_der_x509_certificate(der_bytes)
            result = _process_cert_cryptography(crypto_cert)
        except Exception:
            pass

    return result


def _process_cert_cryptography(cert) -> dict:
    """Process a cryptography.x509.Certificate into our dict format."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

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
    result["issuer_common_name"] = _get_dn_field(cert.issuer, "commonName")

    # Serial
    result["serial_number"] = format(cert.serial_number, "x")

    # Dates
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    result["valid_from"] = not_before.isoformat()
    result["valid_until"] = not_after.isoformat()
    result["valid_days"] = (not_after - not_before).days if hasattr(not_after, "__sub__") else 0

    # Debug check
    cn = result["subject_common_name"]
    result["is_debug_certificate"] = bool("androiddebug" in cn.lower()) if cn else False

    # Public key
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
    elif isinstance(pub_key, dsa.DSAPublicKey):
        result["public_key_type"] = "DSA"
        result["public_key_bit_length"] = pub_key.key_size
    else:
        result["public_key_type"] = "Unknown"
        result["public_key_bit_length"] = 0

    # Signing algorithm
    if hasattr(cert.signature_algorithm_oid, "_name"):
        result["signing_algorithm"] = cert.signature_algorithm_oid._name
    else:
        result["signing_algorithm"] = cert.signature_algorithm_oid.dotted_string

    # Fingerprints
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    result["fingerprint_sha256"] = hashlib.sha256(cert_der).hexdigest().upper()
    result["fingerprint_sha1"] = hashlib.sha1(cert_der).hexdigest().upper()

    # Subject anomaly
    result["subject_anomaly"] = _check_subject_anomaly(result)

    return result


def _process_cert_asn1crypto_direct(cert_obj) -> dict:
    """Fallback processing for asn1crypto certs when cryptography conversion fails."""
    result = {}
    try:
        result["subject"] = cert_obj.subject.native.get("common_name", "")
        result["issuer"] = cert_obj.issuer.native.get("common_name", "")
        result["serial_number"] = format(cert_obj.serial_number.native, "x")
        result["fingerprint_sha256"] = hashlib.sha256(cert_obj.dump()).hexdigest().upper()
        result["fingerprint_sha1"] = hashlib.sha1(cert_obj.dump()).hexdigest().upper()
    except Exception:
        pass
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
        return False
    if cn and len(cn) > 30:
        from common import shannon_entropy_string
        ent = shannon_entropy_string(cn)
        if ent > 4.0:
            return True
    return False


def get_files(apk_path: str) -> list:
    """List all files inside APK."""
    apk = _open_apk(apk_path)
    return apk.get_files()


def get_libraries(apk_path: str) -> list:
    """
    Get native .so libraries inside APK.
    Returns list of path strings (e.g., ["lib/armeabi-v7a/libfoo.so", ...]).
    NOTE: androguard's APK.get_libraries() returns uses-library from manifest,
    NOT native .so files. We scan the APK file list directly.
    """
    apk = _open_apk(apk_path)
    so_files = []
    for f in apk.get_files():
        if f.endswith(".so"):
            so_files.append(f)
    return so_files


def get_uses_features(apk_path: str) -> list:
    """
    Get hardware/software features required from manifest.
    Returns list of dicts: [{name, required}, ...]
    """
    apk = _open_apk(apk_path)
    manifest = apk.get_android_manifest_xml()
    if manifest is None:
        return apk.get_features()  # fallback to string list

    ns = "{http://schemas.android.com/apk/res/android}"
    results = []
    for elem in manifest.iter():
        tag = elem.tag
        if tag == "uses-feature" or tag.endswith("}uses-feature"):
            name = _get_elem_attr(elem, "name", ns) or ""
            req_val = _get_elem_attr(elem, "required", ns)
            required = req_val != "false" if req_val is not None else True
            if name:
                results.append({"name": name, "required": required})
    return results


def get_intent_filters(apk_path: str) -> list:
    """Extract intent filters from manifest."""
    apk = _open_apk(apk_path)
    manifest = apk.get_android_manifest_xml()
    if manifest is None:
        return []

    ns = "{http://schemas.android.com/apk/res/android}"
    results = []
    component_types = ("activity", "service", "receiver")

    for elem in manifest.iter():
        tag = elem.tag
        is_component = False
        comp_type = ""
        for ct in component_types:
            if tag == ct or tag.endswith("}" + ct):
                is_component = True
                comp_type = ct
                break
        if not is_component:
            continue

        class_name = _get_elem_attr(elem, "name", ns) or ""

        # Check for intent-filter children
        for child in elem:
            child_tag = child.tag
            if child_tag == "intent-filter" or child_tag.endswith("}intent-filter"):
                actions = []
                categories = []
                data_schemes = []
                data_mimes = []

                for sub in child:
                    sub_tag = sub.tag
                    if sub_tag == "action" or sub_tag.endswith("}action"):
                        action_val = _get_elem_attr(sub, "name", ns) or ""
                        if action_val:
                            actions.append(action_val)
                    elif sub_tag == "category" or sub_tag.endswith("}category"):
                        cat_val = _get_elem_attr(sub, "name", ns) or ""
                        if cat_val:
                            categories.append(cat_val)
                    elif sub_tag == "data" or sub_tag.endswith("}data"):
                        scheme = _get_elem_attr(sub, "scheme", ns)
                        mime = _get_elem_attr(sub, "mimeType", ns)
                        if scheme:
                            data_schemes.append(scheme)
                        if mime:
                            data_mimes.append(mime)

                results.append({
                    "component_type": comp_type,
                    "component_name": class_name,
                    "actions": actions,
                    "categories": categories,
                    "data_schemes": data_schemes,
                    "data_mimes": data_mimes,
                })

    return results


def get_classes(apk_path: str, package_filter: str = None) -> list:
    """
    List all DEX classes.
    Returns list of class name strings.
    Optionally filter by package prefix (e.g. 'com.example').
    """
    classes = []
    prefix = None
    if package_filter:
        prefix = package_filter.replace(".", "/") + "/"

    for _, _, analysis in _get_dex_objects(apk_path):
        for ca in analysis.get_classes():
            name = ca.name
            if prefix and not name.startswith(prefix):
                continue
            classes.append(name)

    return classes


def get_methods(apk_path: str, class_name: str) -> list:
    """
    Get all methods of a specific DEX class.
    class_name uses slash format (e.g. 'com/example/Foo').
    Returns list of dicts: [{name, descriptor, access_flags}, ...]
    """
    methods = []
    for _, _, analysis in _get_dex_objects(apk_path):
        if not analysis.is_class_present(class_name):
            continue
        ca = analysis.get_class_analysis(class_name)
        for ma in ca.get_methods():
            methods.append({
                "name": ma.name,
                "descriptor": ma.descriptor,
                "full_name": ma.full_name,
                "access_flags": ma.get_access_flags_string(),
            })
    return methods


def get_strings(apk_path: str, limit: int = 500) -> list:
    """
    Extract strings from DEX files.
    Returns list of string values.
    """
    strings = []
    seen = set()
    for _, _, analysis in _get_dex_objects(apk_path):
        for sa in analysis.get_strings():
            val = sa.get_value()
            if val and val not in seen:
                seen.add(val)
                strings.append(val)
                if limit and len(strings) >= limit:
                    return strings
    return strings


def detect_suspicious_apis(apk_path: str) -> list:
    """
    Detect suspicious API calls in DEX using cross-reference analysis.
    Returns list of dicts: [{api, caller, category}, ...].
    """
    suspicious = []
    api_category = {
        "HttpURLConnection": "network",
        "Socket": "network",
        "SmsManager": "sms",
        "TelephonyManager": "telephony",
        "ContentResolver": "content",
        "LocationManager": "location",
        "Runtime": "execution",
        "ProcessBuilder": "execution",
        "DexClassLoader": "dynamic_loading",
        "PathClassLoader": "dynamic_loading",
        "Cipher": "crypto",
        "MessageDigest": "crypto",
        "Build": "device_info",
        "ContactsContract": "contacts",
        "CallLog": "contacts",
        "NotificationManager": "notification",
        "AccessibilityService": "accessibility",
        "DeviceAdminReceiver": "admin",
        "Environment": "storage",
    }

    for dex_name, vm, analysis in _get_dex_objects(apk_path):
        for ma in analysis.get_methods():
            for target_xref in ma.get_xref_to():
                target_name = getattr(target_xref, "class_name", "") or ""
                target_method = getattr(target_xref, "name", "") or ""

                for api_class, category in api_category.items():
                    target_full = target_name + "." + target_name.rsplit("/", 1)[-1] if "/" in target_name else target_name
                    if api_class in target_name or api_class in target_full:
                        suspicious.append({
                            "api": target_name + "." + target_method,
                            "caller": ma.full_name,
                            "category": category,
                        })
                        break

    # Deduplicate
    seen = set()
    unique = []
    for s in suspicious:
        key = (s["api"], s["caller"])
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique


# ── High-level fallback helpers ─────────────────────────────────────────────────

def get_basic_info_fallback(apk_path: str) -> dict:
    """Get basic APK info as fallback when jadx fails."""
    info = {}
    try:
        info["analyze"] = analyze_apk(apk_path)
    except Exception:
        pass
    try:
        info["app_info"] = get_app_info(apk_path)
    except Exception:
        pass
    try:
        info["permissions"] = get_permissions(apk_path)
    except Exception:
        pass
    return info


def get_components_fallback(apk_path: str) -> dict:
    """Get all components as fallback when jadx fails."""
    result = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    try:
        result["activities"] = get_activities(apk_path)
    except Exception:
        pass
    try:
        result["services"] = get_services(apk_path)
    except Exception:
        pass
    try:
        result["receivers"] = get_receivers(apk_path)
    except Exception:
        pass
    try:
        result["providers"] = get_providers(apk_path)
    except Exception:
        pass
    return result


def get_full_fallback(apk_path: str) -> dict:
    """Comprehensive fallback extraction when jadx MCP is completely unavailable."""
    result = {}
    try:
        result["basic"] = get_basic_info_fallback(apk_path)
    except Exception:
        pass
    try:
        result["components"] = get_components_fallback(apk_path)
    except Exception:
        pass
    try:
        result["certificates"] = get_certificates(apk_path)
    except Exception:
        pass
    try:
        result["libraries"] = get_libraries(apk_path)
    except Exception:
        pass
    try:
        result["features"] = get_uses_features(apk_path)
    except Exception:
        pass
    try:
        result["intent_filters"] = get_intent_filters(apk_path)
    except Exception:
        pass
    try:
        result["suspicious_apis"] = detect_suspicious_apis(apk_path)
    except Exception:
        pass
    try:
        result["strings"] = get_strings(apk_path, limit=1000)
    except Exception:
        pass
    return result
