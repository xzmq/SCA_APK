"""
extract_c2_iocs.py - C2 IOCs: c2_communication, iocs.
Usage: python extract_c2_iocs.py <apk_path> <output_dir>
"""
import os
import sys
import re
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import androguard_extractor

# Module-level APK path for androguard fallback in code search
_apk_path = None
from config import *
from common import *
from jadx_extractor import (
    get_android_manifest, get_class_source, get_strings,
    search_code_for_pattern, get_all_classes, get_fields_of_class,
    search_classes_by_keyword,
)


def extract_c2_communication(apk_path, decompiled_dir=""):
    result = dict(C2_COMMUNICATION_DEFAULT)

    # Check manifest for cleartext traffic
    result["cleartext_traffic_permitted"] = _check_cleartext_traffic_permitted()

    # Extract strings from DEX to find URLs, IPs, domains
    all_strings = _extract_all_strings(apk_path)

    # Find C2 URLs
    urls, ips, domains = _extract_network_indicators(all_strings)

    # Build c2_servers
    result["c2_servers"] = _build_c2_servers(urls, ips)
    result["has_c2"] = len(result["c2_servers"]) > 0

    # FALLBACK: check behavior indicators when no explicit URL found in strings
    if not result["has_c2"]:
        try:
            net_pats = ["HttpURLConnection", "Socket", "URL("]
            url_pats = ["http://", "https://", "setDoOutput", "POST"]
            r1 = search_code_for_pattern(net_pats)
            r2 = search_code_for_pattern(url_pats)
            if any(r1.get(p) for p in net_pats) and any(r2.get(p) for p in url_pats):
                result["has_c2"] = True
        except Exception:
            pass

    # Communication pattern
    result["c2_communication_pattern"] = _analyze_communication_pattern()

    # Encrypted C2 indicators
    result["encrypted_c2_indicators"] = _find_encrypted_c2_indicators(apk_path, decompiled_dir)

    # C2 commands
    result["c2_command_categories"] = _detect_c2_command_categories()
    result["c2_commands"] = _detect_c2_commands()

    return result


def extract_iocs(apk_path, c2_result):
    result = dict(IOCS_DEFAULT)

    # Fix 1: iocs.c2_ips derived from c2_servers, but iocs.c2_urls only contains
    # URLs from decrypted results NOT already in c2_servers (no duplicate copy).
    # c2_servers[].url is the authoritative source for C2 server URLs.
    server_urls = set()
    result["c2_ips"] = []
    for srv in c2_result.get("c2_servers", []):
        if srv.get("url"):
            server_urls.add(srv["url"])
        if srv.get("ip"):
            result["c2_ips"].append(srv["ip"])
    result["c2_ips"] = list(set(result["c2_ips"]))

    # iocs.c2_urls: only additional URLs from decrypted results not in c2_servers
    result["c2_urls"] = []
    url_re = re.compile(r'^https?://', re.IGNORECASE)
    for ind in c2_result.get("encrypted_c2_indicators", []):
        decrypted = ind.get("decrypted_result", "")
        if decrypted:
            if url_re.match(decrypted) and decrypted not in server_urls:
                result["c2_urls"].append(decrypted)

    # Deduplicate
    result["c2_urls"] = list(set(result["c2_urls"]))

    # Suspicious domains: only output detail (no separate string array — avoid redundancy)
    all_domains = set()
    for srv in c2_result.get("c2_servers", []):
        domain = srv.get("domain", "")
        if not domain:
            domain = _extract_domain_from_url(srv.get("url", ""))
        if domain:
            all_domains.add(domain)
        if srv.get("ip"):
            all_domains.add(srv["ip"])

    # Crypto wallet addresses
    result["crypto_wallet_addresses"] = _find_crypto_wallets(apk_path)

    # Suspicious domain details (authoritative — contains domain + purpose + level)
    result["suspicious_domains_detail"] = _build_suspicious_domain_details(all_domains)

    return result


# ── C2 helpers ─────────────────────────────────────────────────────────────────

def _check_cleartext_traffic_permitted():
    try:
        manifest = get_android_manifest()
        return 'allowCleartextTraffic="true"' in manifest
    except Exception:
        return False


def _extract_all_strings(apk_path):
    """Extract strings from both jadx and androguard."""
    strings = set()
    try:
        jadx_strings = get_strings()
        if jadx_strings:
            for s in jadx_strings:
                if isinstance(s, dict):
                    val = s.get("value", s.get("text", ""))
                elif isinstance(s, str):
                    val = s
                else:
                    continue
                if val:
                    strings.add(val)
    except Exception:
        pass

    try:
        ag_strings = androguard_extractor.get_strings(apk_path, limit=0)
        if ag_strings:
            for s in ag_strings:
                if isinstance(s, str) and s.strip():
                    strings.add(s.strip())
    except Exception:
        pass

    return strings


# ── C2 URL filtering helpers ───────────────────────────────────────────────────

# Format string placeholders: %s, %d, {0}, ${name}, %(name)s
_FORMAT_PLACEHOLDER_RE = re.compile(r'%[-#+ 0-9.]*[sdboxXfegact%]|\{[0-9]+\}|\$\{[^}]+\}|%\([^)]+\)s')

# Special reserved URLs that are never C2
_SPECIAL_URL_PREFIXES = (
    'about:blank', 'about:srcdoc', 'about:about',
    'data:', 'javascript:', 'blob:', 'file://', 'ftp://', 'mailto:',
    'intent://', 'market://', 'package:', 'content://', 'sms:', 'tel:',
)

# XML namespaces and schema URLs (extended beyond schemas.android.com)
_NAMESPACE_PATTERNS = (
    'schemas.android.com', 'schemas.microsoft.com', 'schemas.xmlsoap.org',
    'www.w3.org/', 'ns.adobe.com/', 'java.sun.com', 'www.springframework.org',
    'xmlns', 'http://schemas.', 'http://www.osgi.org',
)

# Benign SDK domains (advertising/analytics/push/login/map/crash reporting)
# Used with precise suffix matching (host == d or host.endswith('.' + d))
_BENIGN_SDK_DOMAINS = {
    # Advertising / analytics
    'alicdn.lieying.cn', 'lieying.cn', 'ad.toutiao.com', 'pityy.com',
    'mediav.com', 'madserving.com', 'domob.cn', 'domob.org', 'adview.cn',
    'youdao.com', 'adcdn.com', 'admob.com', 'doubleclick.net',
    'googlesyndication.com', 'google-analytics.com', 'googletagmanager.com',
    'umeng.com', 'umeng.co', 'umengcloud.com', 'cnzz.com', 'tanx.com',
    'madserving.com', 'adsame.com', 'mediav.com', 'm.taobao.com',
    'g.cn', 'g.alicdn.com', 'amos.alicdn.com', 'p.gl.nnapp.com',
    'mipcdn.com', 'flurry.com', 'appsflyer.com', 'adjust.com',
    'ironsrc.com', 'applovin.com', 'mintegral.com', 'unityads.unity3d.com',
    'chartbeat.com', 'mixpanel.com', 'amplitude.com', 'segment.com',
    # Push SDK
    'jpush.cn', 'jpush.io', 'getui.com', 'igexin.com', 'tpns.tencent.com',
    'meizu.com', 'huawei.com', 'xiaomi.com', 'push.oppo.com',
    # Third-party login / share / OAuth SDK
    'api.weixin.qq.com', 'open.weixin.qq.com', 'graph.qq.com',
    'm.facebook.com', 'graph.facebook.com', 'api.facebook.com',
    'api.twitter.com', 'ads-twitter.com', 't.co',
    'api.linkedin.com', 'api.instagram.com', 'api.tumblr.com',
    'accounts.google.com', 'oauth2.googleapis.com', 'www.googleapis.com',
    'appleid.apple.com', 'api.weibo.com', 'api.box.com', 'api.500px.com',
    'api.dropboxapi.com', 'api.onedrive.com', 'www.onenote.com',
    'graph.microsoft.com', 'login.microsoftonline.com',
    # Map SDK
    'maps.googleapis.com', 'restapi.amap.com', 'api.map.baidu.com',
    # Crash reporting / logging
    'bugly.qq.com', 'sentry.io', 'rink.hockeyapp.net', 'fabric.io',
    'api.cloud.leanbug.io', 'countly.com',
    # CDN / resources
    'images.ssl.sky.com', 'avatar.csdn.net', 'cdn.jsdelivr.net',
    'z.moatads.com', 'cn2.me', 'cc.co',
    # Common cloud providers (often used as legitimate backends)
    'amazon.com', 'amazonaws.com', 'cloudfront.net', 'akamai.net',
    'akamaized.net', 'cloudflare.com', 'cloudflare.net',
    'github.com', 'githubusercontent.com', 'github.io',
    'youtube.com', 'googlevideo.com', 'gstatic.com',
    'wikipedia.org', 'stackoverflow.com', 'medium.com',
    # CamScanner / INTSIG benign endpoints (Necro sample specific)
    'www-sandbox.camscanner.com', 'www.camscanner.com', 'info.camcard.me',
    'api.intsig.net', 'intsig.com', 'camscanner.com',
    # ── Fix 2: expanded benign domains ──
    # OAuth / social API (frequently mistaken as C2)
    'freelancer.com', 'vimeo.com', 'sohu.com', 'kaixin001.com',
    'getglue.com', 'paytm.com', 'slf4j.org', 'iess.cn',
    'api.t.sohu.com', 't.sohu.com',
    # Ad / analytics SDK (expanded)
    'ogury.com', 'ogury.io', 'eula.ogury.com', 'ads-test.st.ogury.com',
    'applvn.com', 'a.applvn.com', 'mraid.js',
    'adcolony.com', 'chartboost.com', 'startapp.com',
    'inmobi.com', 'fyber.com', 'outbrain.com', 'taboola.com',
    'startapp.android.publish', 'airpush.com', 'leadbolt.com',
    'revmob.com', 'appsflyer.com', 'avazu.com',
    # CDN / cloud / SDK infrastructure
    'cdn.image.suib.com', 'suib.com', 'onelink.com',
    'mobileapptracking.com', 'onelink.mobileapptracking.com',
    'api.tune.com', 'api.hasoffers.com',
    # Common Java/library URLs
    'www.slf4j.org', 'slf4j.org',
    # Video / media SDK
    'googlevideo.com', 'vimeo.cdn', 'vimeocdn.com',
    # CRM / analytics
    'api.getglue.com', 'api.500px.com',
    # Real-time messaging
    'api.tumblr.com', 'api.instagram.com',
}

# Top-level benign keywords for fallback host check
_BENIGN_HOST_KEYWORDS = (
    'google', 'facebook', 'amazon', 'microsoft', 'apple', 'twitter', 'linkedin',
    'github', 'youtube', 'wikipedia', 'cloudflare', 'akamai', 'cloudfront',
    'baidu', 'tencent', 'alibaba', 'alicdn', 'taobao', 'jd.com', 'qq.com',
    'weixin', 'weibo', 'bytedance', 'toutiao', 'microsoftonline', 'office365',
    'nginx', 'camscanner', 'intsig',
)


def _is_format_template(url: str) -> bool:
    """Check if URL is a format string template (e.g. http://%s:%d/%s)."""
    placeholders = _FORMAT_PLACEHOLDER_RE.findall(url)
    # If URL contains placeholders like %s/%d/{0}/${name}, treat as template
    return len(placeholders) >= 1


def _is_special_url(url: str) -> bool:
    """Check if URL is a special reserved URL (about:blank, data:, javascript:, etc.)."""
    low = url.lower()
    for prefix in _SPECIAL_URL_PREFIXES:
        if low.startswith(prefix):
            return True
    # http://about:blank style
    if 'about:blank' in low or 'about:srcdoc' in low:
        return True
    return False


def _is_namespace_url(url: str) -> bool:
    """Check if URL is an XML namespace or schema definition."""
    low = url.lower()
    for pattern in _NAMESPACE_PATTERNS:
        if pattern in low:
            return True
    return False


def _is_private_or_reserved_ip(ip: str) -> bool:
    """Check if IP is private, reserved, loopback, multicast, or broadcast."""
    try:
        parts = [int(p) for p in ip.split('.')]
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            return True
        a, b, c, d = parts
        if a == 0: return True                       # 0.0.0.0/8
        if a == 10: return True                      # 10.0.0.0/8
        if a == 127: return True                     # 127.0.0.0/8 loopback
        if a == 169 and b == 254: return True        # 169.254.0.0/16 link-local
        if a == 172 and 16 <= b <= 31: return True   # 172.16.0.0/12
        if a == 192 and b == 168: return True        # 192.168.0.0/16
        if a == 192 and b == 0 and c == 2: return True  # 192.0.2.0/24 TEST-NET-1
        if a == 198 and (b == 18 or b == 19): return True
        if a == 198 and b == 51 and c == 100: return True  # TEST-NET-2
        if a == 203 and b == 0 and c == 113: return True   # TEST-NET-3
        if 224 <= a <= 239: return True              # 224.0.0.0/4 multicast
        if a >= 240: return True                     # 240.0.0.0/4 reserved
        if a == 255 and b == 255 and c == 255 and d == 255: return True  # broadcast
        return False
    except Exception:
        return True


def _is_likely_oid_fragment(ip: str) -> bool:
    """Check if IP is likely an ASN.1 OID fragment (e.g. 1.3.6.1, 1.12.1.3).
    These are common in X.509/LDAP/SNMP OIDs, not real public IPs.
    Heuristic: first octet 0-5 and all octets <= 100.
    """
    try:
        parts = [int(p) for p in ip.split('.')]
        if len(parts) != 4:
            return False
        a = parts[0]
        if a in (0, 1, 2, 3, 4, 5):
            if all(p <= 100 for p in parts):
                return True
        return False
    except Exception:
        return False


def _extract_host(url: str) -> str:
    """Extract host (domain or IP) from URL, return "" if not found."""
    m = re.match(r'https?://([^/:]+)', url, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return ""


def _is_benign_sdk_url(url: str) -> bool:
    """Check if URL belongs to a benign SDK (ad/analytics/push/login/map/crash)."""
    host = _extract_host(url)
    if not host:
        return False
    # Precise suffix match against benign SDK domains
    for d in _BENIGN_SDK_DOMAINS:
        if host == d or host.endswith('.' + d):
            return True
    # Fallback: benign host keywords (substring match for resilience)
    for kw in _BENIGN_HOST_KEYWORDS:
        if kw in host:
            return True
    return False


def _is_likely_c2_url(url: str) -> bool:
    """Unified C2 URL filter: returns True only if URL passes all exclusion rules.
    This is the main gate for c2_servers entry.
    """
    if not url or not url.startswith(('http://', 'https://')):
        return False
    # Rule 1: exclude format string templates
    if _is_format_template(url):
        return False
    # Rule 2: exclude special reserved URLs
    if _is_special_url(url):
        return False
    # Rule 3: exclude XML namespaces and schema URLs
    if _is_namespace_url(url):
        return False
    # Rule 4: exclude benign SDK URLs (ad/analytics/push/login/map/crash)
    if _is_benign_sdk_url(url):
        return False
    # Rule 5: exclude private/reserved/loopback IPs and OID fragments
    ip_m = re.search(r'://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
    if ip_m:
        ip = ip_m.group(1)
        if _is_private_or_reserved_ip(ip):
            return False
        if _is_likely_oid_fragment(ip):
            return False
    # Rule 6: URL must have a meaningful host (length >= 4, e.g. "x.y")
    host = _extract_host(url)
    if not host or len(host) < 4:
        return False
    # Rule 7 (Fix 2): host must be a valid domain — at least 2 dot-separated parts, each >=2 chars
    # Rejects partial template fragments like "api." "graph." "|https" "hostname" "state"
    if "." not in host:
        return False
    parts = host.split(".")
    if any(len(p) < 2 for p in parts):
        return False  # e.g. "api." → ["api", ""] or "x.y" with single-char segment
    if host.endswith("."):
        return False  # trailing dot = incomplete domain
    # Reject hosts containing special characters that indicate code templates
    if any(c in host for c in '|\\<>'):
        return False
    # Rule 8 (Fix 2): reject code template/placeholder URLs
    _PLACEHOLDER_PATTERNS = (
        "hostname", "state/path", "your_", "example", "placeholder",
        "domain.com", "xxx", "foo", "bar", "yourdomain",
        "yourhost", "localhost", "test_url", "dummy",
    )
    low_url = url.lower()
    if any(ph in low_url for ph in _PLACEHOLDER_PATTERNS):
        return False
    return True


def _extract_network_indicators(strings):
    """Extract URLs, IPs, and domains from strings.
    Applies pre-filtering to exclude format strings, namespaces, and special URLs.
    Final C2 filtering is done in _build_c2_servers() via _is_likely_c2_url().
    """
    # URL regex: exclude % and { } to filter format templates at regex level
    url_pattern = re.compile(r'https?://[^\s"\')<>}%{}]+')
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    urls = set()
    ips = set()
    domains = set()

    for s in strings:
        url_matches = url_pattern.findall(s)
        for u in url_matches:
            # Pre-filter: exclude XML namespaces and special URLs early
            if 'schemas.android.com' in u or 'schemas.microsoft.com' in u:
                continue
            if u.lower().startswith(('about:', 'data:', 'javascript:', 'file://', 'mailto:')):
                continue
            urls.add(u)

        ip_matches = ip_pattern.findall(s)
        for ip in ip_matches:
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                ips.add(ip)

        domain_m = re.findall(r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+)', s)
        for d in domain_m:
            if not d.startswith("android.") and not d.startswith("java.") and not d.startswith("schemas.android."):
                domains.add(d)

    return sorted(urls), sorted(ips), sorted(domains)


def _build_c2_servers(urls, ips):
    """Build C2 server entries with strict filtering.
    Only URLs passing _is_likely_c2_url() are included as c2_servers.
    Fix 2: URLs to the same domain are merged into one server record
    with a paths array, reducing c2_servers count significantly.
    """
    # Phase 1: filter and deduplicate URLs
    filtered_urls = []
    seen_urls = set()
    for url in urls:
        if not _is_likely_c2_url(url):
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)
        filtered_urls.append(url)

    # Phase 2: group by domain (or IP for IP-based URLs)
    domain_groups = {}  # domain → {urls: [url1, url2, ...], first_url: str}
    for url in filtered_urls:
        domain = _extract_domain_from_url(url)
        # For IP-based URLs, use the IP as the grouping key
        if not domain:
            ip_m = re.search(r'://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
            group_key = ip_m.group(1) if ip_m else url
        else:
            group_key = domain

        if group_key not in domain_groups:
            domain_groups[group_key] = {
                "urls": [],
                "domain": domain,
                "first_url": url,
            }
        domain_groups[group_key]["urls"].append(url)

    # Phase 3: build merged server records
    servers = []
    for group_key, group in domain_groups.items():
        url = group["first_url"]
        domain = group["domain"]
        all_group_urls = group["urls"]

        ip = ""
        ip_m = re.search(r'://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
        if ip_m:
            ip = ip_m.group(1)

        is_suspicious_domain = _is_suspicious_domain(domain) if domain else True

        # Extract paths from URLs
        paths = []
        for u in all_group_urls:
            # Extract path portion (after host:port)
            path_m = re.match(r'https?://[^/]+(:\d+)?(/.*)?', u)
            if path_m and path_m.group(2):
                paths.append(path_m.group(2))
            else:
                paths.append("/")

        server = {
            "url": url,
            "domain": domain if domain else ip,
            "ip": ip,
            "paths": list(set(paths))[:10],  # unique paths, max 10
            "url_count": len(all_group_urls),
            "protocol": "HTTPS" if url.startswith("https") else "HTTP",
            "is_encrypted": url.startswith("https"),
            "encryption_method": "" if url.startswith("http") else "TLS",
            "request_method": "POST",
            "data_format": "JSON",
            "cleartext": not url.startswith("https"),
            "is_suspicious_domain": is_suspicious_domain,
            "domain_risk": _assess_domain_risk(domain) if domain else "high",
        }
        servers.append(server)
    return servers


def _extract_domain_from_url(url):
    """Extract domain from URL string. Returns "" for IP-only URLs."""
    m = re.match(r'https?://([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+)', url)
    if not m:
        return ""
    domain = m.group(1)
    # 纯 IP 视为 IP，不是域名
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        return ""
    return domain


def _is_suspicious_domain(domain):
    """Heuristic domain suspiciousness check with precise suffix matching.
    Returns False for benign domains (SDK/CDN/cloud/login endpoints).
    """
    if not domain:
        return False
    low = domain.lower()
    # Check against benign SDK domains using precise suffix matching
    for d in _BENIGN_SDK_DOMAINS:
        if low == d or low.endswith('.' + d):
            return False
    # Fallback: benign host keywords (substring, for resilience)
    for kw in _BENIGN_HOST_KEYWORDS:
        if kw in low:
            return False
    return True


def _assess_domain_risk(domain):
    """Assess domain risk level with benign domain awareness."""
    if not domain:
        return "low"
    low = domain.lower()
    # Benign domains → low risk
    for d in _BENIGN_SDK_DOMAINS:
        if low == d or low.endswith('.' + d):
            return "low"
    for kw in _BENIGN_HOST_KEYWORDS:
        if kw in low:
            return "low"
    tld = low.rsplit(".", 1)[-1] if "." in low else ""
    suspicious_tlds = ["tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "icu"]
    if tld in suspicious_tlds:
        return "high"
    if re.match(r'^[a-z0-9]{10,}\.', low):
        return "high"
    return "medium"


def _analyze_communication_pattern():
    """Analyze C2 communication patterns from code."""
    pattern = {
        "uses_http_cleartext": False,
        "uses_https": False,
        "uses_socket_direct_connection": False,
        "uses_http_url_connection": False,
        "uses_dynmaic_url_resolution": False,
        "has_retry_mechanism": False,
        "data_exfiltration_format": "",
    }
    try:
        search_pats = {
            "http://": "uses_http_cleartext",
            "https://": "uses_https",
            "new Socket": "uses_socket_direct_connection",
            "HttpURLConnection": "uses_http_url_connection",
            "URL(" : "uses_dynmaic_url_resolution",
            "retry": "has_retry_mechanism",
        }
        results = search_code_for_pattern(list(search_pats.keys()))
        for pat, field in search_pats.items():
            if results.get(pat):
                pattern[field] = True

        # Check data format
        fmt_pats = ["JSONObject", "ByteArrayOutputStream", "URLSearchParams"]
        fmt_results = search_code_for_pattern(fmt_pats)
        if fmt_results.get("JSONObject"):
            pattern["data_exfiltration_format"] = "JSON封装POST请求"
        elif fmt_results.get("URLSearchParams"):
            pattern["data_exfiltration_format"] = "URL编码表单数据"
        else:
            pattern["data_exfiltration_format"] = "原始字节流"
    except Exception:
        pass
    return pattern


def _find_encrypted_c2_indicators(apk_path, decompiled_dir=""):
    """Find encrypted C2 URL indicators and attempt static decryption.
    
    When decompiled_dir is provided: uses deterministic jadx CLI source (preferred).
    When not available: falls back to jadx MCP search (non-deterministic).
    
    Key fix: ciphertext candidates are collected ONLY from crypto class context
    (same .java file as Cipher.getInstance), NOT from all DEX hex strings.
    This eliminates false positives (hash values, cert fingerprints, constants).
    """
    if decompiled_dir and os.path.isdir(decompiled_dir):
        return _find_encrypted_indicators_from_decompiled(apk_path, decompiled_dir)
    return _find_encrypted_indicators_via_mcp(apk_path)


def _find_encrypted_indicators_from_decompiled(apk_path, decompiled_dir):
    """Deterministic crypto analysis using jadx CLI decompiled source.
    
    Fix A: Each hex string is paired ONLY with algorithms from the SAME .java file
           (not all algorithms globally).
    Fix B: Hex strings whose value matches a known key from the same file are
           identified as keys, not ciphertexts, and are skipped.
    
    1. Find all .java files with Cipher.getInstance (deterministic)
    2. Per-file: extract algorithms, keys, and hex string literals
    3. Filter: skip hex strings that match known key values (Fix B)
    4. Per-file: try each hex string with algorithms from the SAME file (Fix A)
    5. Validate: strict URL/IP pattern matching
    """
    import pathlib
    
    # ── Step 1: Find all crypto classes ──
    crypto_files = []
    sources_dir = os.path.join(decompiled_dir, "sources")
    if not os.path.isdir(sources_dir):
        sources_dir = decompiled_dir
    
    for filepath in pathlib.Path(sources_dir).rglob("*.java"):
        try:
            source = filepath.read_text(encoding="utf-8", errors="ignore")
            if "Cipher.getInstance" in source or "SecretKeySpec" in source:
                crypto_files.append({"path": str(filepath), "source": source})
        except Exception:
            pass
    
    if not crypto_files:
        print("  [!] [EncryptedC2] No crypto classes found in decompiled source")
        return []
    
    print(f"  [+] [EncryptedC2] Found {len(crypto_files)} crypto class(es) in decompiled source")
    
    # ── Step 2: Per-file extraction (Fix A: maintain file-level association) ──
    cipher_re = re.compile(r'Cipher\.getInstance\(\s*"([^"]+)"\s*\)')
    hex_literal_re = re.compile(r'"([0-9a-fA-F]{16,512})"')
    
    file_records = []
    all_byte_keys_global = []  # for XOR fallback (cross-file)
    all_str_keys_global = []   # for XOR fallback (cross-file)
    
    for cf in crypto_files:
        source = cf["source"]
        
        # Extract algorithms from THIS file
        file_algos = list(set(cipher_re.findall(source)))
        
        # Extract string keys from THIS file
        file_str_keys = _extract_crypto_keys_from_source(source)
        
        # Extract byte[] keys and IVs from THIS file
        file_byte_keys, file_byte_ivs = _extract_byte_array_keys_from_source(source)
        
        # Build set of known key values from THIS file — Fix B
        known_key_hex = set()
        known_str_values = set()  # raw string key values (lowercase)
        for kb, _ in file_byte_keys:
            known_key_hex.add(kb.hex())
        for ks, _ in file_str_keys:
            # String key as ASCII-hex encoding
            known_key_hex.add(ks.encode().hex())
            # Also store the raw string value (for direct comparison with hex literals)
            known_str_values.add(ks.lower())
            # If the string IS a hex string, also store its byte form
            if re.match(r'^[0-9a-fA-F]+$', ks) and len(ks) % 2 == 0:
                try:
                    known_key_hex.add(bytes.fromhex(ks).hex())
                except:
                    pass
        
        # Extract hex string literals from THIS file (ciphertext candidates)
        file_hex_strings = []
        for m in hex_literal_re.finditer(source):
            hex_str = m.group(1)
            low = hex_str.lower()
            # Filter: all-zero / all-ff
            if low.strip('0') == '' or low.strip('f') == '':
                continue
            # Fix B: skip known non-ciphertext hex strings (hex digit lookup tables)
            if low in _KNOWN_NON_CIPHERTEXT_HEX or hex_str in _KNOWN_NON_CIPHERTEXT_HEX:
                continue
            # Fix B: skip if this hex string IS a known key value (direct or encoded)
            if low in known_key_hex or hex_str in known_key_hex:
                continue
            # Fix B: skip if this hex string matches a string key value directly
            if low in known_str_values or hex_str in known_str_values:
                continue
            # Fix B: skip if decoding this hex string as bytes matches any byte[] key
            try:
                ct_bytes = bytes.fromhex(hex_str)
                if any(ct_bytes == kb for kb, _ in file_byte_keys):
                    continue
            except:
                pass
            # Filter: skip hash-length strings unless file has doFinal/decrypt
            if len(hex_str) in (32, 40, 64) and "doFinal" not in source and "decrypt" not in source.lower():
                continue
            file_hex_strings.append(hex_str)
        
        if file_algos or file_hex_strings or file_byte_keys:
            file_records.append({
                "path": cf["path"],
                "algorithms": file_algos,
                "str_keys": file_str_keys,
                "byte_keys": file_byte_keys,
                "byte_ivs": file_byte_ivs,
                "hex_strings": file_hex_strings,
                "has_decrypt": "doFinal" in source or "decrypt" in source.lower(),
            })
        
        # Accumulate global pools for XOR fallback
        all_byte_keys_global.extend(file_byte_keys)
        all_str_keys_global.extend(file_str_keys)
        
        # Also check Class.forName referenced classes
        for ref in re.findall(r'Class\.forName\("([^"]+)"\)', source):
            ref_path = ref.replace(".", "/") + ".java"
            ref_filepath = os.path.join(sources_dir, ref_path)
            if os.path.isfile(ref_filepath):
                try:
                    ref_source = pathlib.Path(ref_filepath).read_text(encoding="utf-8", errors="ignore")
                    extra_str = _extract_crypto_keys_from_source(ref_source)
                    extra_byte, extra_iv = _extract_byte_array_keys_from_source(ref_source)
                    file_str_keys.extend(extra_str)
                    file_byte_keys.extend(extra_byte)
                    file_byte_ivs.extend(extra_iv)
                    all_byte_keys_global.extend(extra_byte)
                    all_str_keys_global.extend(extra_str)
                    # Add hex strings from referenced class
                    for m in hex_literal_re.finditer(ref_source):
                        hex_str = m.group(1)
                        low = hex_str.lower()
                        if low.strip('0') != '' and low.strip('f') != '':
                            if low not in known_key_hex and hex_str not in known_key_hex:
                                file_hex_strings.append(hex_str)
                except Exception:
                    pass
    
    # Summary
    total_hex = sum(len(r["hex_strings"]) for r in file_records)
    total_algos = set()
    for r in file_records:
        total_algos.update(r["algorithms"])
    print(f"  [+] [EncryptedC2] Files: {len(file_records)}, algorithms: {sorted(total_algos)}")
    print(f"  [+] [EncryptedC2] Per-file ciphertexts: {total_hex} (after key-value filtering)")
    
    if total_hex == 0:
        print("  [+] [EncryptedC2] No ciphertext candidates found (all filtered as keys/hash)")
        return []
    
    # ── Step 3: Per-file decryption (Fix A: algorithm-ciphertext association) ──
    url_re = re.compile(r'^https?://', re.IGNORECASE)
    indicators = []
    
    for record in file_records:
        file_algos = record["algorithms"]
        file_hex_strings = record["hex_strings"]
        file_str_keys = record["str_keys"]
        file_byte_keys = record["byte_keys"]
        file_byte_ivs = record["byte_ivs"]
        
        if not file_hex_strings:
            continue
        
        for ct_hex in sorted(set(file_hex_strings)):
            try:
                raw = bytes.fromhex(ct_hex)
            except ValueError:
                continue
            if len(raw) < 8:
                continue
            
            best_entry = None
            
            # Try ONLY algorithms from THIS file (Fix A)
            for algo_str in file_algos:
                algo, mode, padding = _parse_cipher_algorithm(algo_str)
                if not algo:
                    continue
                
                # Skip RSA (asymmetric, can't brute-force)
                if algo == "RSA":
                    continue
                
                key_len = 8 if algo == "DES" else 16 if algo == "AES" else 0
                if not key_len:
                    continue
                
                # Build key candidates from THIS file + common keys
                key_candidates = []
                for kb, _ in file_byte_keys:
                    if len(kb) == key_len:
                        key_candidates.append(kb)
                for ks, _ in file_str_keys:
                    kb = _derive_key(ks, key_len)
                    key_candidates.append(kb)
                    if algo == "AES":
                        for kl in (24, 32):
                            kb2 = _derive_key(ks, kl)
                            key_candidates.append(kb2)
                # Common keys
                common = _COMMON_DES_KEYS if algo == "DES" else _COMMON_AES_KEYS
                key_candidates.extend(common)
                
                iv_candidates = [kb for kb, _ in file_byte_ivs]
                
                try:
                    pt = _try_decrypt(ct_hex, algo, mode, key_candidates, padding=padding, iv_candidates=iv_candidates)
                    if pt and _is_valid_decryption(pt, url_re):
                        best_entry = {
                            "encryption_algorithm": f"{algo}/{mode}/{padding}" if algo in ("DES", "AES") else algo,
                            "ciphertext_sample": ct_hex[:64] if len(ct_hex) > 64 else ct_hex,
                            "decrypted_result": pt,
                            "purpose": _classify_decryption_result(pt, url_re),
                            "key_or_pattern": "反编译源码提取",
                        }
                        break
                except Exception:
                    continue
            
            # XOR fallback (cross-file key pool)
            if best_entry is None:
                xor_pool = [kb for kb, _ in all_byte_keys_global]
                xor_pool.extend([ks.encode() for ks, _ in all_str_keys_global])
                try:
                    pt = _try_xor_decrypt(ct_hex, xor_pool)
                    if pt and _is_valid_decryption(pt, url_re):
                        best_entry = {
                            "encryption_algorithm": "XOR",
                            "ciphertext_sample": ct_hex[:64] if len(ct_hex) > 64 else ct_hex,
                            "decrypted_result": pt,
                            "purpose": _classify_decryption_result(pt, url_re),
                            "key_or_pattern": "反编译源码byte[]密钥",
                        }
                except Exception:
                    pass
            
            # Record result
            if best_entry is None:
                # Skip hash-length strings that failed
                if len(ct_hex) in (32, 40, 64):
                    continue
                best_entry = {
                    "encryption_algorithm": file_algos[0] if file_algos else "未知",
                    "ciphertext_sample": ct_hex[:64] if len(ct_hex) > 64 else ct_hex,
                    "decrypted_result": "",
                    "purpose": "C2服务器地址",
                    "key_or_pattern": "反编译源码未匹配密钥",
                }
            
            indicators.append(best_entry)
    
    print(f"  [+] [EncryptedC2] Results: {len(indicators)} indicators "
          f"({sum(1 for i in indicators if i.get('decrypted_result'))} decrypted)")
    return indicators


def _find_encrypted_indicators_via_mcp(apk_path):
    """Find encrypted C2 URL indicators and attempt static decryption.
    Strategy:
      1. Locate candidate crypto classes via jadx MCP keyword search.
      2. For each candidate class, parse Cipher.getInstance("...") to identify
         algorithm + mode + padding.
      3. Extract hardcoded key strings AND byte[] key arrays from the same class.
      4. Collect all (algorithm, mode, padding, key_candidates, iv_candidates) tuples.
      5. Extract hex-looking strings from DEX as candidate ciphertexts.
      6. For each ciphertext × each combo, attempt decryption.
      7. If symmetric decryption fails, also try XOR with the same key candidates.
      8. Record results with real decrypted_result and key_or_pattern.
    Fallback: if jadx MCP or decryption fails, still record ciphertext with empty decrypted_result.
    """
    indicators = []
    try:
        # ── Step 1: locate candidate crypto classes ──
        candidate_classes = set()
        for term in ("Cipher.getInstance", "SecretKeySpec", "javax.crypto.Cipher"):
            try:
                hits = search_classes_by_keyword(term, search_in="code", count=50)
                if isinstance(hits, list):
                    for h in hits:
                        # jadx MCP returns list of class name strings (not dicts)
                        if isinstance(h, str):
                            cn = h
                        elif isinstance(h, dict):
                            cn = h.get("class_name") or h.get("name") or h.get("class") or ""
                        else:
                            cn = str(h)
                        if cn:
                            candidate_classes.add(cn)
            except Exception:
                pass

        # ── Step 2: gather (algorithm, mode, padding, keys, ivs) per class source ──
        cipher_instance_re = re.compile(r'Cipher\.getInstance\(\s*"([^"]+)"\s*\)')
        # crypto_combos entries:
        #   (algorithm, mode, padding, str_keys:list[(str,hint)], byte_keys:list[(bytes,hint)],
        #    byte_ivs:list[(bytes,hint)], source_class)
        crypto_combos = []
        seen_combos = set()

        # Global pool of all byte[] keys/ivs across classes (for XOR fallback)
        all_byte_keys = []
        all_byte_ivs = []
        all_str_keys = []

        for cn in candidate_classes:
            try:
                src = get_class_source(cn) or ""
            except Exception:
                src = ""
            if not src:
                continue
            # Parse all Cipher.getInstance("...") calls in this class
            algo_matches = cipher_instance_re.findall(src)
            if not algo_matches:
                continue
            # Extract string keys AND byte[] keys/ivs from this class source
            str_keys_here = _extract_crypto_keys_from_source(src)
            byte_keys_here, byte_ivs_here = _extract_byte_array_keys_from_source(src)

            # Update global pools (dedup by value)
            for k, hint in byte_keys_here:
                if k not in [b for b, _ in all_byte_keys]:
                    all_byte_keys.append((k, hint))
            for k, hint in byte_ivs_here:
                if k not in [b for b, _ in all_byte_ivs]:
                    all_byte_ivs.append((k, hint))
            for k, hint in str_keys_here:
                if k not in [s for s, _ in all_str_keys]:
                    all_str_keys.append((k, hint))

            for algo_str in algo_matches:
                algo, mode, padding = _parse_cipher_algorithm(algo_str)
                if not algo:
                    continue
                combo_key = (algo, mode, padding)
                if combo_key in seen_combos and not (str_keys_here or byte_keys_here):
                    continue
                seen_combos.add(combo_key)
                crypto_combos.append((algo, mode, padding, str_keys_here,
                                       byte_keys_here, byte_ivs_here, cn))

        # ── Step 3: collect hex-looking strings as candidate ciphertexts ──
        all_strings_raw = _extract_all_strings(apk_path)
        hex_re = re.compile(r'^[0-9a-fA-F]{16,}$')
        # Block size in hex chars: DES=16, AES=32, RC4=any
        # Filter out obvious hash-length strings (MD5=32, SHA1=40, SHA256=64) only when
        # they exactly match those lengths AND we have no DES/AES combos to try
        # (since DES blocks are 16 hex = 8 bytes, AES blocks are 32 hex = 16 bytes,
        # which collide with MD5/SHA256 lengths). Keep them; let decryption decide.
        candidate_cts = []
        seen_ct = set()
        for s in all_strings_raw:
            if not s or len(s) < 16 or len(s) > 512:
                continue
            if not hex_re.match(s):
                continue
            # Normalize to lowercase for dedup
            cl = s.lower()
            if cl in seen_ct:
                continue
            # Skip all-zero or all-ff strings (definitely not ciphertext)
            if cl.strip('0') == '' or cl.strip('f') == '':
                continue
            seen_ct.add(cl)
            candidate_cts.append(s)

        # ── Step 4: attempt decryption for each ciphertext × each combo ──
        url_re = re.compile(r'^https?://', re.IGNORECASE)
        # Cap iterations to avoid explosion: max 200 ciphertexts × max 30 combos
        max_ct = 200
        max_combos = 30
        combos_to_try = crypto_combos[:max_combos]

        # Build XOR key candidate pool (byte[] keys first, then derived string keys)
        # Used when all symmetric decryption fails for a given ciphertext.
        xor_key_pool = []
        for kb, _hint in all_byte_keys:
            if kb and kb not in xor_key_pool:
                xor_key_pool.append(kb)
        for ks, _hint in all_str_keys:
            kb = ks.encode('utf-8')
            if kb and kb not in xor_key_pool:
                xor_key_pool.append(kb)

        # Time budget: stop processing after DECRYPT_TIME_BUDGET seconds
        # to avoid pipeline timeout. Return partial results.
        DECRYPT_TIME_BUDGET = 400  # seconds
        decrypt_start_time = time.time()

        for ct in candidate_cts[:max_ct]:
            # Check time budget — break if exceeded
            if time.time() - decrypt_start_time > DECRYPT_TIME_BUDGET:
                break
            best_entry = None
            for combo in combos_to_try:
                algo, mode, padding, str_keys_here, byte_keys_here, byte_ivs_here, source_class = combo
                if not (str_keys_here or byte_keys_here):
                    continue
                # Derive key bytes for this algorithm
                if algo == "DES":
                    key_len = 8
                elif algo == "AES":
                    # Try AES-128 first (most common); fall back to 192/256
                    key_len = 16
                elif algo == "RC4":
                    key_len = len(str_keys_here[0][0].encode('utf-8')) if str_keys_here else 16
                else:
                    continue

                # Build candidate_keys list: byte[] keys first (exact length match),
                # then string-derived keys (padded/truncated to key_len).
                candidate_keys = []
                # Use byte[] keys as-is (they are already raw bytes)
                for kb, _hint in byte_keys_here:
                    if algo == "DES" and len(kb) == 8:
                        candidate_keys.append(kb)
                    elif algo == "AES" and len(kb) in (16, 24, 32):
                        candidate_keys.append(kb)
                    elif algo == "RC4":
                        candidate_keys.append(kb)

                # Build iv_candidates from byte[] IVs in this class
                iv_candidates = [kb for kb, _hint in byte_ivs_here]

                # Try each string key individually so we can record which one worked
                plaintext = ""
                working_key = ""
                working_hint = ""
                for ks, hint in str_keys_here:
                    kb = _derive_key(ks, key_len)
                    cand = [kb]
                    # Also try AES-192/256 variants for the same key string
                    if algo == "AES":
                        for kl in (24, 32):
                            kb2 = _derive_key(ks, kl)
                            if kb2 not in cand:
                                cand.append(kb2)
                    pt = _try_decrypt(ct, algo, mode, cand,
                                       padding=padding, iv_candidates=iv_candidates)
                    if pt:
                        plaintext = pt
                        working_key = ks
                        working_hint = hint
                        break

                # If no string key worked, try the byte[] keys
                if not plaintext and candidate_keys:
                    pt = _try_decrypt(ct, algo, mode, candidate_keys,
                                       padding=padding, iv_candidates=iv_candidates)
                    if pt:
                        plaintext = pt
                        working_key = "硬编码byte[]密钥"
                        working_hint = "byte[]"

                if plaintext:
                    # Determine purpose based on plaintext content
                    if url_re.match(plaintext):
                        purpose = "C2服务器地址"
                    elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', plaintext):
                        purpose = "C2服务器地址"
                    elif '/' in plaintext or '?' in plaintext or '=' in plaintext:
                        purpose = "配置参数/路径片段"
                    else:
                        purpose = "加密配置字符串"
                    algo_str_out = f"{algo}/{mode}/{padding}" if algo in ("DES", "AES") else algo
                    best_entry = {
                        "encryption_algorithm": algo_str_out,
                        "ciphertext_sample": ct[:64] if len(ct) > 64 else ct,
                        "decrypted_result": plaintext,
                        "purpose": purpose,
                        "key_or_pattern": working_key,
                    }
                    break  # stop trying other combos for this ciphertext

            # ── Step 5: XOR fallback if all symmetric decryption failed ──
            if best_entry is None and xor_key_pool:
                pt = _try_xor_decrypt(ct, xor_key_pool)
                if pt and (url_re.match(pt) or '/' in pt or '=' in pt or '?' in pt):
                    if url_re.match(pt):
                        purpose = "C2服务器地址"
                    elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', pt):
                        purpose = "C2服务器地址"
                    elif '/' in pt or '?' in pt or '=' in pt:
                        purpose = "配置参数/路径片段"
                    else:
                        purpose = "加密配置字符串"
                    best_entry = {
                        "encryption_algorithm": "XOR",
                        "ciphertext_sample": ct[:64] if len(ct) > 64 else ct,
                        "decrypted_result": pt,
                        "purpose": purpose,
                        "key_or_pattern": "硬编码byte[]密钥",
                    }

            if best_entry is None:
                # ── Fix 3 Step 6: Try common default keys ──
                # When key extraction failed, try known default keys for detected algorithms
                if combos_to_try and not best_entry:
                    for combo in combos_to_try[:5]:
                        algo, mode, padding, _sk, _bk, _bi, _cn = combo
                        common_keys = _COMMON_DES_KEYS if algo == "DES" else _COMMON_AES_KEYS if algo == "AES" else []
                        if not common_keys:
                            continue
                        try:
                            pt = _try_decrypt(ct, algo, mode, common_keys, padding=padding)
                            if pt and _is_valid_decryption(pt, url_re):
                                best_entry = {
                                    "encryption_algorithm": f"{algo}/{mode}/{padding}" if algo in ("DES", "AES") else algo,
                                    "ciphertext_sample": ct[:64] if len(ct) > 64 else ct,
                                    "decrypted_result": pt,
                                    "purpose": _classify_decryption_result(pt, url_re),
                                    "key_or_pattern": "常见默认密钥",
                                }
                                break
                        except Exception:
                            continue

                # ── Fix 3 Step 7: DEX string brute-force for DES and AES keys ──
                if best_entry is None and combos_to_try:
                    des_combos = [c for c in combos_to_try if c[0] == "DES"]
                    aes_combos = [c for c in combos_to_try if c[0] == "AES"]
                    if des_combos:
                        brute_keys = _extract_brute_force_keys(all_strings_raw, key_len=8, max_count=200)
                        if brute_keys:
                            for combo in des_combos[:3]:
                                algo, mode, padding = combo[0], combo[1], combo[2]
                                try:
                                    pt = _try_decrypt(ct, algo, mode, brute_keys, padding=padding)
                                    if pt and _is_valid_decryption(pt, url_re):
                                        best_entry = {
                                            "encryption_algorithm": f"{algo}/{mode}/{padding}",
                                            "ciphertext_sample": ct[:64] if len(ct) > 64 else ct,
                                            "decrypted_result": pt,
                                            "purpose": _classify_decryption_result(pt, url_re),
                                            "key_or_pattern": "DEX字符串暴力尝试",
                                        }
                                        break
                                except Exception:
                                    continue
                    if best_entry is None and aes_combos:
                        # Try AES with 16-byte brute-force keys
                        brute_aes_keys = _extract_brute_force_keys(all_strings_raw, key_len=16, max_count=200)
                        if brute_aes_keys:
                            for combo in aes_combos[:3]:
                                algo, mode, padding = combo[0], combo[1], combo[2]
                                try:
                                    pt = _try_decrypt(ct, algo, mode, brute_aes_keys, padding=padding)
                                    if pt and _is_valid_decryption(pt, url_re):
                                        best_entry = {
                                            "encryption_algorithm": f"{algo}/{mode}/{padding}",
                                            "ciphertext_sample": ct[:64] if len(ct) > 64 else ct,
                                            "decrypted_result": pt,
                                            "purpose": _classify_decryption_result(pt, url_re),
                                            "key_or_pattern": "DEX字符串暴力尝试",
                                        }
                                        break
                                except Exception:
                                    continue

            if best_entry is None:
                # Final fallback: record ciphertext without decryption
                fallback_algo = ""
                if combos_to_try:
                    a, m, p, _sk, _bk, _bi, _cn = combos_to_try[0]
                    fallback_algo = f"{a}/{m}/{p}" if a in ("DES", "AES") else a
                ct_len = len(ct)
                if ct_len in (32, 40, 64) and combos_to_try:
                    continue  # Skip likely hash strings
                best_entry = {
                    "encryption_algorithm": fallback_algo or "未知",
                    "ciphertext_sample": ct[:64] if len(ct) > 64 else ct,
                    "decrypted_result": "",
                    "purpose": "C2服务器地址",
                    "key_or_pattern": "密钥提取失败：正则提取+常见密钥+DEX暴力均未命中" if combos_to_try else "未检测到加解密类",
                }

            indicators.append(best_entry)

    except Exception:
        pass
    return indicators



def _detect_c2_command_categories():
    """Detect C2 command categories from code."""
    categories = []
    try:
        cmd_indicators = {
            "device_info_collection": ["getDeviceId", "Build.MODEL"],
            "sms_operations": ["SmsManager", "SMS_RECEIVED"],
            "file_operations": ["FileOutputStream", "FileInputStream"],
            "contact_operations": ["ContactsContract", "getContacts"],
            "location_tracking": ["LocationManager", "getLocation"],
            "command_download": ["HttpURLConnection", "download"],
        }
        all_pats = [p for pl in cmd_indicators.values() for p in pl]
        results = search_code_for_pattern(all_pats)
        for cat, pats in cmd_indicators.items():
            if any(results.get(p) for p in pats):
                categories.append(cat)
    except Exception:
        pass
    return categories


def _is_valid_decryption(plaintext, url_re):
    """Fix 3: Validate that a decrypted result is meaningful.
    Accepts if it contains a URL, IP, domain pattern, or is printable text >4 chars.
    """
    if not plaintext or len(plaintext) < 3:
        return False
    # URL pattern
    if url_re.match(plaintext):
        return True
    # IP address pattern
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', plaintext):
        return True
    # Contains path-like patterns (/path?param=)
    if '/' in plaintext and ('=' in plaintext or '?' in plaintext):
        return True
    # Printable ASCII text with at least 4 chars (no control chars)
    if len(plaintext) >= 5:
        ctrl = sum(1 for c in plaintext if ord(c) < 0x20 and c not in '\t\n\r')
        if ctrl == 0 and all(0x20 <= ord(c) < 0x7f or c in '\t\n\r' for c in plaintext):
            return True
    return False


def _classify_decryption_result(plaintext, url_re):
    """Fix 3: Classify the purpose of a decrypted result."""
    if url_re.match(plaintext):
        return "C2服务器地址"
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', plaintext):
        return "C2服务器地址"
    if '/' in plaintext or '?' in plaintext or '=' in plaintext:
        return "配置参数/路径片段"
    return "加密配置字符串"


def _extract_brute_force_keys(all_strings, key_len=8, max_count=200):
    """Fix 3: Extract candidate keys of specified length from DEX strings.
    key_len=8 for DES, key_len=16 for AES-128.
    Looks for hex strings of key_len*2 chars (= key_len bytes).
    Limited to max_count to avoid performance issues.
    """
    keys = []
    seen = set()
    hex_len = key_len * 2
    hex_re = re.compile(r'^[0-9a-fA-F]{%d}$' % hex_len)
    for s in all_strings:
        if len(keys) >= max_count:
            break
        if not s or len(s) != hex_len:
            continue
        if hex_re.match(s):
            try:
                kb = bytes.fromhex(s)
                if kb not in seen:
                    seen.add(kb)
                    keys.append(kb)
            except ValueError:
                pass
    return keys


def _detect_c2_commands():
    """Detect specific C2 commands from code."""
    commands = []
    try:
        # Look for command dispatchers
        cmd_search = search_code_for_pattern(["switch", "case ", "equals(", "==" ])
        # Common command patterns in APKs
        cmd_patterns = [
            ("get_device_info", "collect_device_info", "收集设备信息并回传"),
            ("send_sms_cmd", "send_sms", "通过恶意APK发送短信"),
            ("upload_file", "upload_file", "上传文件到远端"),
            ("download_cmd", "download_payload", "下载远程Payload"),
        ]
        for cmd_id, action, desc in cmd_patterns:
            found = search_code_for_pattern([cmd_id])
            if any(found.values()):
                commands.append({"command_id": cmd_id, "action": action, "description": desc})
    except Exception:
        pass
    return commands


# ── Crypto decryption helpers ──────────────────────────────────────────────────

def _derive_key(key_str: str, key_len: int) -> bytes:
    """Mimic Java JUtils.getKey(): take first key_len bytes, pad with 0x00 if short."""
    raw = key_str.encode('utf-8')
    if len(raw) >= key_len:
        return raw[:key_len]
    return raw + b'\x00' * (key_len - len(raw))


def _is_printable_utf8(data: bytes) -> bool:
    """Heuristic: a valid plaintext should be UTF-8 decodable and free of NUL/control bytes."""
    if b'\x00' in data:
        return False
    try:
        s = data.decode('utf-8')
    except UnicodeDecodeError:
        return False
    # Reject if too many control chars (allow common whitespace \t\n\r)
    ctrl = sum(1 for c in s if ord(c) < 0x20 and c not in '\t\n\r')
    return ctrl == 0 and len(s) > 0


def _try_xor_decrypt(ciphertext_hex: str, key_candidates: list) -> str:
    """XOR decryption: ciphertext_hex XOR'd byte-by-byte with each candidate key.
    Returns plaintext string on success, "" on failure.
    Used for simple XOR-based string obfuscation (e.g. com.intsig.e.d fallback).
    """
    try:
        raw = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return ""
    if not raw:
        return ""
    for key in key_candidates:
        if not key:
            continue
        try:
            kl = len(key)
            pt = bytes(raw[i] ^ key[i % kl] for i in range(len(raw)))
            if _is_printable_utf8(pt):
                return pt.decode('utf-8')
        except Exception:
            continue
    return ""


def _try_decrypt(ciphertext_hex: str, algorithm: str, mode: str,
                 key_candidates: list, padding: str = "PKCS5Padding",
                 iv_candidates: list = None) -> str:
    """Try decrypting ciphertext_hex with each candidate key.
    Returns plaintext string on success, "" on failure.
    algorithm: "DES" | "AES" | "RC4"
    mode: "ECB" | "CBC" | "CFB" | "CFB8" | ""
    padding: "PKCS5Padding" | "PKCS7Padding" | "NoPadding" | ""
    key_candidates: list[bytes] (already derived to correct length)
    iv_candidates: optional list[bytes] for non-ECB modes (default = zeros or first-block-as-IV)
    """
    try:
        raw = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return ""

    if not raw:
        return ""

    # Lazy import to avoid hard dependency at module load
    try:
        from Crypto.Cipher import DES, AES, ARC4
        from Crypto.Util.Padding import unpad
    except ImportError:
        return ""

    use_unpad = padding in ("PKCS5Padding", "PKCS7Padding")

    for key in key_candidates:
        try:
            if algorithm == "DES":
                if len(raw) % 8 != 0 or len(key) != 8:
                    continue
                if mode == "ECB":
                    pt = DES.new(key, DES.MODE_ECB).decrypt(raw)
                elif mode == "CBC":
                    iv = b'\x00' * 8
                    if iv_candidates:
                        for ivc in iv_candidates:
                            if len(ivc) == 8:
                                iv = ivc
                                break
                    pt = DES.new(key, DES.MODE_CBC, iv).decrypt(raw)
                elif mode in ("CFB", "CFB8"):
                    # DES/CFB8/NoPadding: PyCryptodome DES.MODE_CFB with segment_size=8
                    iv = b'\x00' * 8
                    if iv_candidates:
                        for ivc in iv_candidates:
                            if len(ivc) == 8:
                                iv = ivc
                                break
                    pt = DES.new(key, DES.MODE_CFB, iv, segment_size=8).decrypt(raw)
                    use_unpad = False  # CFB is a stream cipher, no padding
                else:
                    continue
                if use_unpad:
                    try:
                        pt = unpad(pt, 8)
                    except ValueError:
                        continue
            elif algorithm == "AES":
                if len(raw) % 16 != 0 or len(key) not in (16, 24, 32):
                    continue
                if mode == "ECB":
                    pt = AES.new(key, AES.MODE_ECB).decrypt(raw)
                elif mode == "CBC":
                    iv = b'\x00' * 16
                    if iv_candidates:
                        for ivc in iv_candidates:
                            if len(ivc) == 16:
                                iv = ivc
                                break
                    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(raw)
                else:
                    continue
                if use_unpad:
                    try:
                        pt = unpad(pt, 16)
                    except ValueError:
                        continue
                # NoPadding: strip trailing 0x00 bytes if all remaining bytes are printable
                if padding == "NoPadding" and pt:
                    stripped = pt.rstrip(b'\x00')
                    if stripped and _is_printable_utf8(stripped):
                        return stripped.decode('utf-8')
            elif algorithm == "RC4":
                pt = ARC4.new(key).decrypt(raw)
            else:
                continue

            if _is_printable_utf8(pt):
                return pt.decode('utf-8')
        except Exception:
            continue
    return ""


# Patterns to extract hardcoded key strings from decompiled Java source
_KEY_STRING_PATTERNS = [
    # static field assignment: strDefaultKey = "national"
    re.compile(r'\b\w+\s*=\s*"([^"]{1,64})"\s*;'),
    # constructor call with string literal: new JUtils("TEST") or JUtils("TEST")
    re.compile(r'new\s+\w+\s*\(\s*"([^"]{1,64})"\s*\)'),
    re.compile(r'\bJUtils\s*\(\s*"([^"]{1,64})"\s*\)'),
    # explicit key methods: getKey("..."), init(..., "...")
    re.compile(r'\bgetKey\s*\(\s*"([^"]{1,64})"\s*\)'),
    re.compile(r'\bSecretKeySpec\s*\([^,]+,\s*"([^"]+)"\s*\)'),
    # Fix 3: additional patterns
    # Base64 encoded key: Base64.decode("...") or Base64.getDecoder().decode("...")
    re.compile(r'Base64\.(?:getDecoder\(\)\.)?decode\(\s*"([^"]{4,128})"'),
    # Hex string key: key = "0123456789ABCDEF"
    re.compile(r'\b\w+\s*=\s*"([0-9a-fA-F]{8,64})"\s*;'),
    # String concatenation key: String key = "ab" + "cd" + "ef"
    re.compile(r'String\s+\w+\s*=\s*"([^"]+)"\s*\+\s*"([^"]+)"'),
    # init() with string key parameter
    re.compile(r'\binit\s*\(\s*\d+\s*,\s*"([^"]{1,64})"\s*\)'),
    # put("key", "...") pattern
    re.compile(r'put\s*\(\s*"\w*key\w*"\s*,\s*"([^"]{1,64})"\s*\)', re.IGNORECASE),
    # Fix B: "string".getBytes() pattern — key stored as string then converted to bytes
    re.compile(r'"([^"]{4,64})"\s*\.getBytes\s*\('),
]

# Variable name hints near key literals (lower-priority fallback)
_KEY_VAR_HINTS = ('key', 'secret', 'passwd', 'password', 'token', 'seed')

# Fix 3: Common default keys used by packers/malware (tried when extraction fails)
_COMMON_DES_KEYS = [
    b"TEST", b"12345678", b"password", b"default",
    b"abcdefgh", b"\x00\x00\x00\x00\x00\x00\x00\x00",
    b"intsig", b"camscan", b"intsig\x00",
    b"jiami", b"shell", b"secret", b"key1234",
    b"android", b"mykey12", b"admin12",
]

# Fix B: Hex strings that are NOT ciphertext — standard hex digit lookup tables, etc.
_KNOWN_NON_CIPHERTEXT_HEX = {
    "0123456789abcdef", "0123456789ABCDEF",  # hex digit lookup tables
    "0123456789abcdef0123456789abcdef",      # repeated hex digits
}
_COMMON_AES_KEYS = [
    b"0123456789abcdef", b"1234567890abcdef",
    b"\x00" * 16, b"android" + b"\x00" * 9,
    b"1234567890123456", b"abcdefghijklmnop",
    b"0123456789ABCDEF", b"ABCDEFGHIJKLMNOP",
    b"camscanner123456", b"intsig1234567890",
    b"12345678901234567890123456789012",  # 32-byte AES-256
    b"\x00" * 32,
    b"secr" + b"\x00" * 12,
    b"thisisakey123456", b"thisiskey1234567",
    b"1234123412341234", b"mysecretkey12345",
]


def _extract_crypto_keys_from_source(source: str) -> list:
    """Extract candidate key strings from decompiled Java source.
    Returns list of (key_str, source_hint) tuples, deduped, order-preserved.
    NOTE: For byte[] key arrays, see _extract_byte_array_keys_from_source().
    """
    if not source:
        return []
    found = []
    seen = set()

    # Primary patterns
    for pat in _KEY_STRING_PATTERNS:
        for m in pat.finditer(source):
            ks = m.group(1)
            if ks and ks not in seen and len(ks) >= 1:
                # Skip obvious non-keys: algorithm names, common words
                if ks.lower() in ('des', 'aes', 'rc4', 'rsa', 'utf-8', 'utf8',
                                  'des/ecb/pkcs5padding', 'aes/cbc/pkcs5padding'):
                    continue
                seen.add(ks)
                found.append((ks, f"pattern:{pat.pattern[:30]}"))

    # Fallback: any string literal assigned to a variable whose name hints at key
    # Matches: String key = "abc";  or  String secretKey = "xyz";
    fallback_pat = re.compile(
        r'\b(?:String|byte\[\])\s+(\w*(?:key|secret|passwd|password|token|seed)\w*)\s*=\s*"([^"]{1,64})"\s*;',
        re.IGNORECASE
    )
    for m in fallback_pat.finditer(source):
        var_name, ks = m.group(1), m.group(2)
        if ks and ks not in seen:
            seen.add(ks)
            found.append((ks, f"var:{var_name}"))

    return found


# Patterns to extract hardcoded byte[] key arrays from decompiled Java source.
# Three tiers of matching:
#   Tier 1: static final byte[] with key-length elements (8/16/24/32) — any var name
#   Tier 2: static final byte[] with IV-length elements (8/16) — any var name
#   Tier 3: non-static byte[] with key-hint variable name (key/secret/iv/passwd/token/seed)
#
# Matches both forms:
#   byte[] key = { 1, 2, 3, 4, 5, 6, 7, 8 };                 (jadx default)
#   byte[] key = new byte[]{ (byte)0x01, (byte)0x02, ... };  (explicit cast form)
#   public static final byte[] a = {-59, 6, -122, 86, ...};  (obfuscated var name)

# Tier 1+2: static final byte[] — captures ANY variable name (including obfuscated like 'a', 'b')
# The key/IV length filtering is done post-extraction in _extract_byte_array_keys_from_source()
_BYTE_ARRAY_STATIC_FINAL_RE = re.compile(
    r'(?:public\s+)?(?:static\s+)?(?:final\s+)?byte\[\]\s+(\w+)\s*=\s*(?:new\s+byte\[\]\s*)?\{([^}]+)\}\s*;',
    re.IGNORECASE
)

# Tier 3: non-static byte[] with key-hint variable name (lower confidence)
_BYTE_ARRAY_NONSTATIC_HINTED_RE = re.compile(
    r'\bbyte\[\]\s+(\w*(?:key|secret|iv|passwd|password|token|seed)\w*)\s*=\s*(?:new\s+byte\[\]\s*)?\{([^}]+)\}\s*;',
    re.IGNORECASE
)

# Valid key lengths in bytes (for filtering Tier 1 candidates)
_VALID_KEY_LENGTHS = (8, 16, 24, 32)
# Valid IV lengths in bytes (for filtering Tier 2 candidates)
_VALID_IV_LENGTHS = (8, 16)


def _parse_byte_array_literal(body: str) -> bytes:
    """Parse the body of a Java byte[] literal into bytes.
    Accepts: "1, 2, 3" or "(byte)0x01, (byte)0x02" or "0x01, 0xff, 0x10".
    Returns b"" on parse error.
    """
    if not body:
        return b""
    parts = re.split(r'[,\s]+', body.strip())
    out = bytearray()
    for p in parts:
        if not p:
            continue
        p = p.replace('(byte)', '').strip()
        try:
            if p.lower().startswith('0x'):
                v = int(p, 16)
            else:
                v = int(p)
            # Java byte is signed (-128..127); convert to unsigned 0..255
            if v < 0:
                v = v & 0xFF
            if 0 <= v <= 255:
                out.append(v)
        except ValueError:
            continue
    return bytes(out)


def _extract_byte_array_keys_from_source(source: str) -> tuple:
    """Extract hardcoded byte[] key/iv arrays from decompiled Java source.
    Uses 3-tier matching:
      Tier 1: static final byte[] with key-length elements (8/16/24/32) — any var name
      Tier 2: static final byte[] with IV-length elements (8/16) — any var name
      Tier 3: non-static byte[] with key-hint variable name (key/secret/iv/passwd/token/seed)
    Returns (key_list, iv_list) where each is list of (bytes, hint).
    """
    if not source:
        return [], []
    keys_found = []
    ivs_found = []
    seen_keys = set()
    seen_ivs = set()

    # Tier 1+2: scan all static final byte[] arrays, filter by element count
    for m in _BYTE_ARRAY_STATIC_FINAL_RE.finditer(source):
        var_name = m.group(1)
        body = m.group(2)
        data = _parse_byte_array_literal(body)
        if not data:
            continue
        # Classify by length: key-length → key pool, IV-length → IV pool
        # Note: 8 and 16 overlap (DES key=8, DES IV=8, AES key=16, AES IV=16)
        # For overlapping lengths, add to BOTH pools if variable name hints at IV
        low_name = var_name.lower()
        is_iv_hint = 'iv' in low_name or 'vector' in low_name
        if len(data) in _VALID_KEY_LENGTHS:
            if data not in seen_keys:
                seen_keys.add(data)
                keys_found.append((data, f"byte[]:{var_name}(len={len(data)})"))
        if is_iv_hint and len(data) in _VALID_IV_LENGTHS:
            if data not in seen_ivs:
                seen_ivs.add(data)
                ivs_found.append((data, f"byte[]:{var_name}(iv,len={len(data)})"))
        # Also add IV-length arrays (8/16) that are NOT the same as a key
        # Heuristic: if the array is all-zeros, it's likely an IV (common pattern)
        elif len(data) in _VALID_IV_LENGTHS and all(b == 0 for b in data):
            if data not in seen_ivs:
                seen_ivs.add(data)
                ivs_found.append((data, f"byte[]:{var_name}(zero-iv,len={len(data)})"))

    # Tier 3: non-static byte[] with key-hint variable name (lower confidence)
    for m in _BYTE_ARRAY_NONSTATIC_HINTED_RE.finditer(source):
        var_name = m.group(1)
        body = m.group(2)
        data = _parse_byte_array_literal(body)
        if not data:
            continue
        low_name = var_name.lower()
        if 'iv' in low_name and len(data) in _VALID_IV_LENGTHS:
            if data not in seen_ivs:
                seen_ivs.add(data)
                ivs_found.append((data, f"byte[]:{var_name}(hint-iv)"))
        elif data not in seen_keys:
            seen_keys.add(data)
            keys_found.append((data, f"byte[]:{var_name}(hint-key)"))

    return keys_found, ivs_found


def _parse_cipher_algorithm(algo_str: str) -> tuple:
    """Parse Cipher.getInstance("...") argument into (algorithm, mode, padding) triple.
    Returns ("", "", "") if unrecognized.
    Examples:
        "DES" -> ("DES", "ECB", "PKCS5Padding")    # Java default for "DES" is ECB/PKCS5Padding
        "AES/ECB/PKCS5Padding" -> ("AES", "ECB", "PKCS5Padding")
        "AES/CBC/PKCS5Padding" -> ("AES", "CBC", "PKCS5Padding")
        "AES/CBC/NoPadding"    -> ("AES", "CBC", "NoPadding")
        "DES/CFB8/NoPadding"   -> ("DES", "CFB8", "NoPadding")
        "AES" -> ("AES", "ECB", "PKCS5Padding")
        "RC4" -> ("RC4", "", "")
        "DES/CBC/PKCS5Padding" -> ("DES", "CBC", "PKCS5Padding")
    """
    if not algo_str:
        return ("", "", "")
    s = algo_str.strip().upper()
    parts = s.split('/')
    algo = parts[0]
    mode = parts[1] if len(parts) >= 2 else "ECB"
    padding_raw = parts[2] if len(parts) >= 3 else "PKCS5PADDING"
    if algo in ("DES", "AES") and mode == "":
        mode = "ECB"
    # Normalize padding to Java convention (mixed case)
    if padding_raw in ("NOPADDING",):
        padding = "NoPadding"
    elif padding_raw in ("PKCS5PADDING", "PKCS5", "PKCS7PADDING", "PKCS7"):
        padding = "PKCS5Padding"
    elif padding_raw in ("ISO10126PADDING", "ISO10126"):
        padding = "ISO10126Padding"
    else:
        padding = padding_raw  # unknown padding, keep as-is
    if algo not in ("DES", "AES", "RC4"):
        return ("", "", "")
    return (algo, mode, padding)


# ── IOC helpers ────────────────────────────────────────────────────────────────

def _find_crypto_wallets(apk_path):
    """Find cryptocurrency wallet addresses."""
    result = {"BTC": [], "ETH": [], "XMR": [], "TRX": []}

    all_strings = _extract_all_strings(apk_path)
    for s in all_strings:
        # BTC
        btc_matches = re.findall(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})\b', s)
        if btc_matches:
            result["BTC"].extend(btc_matches)
        # ETH
        eth_matches = re.findall(r'\b(0x[a-fA-F0-9]{40})\b', s)
        if eth_matches:
            result["ETH"].extend(eth_matches)
        # TRX
        trx_matches = re.findall(r'\b(T[1-9A-HJ-NP-Za-km-z]{33})\b', s)
        if trx_matches:
            result["TRX"].extend(trx_matches)

    # Deduplicate
    for key in result:
        result[key] = sorted(set(result[key]))

    return result


def _build_suspicious_domain_details(domains):
    """Build detailed suspicious domain entries."""
    details = []
    for d in domains:
        details.append({
            "domain": d,
            "purpose": "c2_communication",
            "suspicious_level": _assess_domain_risk(d),
        })
    return details


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: extract_c2_iocs.py <apk_path> <output_dir> [decompiled_dir]")
        sys.exit(1)

    apk_path = sys.argv[1]
    output_dir = sys.argv[2]
    decompiled_dir = sys.argv[3] if len(sys.argv) >= 4 else ""
    os.makedirs(output_dir, exist_ok=True)

    global _apk_path
    _apk_path = apk_path

    print("[sub03] Starting sub-agent 03 extraction...")
    if decompiled_dir:
        print(f"  [+] Using decompiled source: {decompiled_dir}")

    print("  [*] Extracting c2_communication...")
    c2_result = extract_c2_communication(apk_path, decompiled_dir)
    save_json(c2_result, os.path.join(output_dir, "c2_communication.json"))

    print("  [*] Extracting iocs...")
    iocs_result = extract_iocs(apk_path, c2_result)
    save_json(iocs_result, os.path.join(output_dir, "iocs.json"))

    print("[sub03] Done.")


if __name__ == "__main__":
    main()
