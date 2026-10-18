"""
SENTRIX — AI-Powered URL Threat Intelligence
Advanced Feature Extraction & Heuristic Risk Engine

This module extracts pure-lexical, structural, and behavioral indicators
from URL strings. It strictly performs client-side string analysis and
NEVER opens, resolves, or sends network requests to target URLs.
"""

import math
import re
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List

# Well-known URL shortening services often abused to conceal targets
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "cutt.ly", "bit.do", "shorte.st", "tiny.cc",
    "tr.im", "v.gd", "snipurl.com", "bl.ink", "lnkd.in", "s.id"
}

# Top-level domains frequently flagged in malicious, spam, or throwaway campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club",
    "work", "country", "kim", "live", "guru", "stream", "bid", "loan",
    "racing", "download", "review", "accountant", "faith", "date",
    "win", "men", "party", "click", "rest", "fit"
}

# High-profile brand targets frequently impersonated in phishing campaigns
TARGET_BRANDS = [
    "paypal", "apple", "appleid", "microsoft", "google", "amazon",
    "netflix", "chase", "wellsfargo", "bankofamerica", "coinbase",
    "binance", "metamask", "dhl", "fedex", "facebook", "instagram",
    "whatsapp", "roblox", "steam", "dropbox", "adobe"
]

# Security-sensitive & credential harvesting keywords often used in social engineering
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "banking", "secure", "signin",
    "ebayisapi", "paypal", "webscr", "confirm", "password", "wallet",
    "crypto", "recover", "authenticate", "billing", "invoice", "claim",
    "bonus", "free-gift", "support-desk", "verification", "security-alert",
    "authorize", "validation", "suspended", "unlock", "re-activate"
]

# Standard feature order for machine learning model training & inference
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_subdomains",
    "num_hyphens",
    "num_special_chars",
    "has_at_symbol",
    "has_ip_address",
    "is_https",
    "suspicious_keyword_count",
    "has_suspicious_keywords",
    "is_shortened_url",
    "is_suspicious_tld",
    "shannon_entropy",
    "digit_ratio",
    "has_double_slash_path",
    "has_punycode",
    "has_unusual_port",
    "num_encoded_chars",
    "has_brand_in_subdomain"
]


def normalize_url(raw_url: str) -> str:
    """
    Clean and normalize URL for parsing without initiating any network traffic.
    Prefixes 'http://' if no scheme is provided to allow valid urlparse handling.
    """
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = "http://" + cleaned
    return cleaned


def calculate_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy of a string to detect high randomness
    (e.g., Domain Generation Algorithms - DGA).
    """
    if not text:
        return 0.0
    text_length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    entropy = 0.0
    for count in char_counts.values():
        p = count / text_length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_ip_address(hostname: str) -> bool:
    """Checks if a hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    host = hostname.split(":")[0].strip("[]")
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        parts = host.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    if ":" in host and len(host.split(":")) >= 3:
        return True
    return False


def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Extracts 21 lexical, structural, and behavioral features from the given URL string.
    Returns a dictionary mapping feature names to numerical values.
    """
    normalized = normalize_url(raw_url)
    if not normalized:
        return {name: 0 for name in FEATURE_NAMES}

    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_clean_url = normalized.lower()

    # 1. URL Length
    url_length = len(raw_url.strip())

    # 2. Hostname Length
    hostname_length = len(hostname)

    # 3. Path Length
    path_length = len(path)

    # 4. Number of dots
    num_dots = raw_url.count(".")

    # 5. Number of subdomains
    if hostname and not is_ip_address(hostname):
        parts = hostname.split(".")
        num_subdomains = max(0, len(parts) - 2)
    else:
        num_subdomains = 0

    # 6. Number of hyphens
    num_hyphens = raw_url.count("-")

    # 7. Number of special characters
    special_chars = set("@?=!%#&~+_;$,")
    num_special_chars = sum(1 for c in raw_url if c in special_chars)

    # 8. Has '@' symbol
    has_at_symbol = 1 if "@" in raw_url else 0

    # 9. Has IP address as hostname
    has_ip = 1 if is_ip_address(hostname) else 0

    # 10. HTTPS usage
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    # 11 & 12. Suspicious keywords count & flag
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_clean_url]
    suspicious_keyword_count = len(found_keywords)
    has_suspicious_keywords = 1 if suspicious_keyword_count > 0 else 0

    # 13. Is shortened URL
    is_shortened = 1 if hostname in KNOWN_SHORTENERS else 0

    # 14. Is suspicious TLD
    tld = hostname.split(".")[-1] if "." in hostname else ""
    is_suspicious_tld = 1 if tld in HIGH_RISK_TLDS else 0

    # 15. Shannon Entropy
    shannon_entropy = calculate_entropy(raw_url.strip())

    # 16. Digit ratio
    num_digits = sum(1 for c in raw_url if c.isdigit())
    digit_ratio = round(num_digits / max(1, url_length), 4)

    # 17. Double slash in path
    has_double_slash_path = 1 if "//" in path else 0

    # 18. Punycode detection (IDN Homograph attacks)
    has_punycode = 1 if "xn--" in hostname else 0

    # 19. Unusual port detection
    has_unusual_port = 0
    if parsed.port and parsed.port not in (80, 443):
        has_unusual_port = 1

    # 20. Encoded character sequences (%xx)
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", raw_url)
    num_encoded_chars = len(encoded_matches)

    # 21. Brand in subdomain or path (Brand-jacking / deceptive impersonation)
    has_brand_in_subdomain = 0
    if hostname and not is_ip_address(hostname):
        parts = hostname.split(".")
        apex_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        subdomain_part = ".".join(parts[:-2]) if len(parts) > 2 else ""
        for brand in TARGET_BRANDS:
            if brand in subdomain_part or (brand in path and brand not in apex_domain):
                has_brand_in_subdomain = 1
                break

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "num_dots": num_dots,
        "num_subdomains": num_subdomains,
        "num_hyphens": num_hyphens,
        "num_special_chars": num_special_chars,
        "has_at_symbol": has_at_symbol,
        "has_ip_address": has_ip,
        "is_https": is_https,
        "suspicious_keyword_count": suspicious_keyword_count,
        "has_suspicious_keywords": has_suspicious_keywords,
        "is_shortened_url": is_shortened,
        "is_suspicious_tld": is_suspicious_tld,
        "shannon_entropy": shannon_entropy,
        "digit_ratio": digit_ratio,
        "has_double_slash_path": has_double_slash_path,
        "has_punycode": has_punycode,
        "has_unusual_port": has_unusual_port,
        "num_encoded_chars": num_encoded_chars,
        "has_brand_in_subdomain": has_brand_in_subdomain
    }


def compute_heuristic_risk_score(raw_url: str, features: Dict[str, Any]) -> int:
    """
    Calculates a transparent, documented 0–100 Heuristic Risk Score.
    This score is purely rule-based and strictly decoupled from ML model confidence.
    
    Scoring Formula Breakdown:
    - Base risk: 5 pts
    - Raw IP Hostname: +35 pts
    - Deceptive '@' Delimiter: +30 pts
    - Brand Spoofing in Subdomain/Path: +25 pts
    - High-Abuse TLD: +20 pts
    - URL Shortener: +20 pts
    - Punycode (IDN homograph): +20 pts
    - Sensitive Keywords: +12 pts per keyword (max 30 pts)
    - Double Slash in Path: +15 pts
    - Unusual Port: +15 pts
    - Excessive Subdomains (>=3): +15 pts
    - High Character Entropy (>4.2): +15 pts
    - Excessive URL Encoding (>=3 %xx): +10 pts
    - Long URL (>85 chars): +10 pts
    - High Digit Ratio (>25%): +10 pts
    - Unencrypted HTTP: +8 pts
    - HTTPS Protocol Offset: -10 pts (Note: HTTPS does NOT guarantee safety)
    """
    score = 5

    if features.get("has_ip_address", 0) == 1:
        score += 35
    if features.get("has_at_symbol", 0) == 1:
        score += 30
    if features.get("has_brand_in_subdomain", 0) == 1:
        score += 25
    if features.get("is_suspicious_tld", 0) == 1:
        score += 20
    if features.get("is_shortened_url", 0) == 1:
        score += 20
    if features.get("has_punycode", 0) == 1:
        score += 20
    
    kw_count = features.get("suspicious_keyword_count", 0)
    score += min(30, kw_count * 12)

    if features.get("has_double_slash_path", 0) == 1:
        score += 15
    if features.get("has_unusual_port", 0) == 1:
        score += 15
    if features.get("num_subdomains", 0) >= 3:
        score += 15
    if features.get("shannon_entropy", 0) > 4.2:
        score += 15
    if features.get("num_encoded_chars", 0) >= 3:
        score += 10
    if features.get("url_length", 0) > 85:
        score += 10
    if features.get("digit_ratio", 0) > 0.25:
        score += 10
    
    if features.get("is_https", 1) == 0:
        score += 8
    else:
        score -= 10

    return max(0, min(100, score))


def get_url_warning_signs(raw_url: str, features: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Translates raw feature metrics into human-readable warning indicators
    explaining why each detected condition represents a potential security risk.
    """
    warnings: List[Dict[str, str]] = []
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    full_url = raw_url.lower()

    if features.get("has_ip_address", 0) == 1:
        warnings.append({
            "severity": "High",
            "category": "Host Spoofing",
            "title": "Raw IP Address Hostname",
            "description": f"The URL targets a raw IP address ({hostname}) instead of a registered domain. Attackers use raw IPs to bypass domain registration oversight and host rogue infrastructure."
        })

    if features.get("has_at_symbol", 0) == 1:
        warnings.append({
            "severity": "High",
            "category": "Credential Abuse",
            "title": "Deceptive '@' Credential Delimiter",
            "description": "The URL contains an '@' character. Browsers treat characters before '@' as authentication credentials and connect to the host that follows, misleading users about the real destination."
        })

    if features.get("has_brand_in_subdomain", 0) == 1:
        warnings.append({
            "severity": "High",
            "category": "Impersonation",
            "title": "Brand Impersonation in Subdomain / Path",
            "description": "A well-known corporate brand is embedded in a subdomain or deceptive path rather than the authentic apex domain (e.g., 'paypal.security-update.com')."
        })

    if features.get("has_punycode", 0) == 1:
        warnings.append({
            "severity": "High",
            "category": "Homograph Attack",
            "title": "Punycode Encoding ('xn--') Detected",
            "description": "The domain uses internationalized punycode characters which can visually mimic legitimate ASCII characters (e.g., Cyrillic 'а' replacing Latin 'a')."
        })

    if features.get("has_double_slash_path", 0) == 1:
        warnings.append({
            "severity": "Medium",
            "category": "Redirection",
            "title": "Embedded Double Slash ('//') in Path",
            "description": "Detected a double slash inside the URL path, commonly exploited in open-redirect attacks to disguise malware links as internal portal routes."
        })

    if features.get("has_unusual_port", 0) == 1:
        warnings.append({
            "severity": "Medium",
            "category": "Network",
            "title": f"Non-Standard Port ({parsed.port})",
            "description": f"The URL specifies a non-standard port ({parsed.port}) instead of standard HTTP (80) or HTTPS (443). Often used by rogue C2 servers or proxy tunnels."
        })

    if features.get("is_shortened_url", 0) == 1:
        warnings.append({
            "severity": "Medium",
            "category": "Obfuscation",
            "title": "URL Shortener Concealment",
            "description": f"The hostname '{hostname}' is a known URL shortening service. Shorteners conceal the actual target destination and evade standard perimeter filters."
        })

    if features.get("is_suspicious_tld", 0) == 1:
        tld = hostname.split(".")[-1] if "." in hostname else "unknown"
        warnings.append({
            "severity": "Medium",
            "category": "Domain Risk",
            "title": f"High-Abuse Top Level Domain (.{tld})",
            "description": f"The domain suffix '.{tld}' has an elevated correlation with spam, malicious redirects, and disposable phishing operations according to threat intelligence records."
        })

    matched_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    if matched_kw:
        warnings.append({
            "severity": "Medium" if len(matched_kw) == 1 else "High",
            "category": "Social Engineering",
            "title": f"Authentication Keywords ({', '.join(matched_kw[:4])})",
            "description": "Contains social engineering terms frequently employed to fake urgent credential verification, payment updates, or account suspensions."
        })

    if features.get("num_subdomains", 0) >= 3:
        warnings.append({
            "severity": "Medium",
            "category": "Structure",
            "title": f"Excessive Subdomain Stacking ({features.get('num_subdomains')} levels)",
            "description": "Deep subdomain nesting is frequently deployed to push the true root domain out of browser address bar view on mobile devices."
        })

    if features.get("shannon_entropy", 0) > 4.2:
        warnings.append({
            "severity": "Medium",
            "category": "Randomness",
            "title": f"Elevated Character Entropy ({features.get('shannon_entropy', 0)})",
            "description": "Character randomness is abnormally high, characteristic of Domain Generation Algorithms (DGA), botnet tracking tokens, or hashed malware drops."
        })

    if features.get("num_encoded_chars", 0) >= 3:
        warnings.append({
            "severity": "Low",
            "category": "Encoding",
            "title": f"Excessive Hex URL Encoding ({features.get('num_encoded_chars')} entities)",
            "description": "Multiple percent-encoded characters detected, frequently used to obscure malicious SQL, script tags, or directory traversal sequences."
        })

    if features.get("url_length", 0) > 85:
        warnings.append({
            "severity": "Low",
            "category": "Structure",
            "title": f"Abnormally Long URL ({features.get('url_length')} characters)",
            "description": "Excessive length often conceals attack payloads or confuses signature-based security filters."
        })

    if features.get("digit_ratio", 0) > 0.25:
        warnings.append({
            "severity": "Low",
            "category": "Entropy",
            "title": f"High Numeric Density ({int(features.get('digit_ratio', 0) * 100)}% digits)",
            "description": "A high proportion of numerical digits indicates automated session identifiers or brute-force attack paths."
        })

    if features.get("is_https", 1) == 0:
        warnings.append({
            "severity": "Low",
            "category": "Protocol",
            "title": "Unencrypted Protocol (Plain HTTP)",
            "description": "Traffic is transmitted in unencrypted clear text. Note: While HTTPS encrypts traffic, HTTPS alone DOES NOT prove a site is trustworthy."
        })

    return warnings


def get_safety_advice(prediction: str, risk_score: int) -> Dict[str, Any]:
    """
    Returns actionable, realistic safety guidance tailored to the threat tier.
    Clearly notes that URL analysis evaluates structure, not full site behavior.
    """
    pred_upper = prediction.upper()
    if pred_upper == "MALICIOUS" or risk_score >= 65:
        return {
            "headline": "CRITICAL RISK — DO NOT OPEN OR VISIT",
            "badge_color": "#ef4444",
            "risk_level": "Severe Threat",
            "summary": "This URL exhibits verified attack indicators such as raw IP targeting, credential injection, or malware dropper structure.",
            "actions": [
                "Do not open, click, or load this link in any browser or application.",
                "Never enter passwords, credit card details, or authentication MFA codes.",
                "Block or blacklist this domain/IP across firewall and DNS resolvers.",
                "If submitted by an employee or user, report it to your Security Operations Center (SOC)."
            ],
            "disclaimer": "Safety Notice: Never attempt to navigate to malicious links to 'inspect' them. Malicious servers may exploit browser vulnerabilities."
        }
    elif pred_upper == "SUSPICIOUS" or risk_score >= 30:
        return {
            "headline": "ELEVATED RISK — EXERCISE CAUTION",
            "badge_color": "#f59e0b",
            "risk_level": "Suspicious / Anomalous",
            "summary": "This URL displays anomalies such as deceptive keywords, unusual TLDs, or obfuscation that resemble phishing traps.",
            "actions": [
                "Verify the sender's authentic identity via an out-of-band channel (phone, known portal).",
                "Carefully inspect the root domain name for typosquatting (e.g. 'micros0ft.com').",
                "Do not download attachments or execute prompted software installations.",
                "Verify with organizational IT security if this involves corporate credentials."
            ],
            "disclaimer": "Safety Notice: While HTTPS may be present, HTTPS only encrypts the connection. Attackers can and do obtain free HTTPS certificates."
        }
    else:  # SAFE
        return {
            "headline": "BENIGN INDICATORS — STANDARD CAUTION APPLIES",
            "badge_color": "#10b981",
            "risk_level": "Low Structural Risk",
            "summary": "The URL structure follows standard domain conventions and exhibits no known malicious structural heuristics.",
            "actions": [
                "The lexical structure of the URL matches typical legitimate web resources.",
                "Ensure your operating system and web browser apply security updates regularly.",
                "Always check for a valid SSL padlock when submitting confidential data.",
                "Employ multi-factor authentication (MFA) as defense-in-depth across all accounts."
            ],
            "disclaimer": "Safety Notice: Static URL analysis evaluates syntactic and behavioral indicators, but cannot guarantee 100% safety against compromised legitimate domains."
        }
