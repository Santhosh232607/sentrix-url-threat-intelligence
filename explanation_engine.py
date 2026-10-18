"""
SENTRIX — AI-Powered URL Threat Intelligence
Explainable URL Risk Detection Engine

Generates clear, evidence-based, transparent explanations of WHY a URL was
classified as SAFE, SUSPICIOUS, or MALICIOUS.

Features:
- Identifies specific checks that passed (with actual values).
- Identifies exact anomalous features that triggered warnings (with actual values).
- Clearly separates ML model predictions, heuristic scores, and threat intel feeds.
- Explicitly states scan limitations and avoids falsely claiming safety.
- Strictly deterministic and evidence-grounded (zero invented facts or LLM hallucinations).
"""

from urllib.parse import urlparse
from typing import Dict, Any, List, Optional


def generate_explanation(
    url: str,
    features: Dict[str, Any],
    prediction: str,
    risk_score: int,
    model_confidence: Optional[float] = None,
    threat_intel: Optional[Dict[str, Any]] = None,
    warning_signs: Optional[List[Dict[str, str]]] = None,
    model_feature_importances: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """
    Constructs a comprehensive, evidence-based explanation for the scan verdict.
    """
    clean_url = url.strip()
    parsed = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    threat_intel = threat_intel or {"status": "NOT_CONFIGURED", "details": "Not configured"}
    ti_status = threat_intel.get("status", "NOT_CONFIGURED")
    ti_threat = threat_intel.get("is_threat", False)

    pred_norm = prediction.upper()

    # 1. EVALUATE GENUINELY PASSED CHECKS (WITH ACTUAL DETECTED VALUES)
    checks_passed = []

    # Check 1: Registered Domain vs Raw IP
    if features.get("has_ip_address", 0) == 0:
        checks_passed.append({
            "check": "Registered Domain Verification",
            "status": "Passed",
            "actual_value": hostname if hostname else "Standard Domain",
            "detail": "Target resolves to a named domain hierarchy rather than an exposed raw IP address."
        })

    # Check 2: Credential Delimiter
    if features.get("has_at_symbol", 0) == 0:
        checks_passed.append({
            "check": "No Credential Delimiter ('@')",
            "status": "Passed",
            "actual_value": "Zero '@' symbols detected",
            "detail": "The URL does not use HTTP basic authentication syntax to obscure the destination host."
        })

    # Check 3: Subdomain Stacking
    subdomains_count = features.get("num_subdomains", 0)
    if subdomains_count <= 2:
        checks_passed.append({
            "check": "Standard Subdomain Hierarchy",
            "status": "Passed",
            "actual_value": f"{subdomains_count} subdomain(s) detected",
            "detail": "Subdomain structure conforms to normal organizational levels (<= 2 tiers)."
        })

    # Check 4: URL Length
    url_len = features.get("url_length", len(clean_url))
    if url_len <= 85:
        checks_passed.append({
            "check": "Acceptable URL Length",
            "status": "Passed",
            "actual_value": f"{url_len} characters (<= 85 threshold)",
            "detail": "Length is within standard web conventions, with no excessive parameter bloat."
        })

    # Check 5: Top-Level Domain Reputation
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if features.get("is_suspicious_tld", 0) == 0:
        checks_passed.append({
            "check": "Standard Top-Level Domain",
            "status": "Passed",
            "actual_value": f".{tld}" if tld else "Standard TLD",
            "detail": "The domain extension is not listed among high-abuse disposable or scam TLDs."
        })

    # Check 6: Direct Domain (Not a Shortener)
    if features.get("is_shortened_url", 0) == 0:
        checks_passed.append({
            "check": "Direct Destination Host",
            "status": "Passed",
            "actual_value": "Direct Apex Host (Not Shortened)",
            "detail": "The host is not a known URL shortening intermediary concealing the true destination."
        })

    # Check 7: Character Entropy
    entropy = features.get("shannon_entropy", 0.0)
    if entropy <= 4.2:
        checks_passed.append({
            "check": "Natural Character Entropy",
            "status": "Passed",
            "actual_value": f"{entropy:.2f} bits/char (<= 4.2 threshold)",
            "detail": "Character distribution matches natural language and standard naming, not machine-generated DGA."
        })

    # Check 8: Phishing / Sensitive Keywords
    kw_count = features.get("suspicious_keyword_count", 0)
    if kw_count == 0:
        checks_passed.append({
            "check": "Zero Deceptive Keywords",
            "status": "Passed",
            "actual_value": "0 suspicious keywords found",
            "detail": "No social engineering terms targeting credentials, banking, or urgent verification were found."
        })

    # Check 9: Double Slash in Path
    if features.get("has_double_slash_path", 0) == 0:
        checks_passed.append({
            "check": "Clean Path Structure",
            "status": "Passed",
            "actual_value": "No embedded '//' in path",
            "detail": "Path does not contain open-redirect patterns designed to disguise malicious links."
        })

    # Check 10: Standard Port
    if features.get("has_unusual_port", 0) == 0:
        checks_passed.append({
            "check": "Standard Web Port",
            "status": "Passed",
            "actual_value": f"Port {port}" if port else "Standard Port (80/443 default)",
            "detail": "The connection targets standard web services rather than high-numbered or proxy ports."
        })

    # Check 11: Punycode / Homograph
    if features.get("has_punycode", 0) == 0:
        checks_passed.append({
            "check": "Standard Character Set (No Punycode)",
            "status": "Passed",
            "actual_value": "Standard ASCII Domain",
            "detail": "The domain does not use internationalized punycode ('xn--') to visually impersonate familiar brands."
        })

    # Check 12: Brand-jacking in Subdomains
    if features.get("has_brand_in_subdomain", 0) == 0:
        checks_passed.append({
            "check": "No Brand Impersonation in Subdomains",
            "status": "Passed",
            "actual_value": "No third-party brand keywords in subdomain/path",
            "detail": "Subdomains and path do not attempt to spoof trusted services outside their legitimate apex domain."
        })

    # Check 13: Protocol Encryption
    if features.get("is_https", 0) == 1:
        checks_passed.append({
            "check": "Transport Layer Security (HTTPS)",
            "status": "Passed",
            "actual_value": "HTTPS Protocol",
            "detail": "Traffic is encrypted via TLS. (Note: HTTPS encrypts data, but does not guarantee the site owner is trustworthy)."
        })

    # 2. IDENTIFY ANOMALOUS TRIGGERED INDICATORS (WITH ACTUAL VALUES)
    triggered_indicators = []
    
    if features.get("has_ip_address", 0) == 1:
        triggered_indicators.append({
            "title": "Raw IP Address Hostname",
            "category": "Host Obfuscation",
            "severity": "High",
            "actual_value": f"Target Host: {hostname}",
            "why_it_matters": "Attackers frequently host malware payloads or phishing traps directly on raw IP addresses to bypass domain registration accountability and DNS monitoring."
        })

    if features.get("has_at_symbol", 0) == 1:
        triggered_indicators.append({
            "title": "Deceptive '@' Credential Delimiter",
            "category": "URL Deception",
            "severity": "High",
            "actual_value": "'@' symbol present in URL",
            "why_it_matters": "Browsers interpret content before the '@' as authentication credentials and connect only to the host after it, misleading users about where the link actually leads."
        })

    if features.get("has_brand_in_subdomain", 0) == 1:
        triggered_indicators.append({
            "title": "Brand Impersonation in Subdomain / Path",
            "category": "Social Engineering",
            "severity": "High",
            "actual_value": f"Host: {hostname}",
            "why_it_matters": "A well-known brand name is placed in a subdomain or deceptive path rather than the authentic registered domain (e.g., 'paypal.security-alert.com')."
        })

    if features.get("has_punycode", 0) == 1:
        triggered_indicators.append({
            "title": "Punycode Homograph Domain ('xn--')",
            "category": "Homograph Spoofing",
            "severity": "High",
            "actual_value": f"Punycode Host: {hostname}",
            "why_it_matters": "Punycode enables homograph spoofing by rendering visually identical characters from different alphabets (e.g. Cyrillic 'а' vs Latin 'a') to mimic trusted domains."
        })

    if features.get("has_double_slash_path", 0) == 1:
        triggered_indicators.append({
            "title": "Embedded Double Slash ('//') in Path",
            "category": "Open Redirect",
            "severity": "Medium",
            "actual_value": f"Path: {parsed.path}",
            "why_it_matters": "Double slashes in the path are commonly leveraged in open-redirect exploits to deceive perimeter security filters into treating external targets as local routes."
        })

    if features.get("has_unusual_port", 0) == 1:
        triggered_indicators.append({
            "title": f"Non-Standard Port ({port})",
            "category": "Network Routing",
            "severity": "Medium",
            "actual_value": f"Port: {port}",
            "why_it_matters": "Standard web browsing uses ports 80 (HTTP) and 443 (HTTPS). Non-standard ports frequently host unauthorized proxies, testing servers, or command-and-control backdoors."
        })

    if features.get("is_shortened_url", 0) == 1:
        triggered_indicators.append({
            "title": "URL Shortener Concealment",
            "category": "Destination Obfuscation",
            "severity": "Medium",
            "actual_value": f"Shortener Host: {hostname}",
            "why_it_matters": "URL shorteners conceal the true destination domain, preventing inspection prior to click and often bypassing basic link blocklists."
        })

    if features.get("is_suspicious_tld", 0) == 1:
        triggered_indicators.append({
            "title": f"High-Abuse Top Level Domain (.{tld})",
            "category": "Domain Reputation",
            "severity": "Medium",
            "actual_value": f"TLD: .{tld}",
            "why_it_matters": "This top-level domain exhibits high statistical rates of spam, disposable phishing infrastructure, and throwaway registrations according to threat intelligence records."
        })

    if features.get("suspicious_keyword_count", 0) > 0:
        triggered_indicators.append({
            "title": f"Sensitive Security Keywords ({features.get('suspicious_keyword_count')} detected)",
            "category": "Credential Harvesting",
            "severity": "High" if features.get("suspicious_keyword_count", 0) >= 3 else "Medium",
            "actual_value": f"{features.get('suspicious_keyword_count')} keyword(s) detected",
            "why_it_matters": "The URL contains terms commonly used in phishing campaigns to manufacture urgency around authentication, billing updates, or account suspensions."
        })

    if features.get("num_subdomains", 0) >= 3:
        triggered_indicators.append({
            "title": f"Excessive Subdomain Stacking ({features.get('num_subdomains')} levels)",
            "category": "Visual Deception",
            "severity": "Medium",
            "actual_value": f"{features.get('num_subdomains')} subdomain tiers",
            "why_it_matters": "Deep subdomain nesting is frequently deployed to push the authentic apex domain out of view in mobile address bars and browser tabs."
        })

    if features.get("shannon_entropy", 0) > 4.2:
        triggered_indicators.append({
            "title": f"Elevated Character Randomness ({features.get('shannon_entropy'):.2f} bits)",
            "category": "DGA / Algorithmic",
            "severity": "Medium",
            "actual_value": f"Entropy: {features.get('shannon_entropy'):.2f}",
            "why_it_matters": "Abnormally high character entropy indicates machine-generated, algorithmic (DGA) domain generation, randomized botnet beacons, or encrypted path tokens."
        })

    if features.get("num_encoded_chars", 0) >= 3:
        triggered_indicators.append({
            "title": f"Multiple Percent-Encoded Characters ({features.get('num_encoded_chars')} entities)",
            "category": "Payload Obfuscation",
            "severity": "Low",
            "actual_value": f"{features.get('num_encoded_chars')} hex escape codes",
            "why_it_matters": "Multiple percent-encoded sequences can conceal directory traversal, cross-site scripting (XSS), or SQL injection payloads from basic pattern scanners."
        })

    if features.get("url_length", 0) > 85:
        triggered_indicators.append({
            "title": f"Abnormally Long URL ({features.get('url_length')} characters)",
            "category": "Structure",
            "severity": "Low",
            "actual_value": f"Length: {features.get('url_length')} chars",
            "why_it_matters": "Excessive URL length is frequently used to bury suspicious parameters, pad links beyond display boundaries, or pass complex serialized payloads."
        })

    if features.get("digit_ratio", 0) > 0.25:
        triggered_indicators.append({
            "title": f"High Numeric Digit Ratio ({int(features.get('digit_ratio', 0) * 100)}% numeric)",
            "category": "Automation",
            "severity": "Low",
            "actual_value": f"{int(features.get('digit_ratio', 0) * 100)}% digits",
            "why_it_matters": "A high concentration of numbers across the URL suggests automated attack scripts, session tracking tokens, or randomized target paths."
        })

    if features.get("is_https", 1) == 0:
        triggered_indicators.append({
            "title": "Unencrypted Protocol (Plain HTTP)",
            "category": "Protocol Security",
            "severity": "Low",
            "actual_value": "HTTP (Unencrypted)",
            "why_it_matters": "Communication over unencrypted HTTP can be intercepted or modified in transit by attackers on public or untrusted networks."
        })

    # 3. THREAT INTELLIGENCE ASSESSMENT
    threat_intel_summary = {
        "status": ti_status,
        "is_threat": ti_threat,
        "service": threat_intel.get("service", "None"),
        "details": threat_intel.get("details", ""),
        "threat_types": threat_intel.get("threat_types", [])
    }

    if ti_status == "CONFIRMED_THREAT":
        threat_intel_summary["display_badge"] = "Confirmed Threat by External Feed"
        threat_intel_summary["badge_type"] = "error"
    elif ti_status == "CLEAN":
        threat_intel_summary["display_badge"] = "No Known Threats in External Feed"
        threat_intel_summary["badge_type"] = "success"
    elif ti_status == "NOT_CONFIGURED":
        threat_intel_summary["display_badge"] = "Threat Intelligence Not Configured"
        threat_intel_summary["badge_type"] = "info"
    else:
        threat_intel_summary["display_badge"] = f"Threat Intelligence Unavailable ({ti_status})"
        threat_intel_summary["badge_type"] = "warning"

    # 4. COMPOSE "WHY THIS RESULT?" SUMMARY PARAGRAPH
    if pred_norm == "SAFE":
        if ti_status == "CLEAN":
            ti_phrase = "and was verified clean by external threat intelligence"
        elif ti_status == "NOT_CONFIGURED":
            ti_phrase = "though external threat intelligence lookup is not configured for independent verification"
        else:
            ti_phrase = f"though external threat intelligence was unavailable ({ti_status})"

        summary = (
            f"The URL passed {len(checks_passed)} standard structural security checks. "
            f"No recognized malicious or deceptive patterns—such as raw IP hostnames, credential injection, "
            f"excessive subdomains, or high-abuse TLDs—were observed ({ti_phrase}). "
            f"The Random Forest model evaluated the lexical profile as SAFE with {model_confidence*100:.1f}% confidence "
            f"and a low heuristic risk score of {risk_score}/100."
            if model_confidence is not None else
            f"The URL passed {len(checks_passed)} standard structural security checks with no recognized threat patterns ({ti_phrase}). "
            f"Calculated heuristic risk score is low at {risk_score}/100."
        )

    elif pred_norm == "SUSPICIOUS":
        top_triggers = [t["title"] for t in triggered_indicators[:3]]
        triggers_str = "; ".join(top_triggers) if top_triggers else "elevated structural anomalies"
        ti_note = (
            "External threat intelligence has not confirmed active malware"
            if ti_status in ("CLEAN", "NOT_CONFIGURED", "UNAVAILABLE")
            else f"Threat intelligence reported: {ti_status}"
        )

        summary = (
            f"The URL triggered {len(triggered_indicators)} warning indicator(s), notably: {triggers_str}. "
            f"These characteristics frequently accompany social engineering, unencrypted credential forms, or link obfuscation. "
            f"While these patterns warrant caution, they do not constitute definitive proof of malicious activity ({ti_note}). "
            f"The overall heuristic risk score is {risk_score}/100."
        )

    else:  # MALICIOUS
        if ti_threat:
            threat_names = ", ".join(threat_intel.get("threat_types", ["MALWARE"]))
            summary = (
                f"The URL has been CONFIRMED MALICIOUS by external threat intelligence "
                f"({threat_intel.get('service', 'Threat Intel Feed')}: {threat_names}). "
                f"Local lexical analysis additionally identified {len(triggered_indicators)} risk indicator(s), "
                f"resulting in a critical risk score of {risk_score}/100."
            )
        else:
            top_triggers = [t["title"] for t in triggered_indicators[:3]]
            triggers_str = "; ".join(top_triggers) if top_triggers else "critical attack indicators"
            conf_str = f" with {model_confidence*100:.1f}% model confidence" if model_confidence else ""
            summary = (
                f"The URL exhibits high-severity attack signatures: {triggers_str}. "
                f"The Random Forest classifier predicted MALICIOUS{conf_str}, yielding a severe heuristic risk score of {risk_score}/100. "
                f"These structural patterns strongly indicate active phishing, credential interception, or malware delivery infrastructure."
            )

    # 5. DOCUMENTED SCAN LIMITATIONS
    limitations = [
        "URL-only analysis evaluates lexical and structural syntax. It cannot inspect live web page DOM content, executed JavaScript, or server-side behavior.",
        "Absence of detected threat indicators does not guarantee that a legitimate domain has not suffered account takeover, DNS hijacking, or recent malicious redirection.",
        "HTTPS protocol verifies transport-layer encryption, but does NOT guarantee the site owner is trustworthy or non-malicious."
    ]

    if ti_status in ("NOT_CONFIGURED", "UNAVAILABLE", "TIMEOUT", "API_ERROR", "RATE_LIMITED"):
        limitations.append(
            f"External threat-intelligence verification was {ti_status.lower().replace('_', ' ')} for this scan; "
            f"the URL has not been cross-referenced against Google Safe Browsing blacklists."
        )

    # 6. TOP SUPPORTING MODEL OBSERVATIONS
    supporting_observations = []
    if model_feature_importances:
        # Match top features in this specific URL against global feature importances
        sorted_fi = sorted(model_feature_importances.items(), key=lambda x: x[1], reverse=True)
        for fname, imp in sorted_fi[:6]:
            val = features.get(fname, 0)
            supporting_observations.append({
                "feature": fname,
                "importance_weight": round(imp, 4),
                "actual_value": val
            })

    return {
        "url": clean_url,
        "classification": pred_norm,
        "risk_score": risk_score,
        "confidence": model_confidence,
        "why_this_result": summary,
        "checks_passed_count": len(checks_passed),
        "checks_passed": checks_passed,
        "triggered_indicators_count": len(triggered_indicators),
        "triggered_indicators": triggered_indicators,
        "threat_intel_assessment": threat_intel_summary,
        "limitations": limitations,
        "supporting_observations": supporting_observations
    }
