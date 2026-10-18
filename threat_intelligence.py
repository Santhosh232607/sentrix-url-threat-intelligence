"""
SENTRIX — AI-Powered URL Threat Intelligence
Real-Time Threat Intelligence Integration Module

Provides safe, authenticated lookups against authoritative threat databases
(such as Google Safe Browsing v4 and VirusTotal v3) with strict timeout
handling, rate-limit resilience, safe offline fallbacks, and zero key exposure.

NOTE: This module NEVER visits or opens target URLs. It strictly sends
structured lookup queries to official API endpoints.
"""

import os
import re
import json
from typing import Dict, Any, Optional

try:
    import requests
except ImportError:
    requests = None


def get_safe_browsing_api_key() -> Optional[str]:
    """
    Safely retrieves the Google Safe Browsing API key from Streamlit secrets,
    local .streamlit/secrets.toml file, or OS environment variables.
    Never hardcodes secrets and supports both GOOGLE_SAFE_BROWSING_API_KEY
    and SAFE_BROWSING_API_KEY.
    """
    candidate_keys = [
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "SAFE_BROWSING_API_KEY",
        "GOOGLE_API_KEY"
    ]

    # 1. Check Streamlit runtime secrets
    try:
        import streamlit as st
        if hasattr(st, "secrets"):
            for k in candidate_keys:
                if k in st.secrets:
                    val = st.secrets[k]
                    if val and str(val).strip():
                        return str(val).strip()

            # Check nested sections (e.g., [google] or [api_keys])
            for sec_name in st.secrets:
                sec = st.secrets[sec_name]
                if isinstance(sec, dict):
                    for k in candidate_keys:
                        if k in sec:
                            val = sec[k]
                            if val and str(val).strip():
                                return str(val).strip()
    except Exception:
        pass

    # 2. Check direct .streamlit/secrets.toml file (for test suites / CLI scripts)
    secrets_path = os.path.join(os.path.dirname(__file__), ".streamlit", "secrets.toml")
    if os.path.exists(secrets_path):
        try:
            # Use Python 3.11 tomllib
            try:
                import tomllib
                with open(secrets_path, "rb") as f:
                    data = tomllib.load(f)
            except ImportError:
                import toml
                with open(secrets_path, "r", encoding="utf-8") as f:
                    data = toml.load(f)

            if isinstance(data, dict):
                for k in candidate_keys:
                    if k in data and data[k] and str(data[k]).strip():
                        return str(data[k]).strip()
                for sec in data.values():
                    if isinstance(sec, dict):
                        for k in candidate_keys:
                            if k in sec and sec[k] and str(sec[k]).strip():
                                return str(sec[k]).strip()
        except Exception:
            pass

    # 3. Check environment variables
    for k in candidate_keys:
        env_key = os.environ.get(k)
        if env_key and env_key.strip():
            return env_key.strip()

    return None


def get_virustotal_api_key() -> Optional[str]:
    """Safely retrieves optional VirusTotal API key from secrets or env."""
    candidate_keys = ["VIRUSTOTAL_API_KEY", "VT_API_KEY"]

    try:
        import streamlit as st
        if hasattr(st, "secrets"):
            for k in candidate_keys:
                if k in st.secrets:
                    val = st.secrets[k]
                    if val and str(val).strip():
                        return str(val).strip()
    except Exception:
        pass

    # Check direct secrets.toml
    secrets_path = os.path.join(os.path.dirname(__file__), ".streamlit", "secrets.toml")
    if os.path.exists(secrets_path):
        try:
            try:
                import tomllib
                with open(secrets_path, "rb") as f:
                    data = tomllib.load(f)
            except ImportError:
                import toml
                with open(secrets_path, "r", encoding="utf-8") as f:
                    data = toml.load(f)

            if isinstance(data, dict):
                for k in candidate_keys:
                    if k in data and data[k] and str(data[k]).strip():
                        return str(data[k]).strip()
        except Exception:
            pass

    for k in candidate_keys:
        env_key = os.environ.get(k)
        if env_key and env_key.strip():
            return env_key.strip()

    return None


def mask_api_key(key: Optional[str]) -> str:
    """Masks an API key for safe UI status reporting without exposure."""
    if not key:
        return "Not Set"
    if len(key) <= 8:
        return "••••••••"
    return f"{key[:4]}••••••••{key[-4:]}"


def test_harmless_url(harmless_url: str = "https://www.google.com") -> Dict[str, Any]:
    """
    Test function that performs a real Google Safe Browsing API lookup on a harmless URL.
    Verifies that:
    1. The API key is loaded from secrets or environment.
    2. The Google Cloud project has Safe Browsing API enabled.
    3. The API request succeeds with HTTP 200 and returns a valid response.
    Never prints, logs, or exposes the API key.
    """
    sb_key = get_safe_browsing_api_key()
    if not sb_key:
        return {
            "connected": False,
            "status": "NOT_CONFIGURED",
            "dashboard_status": "Unavailable/Error",
            "details": "Google Safe Browsing API key is not configured.",
            "masked_key": "Not Set",
            "test_url": harmless_url
        }

    res = lookup_google_safe_browsing(harmless_url, sb_key)
    if res.get("status") in ("NO_MATCH", "CLEAN"):
        return {
            "connected": True,
            "status": "CONNECTED",
            "dashboard_status": "Connected",
            "details": "Google Safe Browsing API request succeeded (Safe Browsing API is enabled in Google Cloud).",
            "masked_key": mask_api_key(sb_key),
            "test_url": harmless_url,
            "response": res
        }
    else:
        return {
            "connected": False,
            "status": res.get("status", "UNAVAILABLE_OR_ERROR"),
            "dashboard_status": "Unavailable/Error",
            "details": res.get("details", "Connection failed."),
            "masked_key": mask_api_key(sb_key),
            "test_url": harmless_url,
            "response": res
        }


def get_threat_intel_status(probe_live: bool = False) -> Dict[str, Any]:
    """
    Returns an overview of the threat intelligence services' connectivity
    and configuration state for the dashboard.
    """
    sb_key = get_safe_browsing_api_key()
    vt_key = get_virustotal_api_key()

    sb_status = {
        "name": "Google Safe Browsing v4",
        "is_configured": sb_key is not None,
        "status": "Ready (API Key Detected)" if sb_key else "Not Configured",
        "dashboard_status": "Connected" if sb_key else "Unavailable/Error",
        "masked_key": mask_api_key(sb_key),
        "description": "Checks URLs against Google's constantly updated lists of unsafe web resources."
    }

    if probe_live and sb_key:
        probe = test_harmless_url()
        sb_status["connected"] = probe["connected"]
        sb_status["status"] = "Connected (Live Request Verified)" if probe["connected"] else f"Unavailable/Error ({probe['status']})"
        sb_status["dashboard_status"] = probe["dashboard_status"]
        sb_status["details"] = probe["details"]

    return {
        "safe_browsing": sb_status,
        "virustotal": {
            "name": "VirusTotal v3",
            "is_configured": vt_key is not None,
            "status": "Ready (API Key Detected)" if vt_key else "Not Configured",
            "dashboard_status": "Connected" if vt_key else "Unavailable/Error",
            "masked_key": mask_api_key(vt_key),
            "description": "Aggregates multi-antivirus scanning engines and threat intelligence feeds."
        }
    }


def lookup_google_safe_browsing(url: str, api_key: str, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Performs an official Google Safe Browsing Lookup API v4 query.
    Endpoint: https://safebrowsing.googleapis.com/v4/threatMatches:find
    Reference: https://developers.google.com/safe-browsing/v4/lookup-api
    
    Security & Reliability Rules:
    - Passes API key via params and X-goog-api-key header securely.
    - Never logs, prints, or exposes the raw API key in errors or output.
    - Gracefully handles HTTP 200 (Matches & Clean), HTTP 400 (Invalid Key),
      HTTP 403 (Forbidden), HTTP 429 (Rate Limit), timeouts, network drops, and invalid JSON.
    - Maps results clearly to standard dashboard statuses:
      Connected, Threat detected, No match, Unavailable/Error.
    """
    if not requests:
        return {
            "service": "Google Safe Browsing",
            "status": "UNAVAILABLE",
            "dashboard_status": "Unavailable/Error",
            "is_threat": False,
            "details": "HTTP client library 'requests' is missing.",
            "threat_types": []
        }

    clean_url = str(url).strip()
    if not clean_url:
        return {
            "service": "Google Safe Browsing",
            "status": "INVALID_INPUT",
            "dashboard_status": "Unavailable/Error",
            "is_threat": False,
            "details": "Provided URL is empty.",
            "threat_types": []
        }

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    params = {"key": api_key}
    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": api_key
    }
    payload = {
        "client": {
            "clientId": "sentrix-threat-intelligence",
            "clientVersion": "2.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": clean_url}]
        }
    }

    try:
        response = requests.post(
            endpoint,
            params=params,
            json=payload,
            headers=headers,
            timeout=timeout
        )

        if response.status_code == 200:
            try:
                data = response.json()
            except (ValueError, json.JSONDecodeError):
                return {
                    "service": "Google Safe Browsing",
                    "status": "INVALID_JSON",
                    "dashboard_status": "Unavailable/Error",
                    "is_threat": False,
                    "details": "Google Safe Browsing returned an invalid JSON response.",
                    "threat_types": []
                }

            matches = data.get("matches", [])
            if matches:
                threats = sorted(list({m.get("threatType", "UNKNOWN_THREAT") for m in matches}))
                return {
                    "service": "Google Safe Browsing",
                    "status": "THREAT_DETECTED",
                    "dashboard_status": "Threat detected",
                    "is_threat": True,
                    "details": f"Threat detected by Google Safe Browsing: {', '.join(threats)}",
                    "threat_types": threats,
                    "raw_matches": matches
                }
            else:
                return {
                    "service": "Google Safe Browsing",
                    "status": "NO_MATCH",
                    "dashboard_status": "No match",
                    "is_threat": False,
                    "details": "No threat matches identified in Google Safe Browsing global blacklist.",
                    "threat_types": []
                }
        elif response.status_code == 400:
            details = "Google Safe Browsing API key rejected (Verify key validity in Google Cloud Console)."
            try:
                err_data = response.json()
                err_msg = err_data.get("error", {}).get("message", "")
                if "API key not valid" in err_msg:
                    details = "Google Safe Browsing API key is invalid or unrecognized."
            except Exception:
                pass
            return {
                "service": "Google Safe Browsing",
                "status": "INVALID_API_KEY",
                "dashboard_status": "Unavailable/Error",
                "is_threat": False,
                "details": details,
                "threat_types": []
            }
        elif response.status_code == 403:
            return {
                "service": "Google Safe Browsing",
                "status": "API_KEY_FORBIDDEN",
                "dashboard_status": "Unavailable/Error",
                "is_threat": False,
                "details": "Google Safe Browsing API access forbidden (Ensure Safe Browsing API is enabled in Google Cloud Console).",
                "threat_types": []
            }
        elif response.status_code == 429:
            return {
                "service": "Google Safe Browsing",
                "status": "RATE_LIMITED",
                "dashboard_status": "Unavailable/Error",
                "is_threat": False,
                "details": "Rate limit exceeded on Google Safe Browsing API.",
                "threat_types": []
            }
        else:
            return {
                "service": "Google Safe Browsing",
                "status": "API_ERROR",
                "dashboard_status": "Unavailable/Error",
                "is_threat": False,
                "details": f"Threat intel query returned HTTP {response.status_code}.",
                "threat_types": []
            }
    except requests.exceptions.Timeout:
        return {
            "service": "Google Safe Browsing",
            "status": "TIMEOUT",
            "dashboard_status": "Unavailable/Error",
            "is_threat": False,
            "details": f"Threat intelligence lookup timed out after {timeout}s (safe fallback used).",
            "threat_types": []
        }
    except requests.exceptions.RequestException:
        return {
            "service": "Google Safe Browsing",
            "status": "NETWORK_ERROR",
            "dashboard_status": "Unavailable/Error",
            "is_threat": False,
            "details": "Network error communicating with Google Safe Browsing service.",
            "threat_types": []
        }
    except Exception:
        return {
            "service": "Google Safe Browsing",
            "status": "SYSTEM_ERROR",
            "dashboard_status": "Unavailable/Error",
            "is_threat": False,
            "details": "Internal exception during threat intelligence lookup.",
            "threat_types": []
        }


def query_threat_intelligence(url: str, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Main entry point for URL threat intelligence querying.
    Inspects configured providers and queries them with automatic graceful fallbacks.
    """
    sb_key = get_safe_browsing_api_key()

    if not sb_key:
        return {
            "service": "None",
            "status": "NOT_CONFIGURED",
            "dashboard_status": "Unavailable/Error",
            "is_threat": False,
            "details": "External Threat Intel API key is not configured. Classification relies strictly on local ML model and lexical heuristics.",
            "threat_types": []
        }

    # Query Safe Browsing
    return lookup_google_safe_browsing(url, sb_key, timeout=timeout)
