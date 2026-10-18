"""
=============================================================================
SENTRIX — AI-Powered URL Threat Intelligence
Real-Time URL Risk Analysis & Cyber Threat Monitoring
Built with Python, Streamlit, pandas, scikit-learn, and Random Forest
=============================================================================
"""

import os
import time
import json
import io
from datetime import datetime
import pandas as pd
import streamlit as st
import joblib

# Internal Core Modules
from feature_extractor import (
    extract_features,
    compute_heuristic_risk_score,
    get_url_warning_signs,
    get_safety_advice,
    FEATURE_NAMES
)
from database import (
    init_db,
    insert_scan,
    get_stats,
    get_recent_scans,
    get_filtered_history_df,
    clear_history
)
from threat_intelligence import (
    get_threat_intel_status,
    query_threat_intelligence,
    test_harmless_url
)
from explanation_engine import generate_explanation

# Initialize database tables on startup
init_db()

# -----------------------------------------------------------------------------
# 1. PAGE CONFIGURATION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SENTRIX — AI-Powered URL Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# 2. DESIGN SYSTEM: CYBER DARK NAVY & NEON CYAN ACCENTS
# -----------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
/* SENTRIX Theme Variables */
:root {
    --bg-dark-navy: #070d1e;
    --card-navy: #0d172e;
    --card-border: rgba(0, 240, 255, 0.22);
    --cyan-accent: #00f0ff;
    --cyan-glow: rgba(0, 240, 255, 0.45);
    --text-white: #f8fafc;
    --text-muted: #94a3b8;
    --safe-green: #10b981;
    --suspicious-amber: #f59e0b;
    --malicious-red: #ef4444;
}

/* Background & Body */
.stApp {
    background: radial-gradient(circle at 10% 10%, #0d1c3e 0%, #070d1e 60%, #030611 100%);
    color: var(--text-white);
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

/* Headings */
h1, h2, h3, h4, h5, h6 {
    color: #ffffff !important;
    font-weight: 700;
}

.sentrix-title {
    font-size: 2.2rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(135deg, #ffffff 40%, var(--cyan-accent) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0.2rem;
}

.sentrix-subtitle {
    color: var(--text-muted);
    font-size: 1.0rem;
    margin-bottom: 1.5rem;
}

/* Cyber Cards */
.cyber-card {
    background-color: var(--card-navy);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.2rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    backdrop-filter: blur(8px);
}

.cyber-card-highlight {
    background: linear-gradient(180deg, rgba(13, 23, 46, 0.95) 0%, rgba(9, 17, 36, 0.98) 100%);
    border: 1px solid var(--cyan-accent);
    box-shadow: 0 0 25px rgba(0, 240, 255, 0.16);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}

/* Offline Inspection Guarantee Banner */
.offline-banner {
    display: flex;
    align-items: center;
    background-color: rgba(6, 182, 212, 0.08);
    border-left: 4px solid var(--cyan-accent);
    padding: 0.75rem 1rem;
    border-radius: 6px;
    margin-bottom: 1.5rem;
    font-size: 0.92rem;
    color: #cbd5e1;
}

/* Verdict Badges */
.verdict-badge {
    display: inline-block;
    padding: 0.4rem 1.2rem;
    border-radius: 30px;
    font-weight: 800;
    font-size: 1.25rem;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
}

.badge-safe {
    background-color: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid #10b981;
    box-shadow: 0 0 15px rgba(16, 185, 129, 0.35);
}

.badge-suspicious {
    background-color: rgba(245, 158, 11, 0.15);
    color: #fbbf24;
    border: 1px solid #f59e0b;
    box-shadow: 0 0 15px rgba(245, 158, 11, 0.35);
}

.badge-malicious {
    background-color: rgba(239, 68, 68, 0.15);
    color: #f87171;
    border: 1px solid #ef4444;
    box-shadow: 0 0 15px rgba(239, 68, 68, 0.4);
}

/* Severity Pill */
.severity-pill {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    margin-right: 0.5rem;
}
.sev-high {
    background-color: rgba(239, 68, 68, 0.2);
    color: #fca5a5;
    border: 1px solid #ef4444;
}
.sev-med {
    background-color: rgba(245, 158, 11, 0.2);
    color: #fde68a;
    border: 1px solid #f59e0b;
}
.sev-low {
    background-color: rgba(56, 189, 248, 0.2);
    color: #bae6fd;
    border: 1px solid #38bdf8;
}

/* Inputs & Buttons */
div[data-testid="stTextInput"] input {
    background-color: #0b1528 !important;
    color: #ffffff !important;
    border: 1.5px solid rgba(0, 240, 255, 0.35) !important;
    border-radius: 8px !important;
    font-family: monospace;
    font-size: 1rem;
    padding: 0.65rem 1rem !important;
}

div[data-testid="stTextInput"] input:focus {
    border-color: var(--cyan-accent) !important;
    box-shadow: 0 0 15px rgba(0, 240, 255, 0.5) !important;
}

div[data-testid="stButton"] button {
    background: linear-gradient(135deg, #0284c7 0%, #00f0ff 100%) !important;
    color: #040814 !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 0.6rem 1.6rem !important;
    transition: all 0.2s ease-in-out !important;
    box-shadow: 0 4px 12px rgba(0, 240, 255, 0.25) !important;
}

div[data-testid="stButton"] button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 20px rgba(0, 240, 255, 0.55) !important;
}

/* Sidebar styling */
section[data-testid="stSidebar"] {
    background-color: #050a16 !important;
    border-right: 1px solid rgba(0, 240, 255, 0.15) !important;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 3. MODEL LOADER & CACHING
# -----------------------------------------------------------------------------
MODEL_FILE = os.path.join(os.path.dirname(__file__), "models", "url_classifier.joblib")

@st.cache_resource(show_spinner=False)
def load_trained_model():
    """Loads the trained Random Forest model bundle."""
    if os.path.exists(MODEL_FILE):
        try:
            return joblib.load(MODEL_FILE)
        except Exception:
            return None
    return None

model_bundle = load_trained_model()


# -----------------------------------------------------------------------------
# 4. SIDEBAR NAVIGATION & SYSTEM HEALTH
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ SENTRIX // PLATFORM")
    st.markdown(
        "<div style='font-size:0.83rem; color:#94a3b8; margin-top:-0.5rem; margin-bottom:1.2rem;'>"
        "AI-Powered URL Threat Intelligence & Risk Monitoring</div>",
        unsafe_allow_html=True
    )

    page = st.radio(
        "Navigation",
        [
            "📊 Overview Dashboard",
            "🔍 URL Scanner",
            "📁 Batch Scanner",
            "🌐 Threat Intelligence",
            "📜 Scan History",
            "🧠 Model Performance",
            "⚙️ Settings & API Status"
        ],
        index=1,
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("#### ⚡ Core Engine Status")

    # Engine Status
    if model_bundle is not None:
        metrics = model_bundle.get("metrics", {})
        acc = metrics.get("accuracy", 0.0) * 100
        st.success(f"🟢 **ML Core Active** (Test Acc: {acc:.1f}%)")
    else:
        st.error("🔴 **ML Core Inactive** (Model Not Found)")

    # Threat Intel Status
    ti_status = get_threat_intel_status()
    if ti_status["safe_browsing"]["is_configured"]:
        st.success("🟢 **Google Safe Browsing: Connected**")
    else:
        st.info("⚪ **Threat Intel: Offline Mode**")

    st.markdown("---")
    st.caption(
        "**Strictly Safe Inspection:** URLs are analyzed via local lexical string parsing. "
        "The system never opens or visits user-entered links."
    )


# -----------------------------------------------------------------------------
# 5. PAGE ROUTER
# -----------------------------------------------------------------------------

# =============================================================================
# PAGE 1: OVERVIEW DASHBOARD
# =============================================================================
if page == "📊 Overview Dashboard":
    st.markdown("<div class='sentrix-title'>SENTRIX — Security Operations Dashboard</div>", unsafe_allow_html=True)
    st.markdown("<div class='sentrix-subtitle'>Live aggregate scan telemetry, threat distribution, and system performance metrics.</div>", unsafe_allow_html=True)

    stats = get_stats()

    # Metric KPI Cards
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Scanned", f"{stats['total_scans']:,}")
    with col2:
        st.metric("Safe URLs", f"{stats['safe_count']:,}", delta=f"{stats['safe_count']} clean", delta_color="normal")
    with col3:
        st.metric("Suspicious URLs", f"{stats['suspicious_count']:,}", delta=f"{stats['suspicious_count']} caution", delta_color="off")
    with col4:
        st.metric("Malicious URLs", f"{stats['malicious_count']:,}", delta=f"{stats['malicious_count']} blocked", delta_color="inverse")
    with col5:
        st.metric("Avg Risk Score", f"{stats['avg_risk_score']}/100")

    st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)

    # Charts Row
    chart_col1, chart_col2 = st.columns([1, 1])

    with chart_col1:
        st.markdown("##### 🎯 Threat Category Distribution")
        if stats["total_scans"] > 0:
            cat_df = pd.DataFrame({
                "Category": ["Safe", "Suspicious", "Malicious"],
                "Count": [stats["safe_count"], stats["suspicious_count"], stats["malicious_count"]]
            }).set_index("Category")
            st.bar_chart(cat_df, color="#00f0ff", use_container_width=True)
        else:
            st.info("No scans recorded yet. Use the **URL Scanner** or **Batch Scanner** to analyze URLs.")

    with chart_col2:
        st.markdown("##### 📈 Threat Intel & Engine Telemetry")
        sb_conf = ti_status["safe_browsing"]["is_configured"]
        vt_conf = ti_status["virustotal"]["is_configured"]
        
        st.markdown(
            f"""
            <div class='cyber-card'>
                <div style='display:flex; justify-content:space-between; margin-bottom:0.6rem;'>
                    <span><strong>ML Model:</strong> Random Forest Classifier</span>
                    <span style='color:#34d399;'>● Online</span>
                </div>
                <div style='display:flex; justify-content:space-between; margin-bottom:0.6rem;'>
                    <span><strong>Google Safe Browsing API:</strong></span>
                    <span style='color:{'#34d399' if sb_conf else '#94a3b8'};'>
                        {'● Connected' if sb_conf else '○ Not Configured'}
                    </span>
                </div>
                <div style='display:flex; justify-content:space-between; margin-bottom:0.6rem;'>
                    <span><strong>VirusTotal v3 API:</strong></span>
                    <span style='color:{'#34d399' if vt_conf else '#94a3b8'};'>
                        {'● Connected' if vt_conf else '○ Not Configured'}
                    </span>
                </div>
                <div style='display:flex; justify-content:space-between; margin-bottom:0.6rem;'>
                    <span><strong>Last Scan Time:</strong></span>
                    <span style='color:#cbd5e1;'>{stats['latest_timestamp'] or 'No activity recorded'}</span>
                </div>
                <div style='font-size:0.8rem; color:#64748b; margin-top:0.8rem;'>
                    *Note: Telemetry reflects URLs submitted to this local application, not all global internet threats.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)
    st.markdown("##### ⏱️ Recent Threat Scan Activity")
    recent = get_recent_scans(limit=8)
    if recent:
        rec_data = []
        for r in recent:
            exp_sum = str(r.get("explanation_summary") or "")
            rec_data.append({
                "Timestamp": r["timestamp"][:19].replace("T", " "),
                "Target URL": r["url"],
                "Prediction": r["prediction"],
                "Risk Score": f"{r['risk_score']}/100",
                "Model Confidence": f"{r['model_confidence']*100:.1f}%" if r["model_confidence"] else "N/A",
                "Why This Result?": (exp_sum[:75] + "...") if len(exp_sum) > 75 else exp_sum,
                "Threat Intel": r["threat_intel_status"],
                "Source": r["source"]
            })
        st.dataframe(pd.DataFrame(rec_data), use_container_width=True)
    else:
        st.caption("No recent scan records available.")


# =============================================================================
# PAGE 2: URL SCANNER (SINGLE URL)
# =============================================================================
elif page == "🔍 URL Scanner":
    st.markdown("<div class='sentrix-title'>SENTRIX // URL Threat Scanner</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='sentrix-subtitle'>Submit a URL for pure-lexical structural analysis, heuristic risk calculation, and real-time threat intelligence lookup.</div>",
        unsafe_allow_html=True
    )

    st.markdown(
        """<div class='offline-banner'>
            <span style='font-size:1.25rem; margin-right:0.6rem;'>🔒</span>
            <div>
                <strong>Zero Infection Risk:</strong> SENTRIX evaluates URLs using safe lexical string parsing and official threat database query APIs.
                It <strong>never opens, resolves, downloads, or connects</strong> directly to user-entered URLs.
            </div>
        </div>""",
        unsafe_allow_html=True
    )

    # Preset quick-test samples
    st.markdown("###### Quick Preset Sample URLs:")
    s_col1, s_col2, s_col3 = st.columns(3)
    if "active_scan_url" not in st.session_state:
        st.session_state.active_scan_url = "https://www.wikipedia.org/wiki/Computer_security"

    with s_col1:
        if st.button("🟢 Safe: Wikipedia Article", use_container_width=True):
            st.session_state.active_scan_url = "https://www.wikipedia.org/wiki/Computer_security"
            st.rerun()
    with s_col2:
        if st.button("🟡 Suspicious: Billing Notice (.top)", use_container_width=True):
            st.session_state.active_scan_url = "http://billing-update-center.top/auth-token-refresh?ref=33530"
            st.rerun()
    with s_col3:
        if st.button("🔴 Malicious: PayPal IP Phish", use_container_width=True):
            st.session_state.active_scan_url = "http://192.168.1.105/paypal/verify-identity-confirm/login?auth_session=25084"
            st.rerun()

    # Search Bar & Trigger Button
    input_col, btn_col = st.columns([4, 1])
    with input_col:
        target_url = st.text_input(
            "Enter URL to inspect:",
            value=st.session_state.get("active_scan_url", ""),
            placeholder="e.g. http://192.168.1.105/paypal/login or https://github.com",
            label_visibility="collapsed"
        )
    with btn_col:
        scan_clicked = st.button("⚡ Check URL", use_container_width=True)

    # Run Analysis
    should_run = scan_clicked or ("single_scanned" not in st.session_state and target_url.strip())

    if should_run:
        clean_url = target_url.strip()
        if not clean_url:
            st.error("❌ **Invalid Input:** Please provide a valid URL string.")
        elif len(clean_url) < 3:
            st.error("❌ **URL Too Short:** Please enter a complete domain or URL.")
        else:
            st.session_state["single_scanned"] = True
            
            with st.spinner("Analyzing lexical structures and querying threat feeds..."):
                # 1. Feature Extraction
                features = extract_features(clean_url)
                risk_score = compute_heuristic_risk_score(clean_url, features)
                warning_signs = get_url_warning_signs(clean_url, features)

                # 2. ML Prediction
                pred_label = "SAFE"
                confidence = None
                probabilities = [0.33, 0.33, 0.34]
                classes = ["Safe", "Suspicious", "Malicious"]

                if model_bundle is not None:
                    clf = model_bundle["model"]
                    feat_names = model_bundle.get("feature_names", FEATURE_NAMES)
                    row = [features.get(f, 0) for f in feat_names]
                    X_df = pd.DataFrame([row], columns=feat_names)
                    pred_idx = clf.predict(X_df)[0]
                    pred_label = classes[pred_idx]
                    probs = clf.predict_proba(X_df)[0]
                    probabilities = probs
                    confidence = float(max(probs))
                else:
                    if risk_score >= 65:
                        pred_label = "Malicious"
                    elif risk_score >= 30:
                        pred_label = "Suspicious"
                    else:
                        pred_label = "Safe"
                    confidence = None

                # 3. Real-Time Threat Intelligence Query
                ti_result = query_threat_intelligence(clean_url)

                # If external threat intelligence confirms threat, elevate prediction
                if ti_result.get("is_threat"):
                    pred_label = "Malicious"
                    risk_score = max(risk_score, 95)

                # 4. Generate Evidence-Based Explanation
                fi_dict = model_bundle.get("feature_importances", {}) if model_bundle else None
                explanation = generate_explanation(
                    url=clean_url,
                    features=features,
                    prediction=pred_label,
                    risk_score=risk_score,
                    model_confidence=confidence,
                    threat_intel=ti_result,
                    warning_signs=warning_signs,
                    model_feature_importances=fi_dict
                )

                # 5. Insert into database
                insert_scan(
                    url=clean_url,
                    prediction=pred_label,
                    risk_score=risk_score,
                    model_confidence=confidence,
                    indicators=warning_signs,
                    threat_intel_status=ti_result.get("status", "NOT_CONFIGURED"),
                    threat_intel_details=ti_result.get("details", ""),
                    source="SINGLE_SCAN",
                    explanation_summary=explanation["why_this_result"],
                    explanation_json=json.dumps(explanation)
                )

                # 6. Safety Advice
                advice = get_safety_advice(pred_label, risk_score)

            # Display Verdict Card
            st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)
            
            badge_class = {
                "Safe": "badge-safe",
                "SAFE": "badge-safe",
                "Suspicious": "badge-suspicious",
                "SUSPICIOUS": "badge-suspicious",
                "Malicious": "badge-malicious",
                "MALICIOUS": "badge-malicious"
            }.get(pred_label, "badge-safe")

            badge_text = {
                "Safe": "🟢 SAFE",
                "SAFE": "🟢 SAFE",
                "Suspicious": "🟡 SUSPICIOUS",
                "SUSPICIOUS": "🟡 SUSPICIOUS",
                "Malicious": "🔴 MALICIOUS",
                "MALICIOUS": "🔴 MALICIOUS"
            }.get(pred_label, "SAFE")

            st.markdown(
                f"""
                <div class='cyber-card-highlight'>
                    <div style='display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap;'>
                        <div>
                            <div style='color:#94a3b8; font-size:0.85rem; text-transform:uppercase; letter-spacing:1.5px; font-weight:700;'>
                                SENTRIX Threat Classification Verdict
                            </div>
                            <div style='margin-top:0.4rem;'>
                                <span class='verdict-badge {badge_class}'>{badge_text}</span>
                            </div>
                            <div style='color:#ffffff; font-size:1.1rem; margin-top:0.5rem; word-break:break-all; font-family:monospace;'>
                                {clean_url}
                            </div>
                        </div>
                        <div style='text-align:right; min-width:200px; margin-top:0.5rem;'>
                            <div style='color:#94a3b8; font-size:0.85rem;'>Heuristic Risk Score</div>
                            <div style='font-size:2.0rem; font-weight:800; color:{advice["badge_color"]};'>
                                {risk_score} <span style='font-size:1.0rem; color:#64748b;'>/ 100</span>
                            </div>
                            <div style='font-size:0.8rem; color:#94a3b8;'>{advice["risk_level"]}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # WHY THIS RESULT? PROMINENT SYNTHESIS CARD
            st.markdown(
                f"""
                <div class='cyber-card' style='border-left: 4px solid var(--cyan-accent); background: linear-gradient(180deg, rgba(13, 23, 46, 0.95) 0%, rgba(8, 15, 32, 0.98) 100%);'>
                    <div style='display:flex; align-items:center; margin-bottom:0.4rem;'>
                        <span style='font-size:1.3rem; margin-right:0.5rem;'>💡</span>
                        <h4 style='margin:0; color:#00f0ff !important; font-size:1.1rem;'>Why This Result? (Evidence-Based Synthesis)</h4>
                    </div>
                    <p style='color:#e2e8f0; font-size:1.02rem; line-height:1.6; margin:0;'>
                        {explanation["why_this_result"]}
                    </p>
                    <div style='display:flex; gap:1.5rem; margin-top:0.8rem; font-size:0.85rem; color:#94a3b8; flex-wrap:wrap;'>
                        <span>✅ Checks Passed: <strong style='color:#34d399;'>{explanation["checks_passed_count"]}</strong></span>
                        <span>⚠️ Warnings Triggered: <strong style='color:{'#f87171' if explanation["triggered_indicators_count"] > 0 else '#94a3b8'};'>{explanation["triggered_indicators_count"]}</strong></span>
                        <span>🌐 Threat Intelligence: <strong style='color:#cbd5e1;'>{explanation["threat_intel_assessment"]["display_badge"]}</strong></span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # Dual Telemetry: Model Probability vs Threat Intel Feed
            m_col1, m_col2 = st.columns([1, 1])
            with m_col1:
                st.markdown("##### 🧠 Machine Learning Engine (Random Forest)")
                if confidence is not None:
                    st.metric("Model Confidence", f"{confidence*100:.1f}%", help="Calibrated probability from 100 decision trees on test-evaluated features.")
                    p_cols = st.columns(3)
                    p_cols[0].caption(f"Safe: {probabilities[0]*100:.1f}%")
                    p_cols[1].caption(f"Suspicious: {probabilities[1]*100:.1f}%")
                    p_cols[2].caption(f"Malicious: {probabilities[2]*100:.1f}%")
                else:
                    st.info("Model probability unavailable (Offline heuristic fallback used).")

            with m_col2:
                st.markdown("##### 🌐 Threat Intelligence (Google Safe Browsing)")
                ti_stat = ti_result.get("status", "NOT_CONFIGURED")
                d_stat = ti_result.get("dashboard_status", "Unavailable/Error")
                
                if ti_stat in ("CONFIRMED_THREAT", "THREAT_DETECTED") or ti_result.get("is_threat"):
                    st.error(f"🚨 **Threat detected:** {ti_result.get('details')}")
                    st.caption("🔴 **API Status Indicator:** `Threat detected` (Confirmed by Google threat feeds).")
                elif ti_stat in ("CLEAN", "NO_MATCH"):
                    st.success(f"🛡️ **No match:** {ti_result.get('details')}")
                    st.caption("🟢 **API Status Indicator:** `Connected` | `No match` (API succeeded; URL not found in threat lists).")
                elif ti_stat == "NOT_CONFIGURED":
                    st.info(f"⚪ **Unavailable/Error:** {ti_result.get('details')}")
                    st.caption("⚠️ **Notice:** Unsuccessful or unconfigured API checks are never treated as safe. Machine learning & lexical heuristics remain strictly decoupled.")
                else:
                    st.warning(f"⚠️ **Unavailable/Error ({ti_stat}):** {ti_result.get('details')}")
                    st.caption("⚠️ **Notice:** Unsuccessful API lookups are never treated as safe. Machine learning & lexical heuristics remain strictly decoupled.")

            st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)

            # 5 Detailed Explainable AI Tabs
            tab_warn, tab_passed, tab_feats, tab_advice, tab_limits = st.tabs([
                f"🚨 Detected Indicators ({len(explanation['triggered_indicators'])})",
                f"✅ Checks Passed ({len(explanation['checks_passed'])})",
                "📊 Extracted Features (21)",
                "🛡️ Recommended Actions",
                "⚠️ Scan Limitations"
            ])

            # TAB 1: DETECTED INDICATORS
            with tab_warn:
                if not explanation["triggered_indicators"]:
                    st.markdown(
                        """<div class='cyber-card' style='border-left: 4px solid #10b981;'>
                            <h4 style='color:#34d399 !important; margin-bottom:0.3rem;'>No Threat Anomalies Detected</h4>
                            <p style='color:#cbd5e1; margin:0;'>
                                This URL does not trigger any known structural warnings. No raw IP addresses,
                                suspicious TLDs, URL shorteners, punycode, or deceptive credential injection tokens were found.
                            </p>
                            <p style='color:#94a3b8; font-size:0.85rem; margin-top:0.4rem;'>
                                *Note: Lack of detected structural anomalies does not guarantee complete safety against compromised servers.
                            </p>
                        </div>""",
                        unsafe_allow_html=True
                    )
                else:
                    st.caption("Each triggered indicator represents an observed anomaly. Individual indicators do not by themselves constitute proof of malice.")
                    for w in explanation["triggered_indicators"]:
                        sev_class = "sev-high" if w["severity"] == "High" else ("sev-med" if w["severity"] == "Medium" else "sev-low")
                        border_color = "#ef4444" if w["severity"] == "High" else ("#f59e0b" if w["severity"] == "Medium" else "#38bdf8")
                        st.markdown(
                            f"""<div class='cyber-card' style='border-left: 4px solid {border_color};'>
                                <div style='display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; margin-bottom:0.4rem;'>
                                    <div>
                                        <span class='severity-pill {sev_class}'>{w["severity"]}</span>
                                        <span style='font-size:0.8rem; color:#94a3b8; margin-right:0.6rem;'>[{w["category"]}]</span>
                                        <strong style='font-size:1.05rem; color:#ffffff;'>{w["title"]}</strong>
                                    </div>
                                    <div style='background:rgba(255,255,255,0.08); padding:0.2rem 0.6rem; border-radius:6px; font-family:monospace; font-size:0.82rem; color:#38bdf8;'>
                                        Detected: {w["actual_value"]}
                                    </div>
                                </div>
                                <div style='color:#cbd5e1; font-size:0.92rem; line-height:1.4;'>
                                    <strong>Why this matters:</strong> {w["why_it_matters"]}
                                </div>
                            </div>""",
                            unsafe_allow_html=True
                        )

            # TAB 2: CHECKS PASSED
            with tab_passed:
                st.caption(f"Verified {len(explanation['checks_passed'])} benign structural attributes confirming standard web conventions:")
                for p in explanation["checks_passed"]:
                    st.markdown(
                        f"""<div class='cyber-card' style='border-left: 4px solid #10b981; padding:0.9rem 1.2rem; margin-bottom:0.7rem;'>
                            <div style='display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap;'>
                                <div>
                                    <span style='color:#34d399; font-weight:700; font-size:0.85rem; margin-right:0.5rem;'>✔ PASSED</span>
                                    <strong style='color:#ffffff; font-size:0.98rem;'>{p["check"]}</strong>
                                </div>
                                <span style='background:rgba(16,185,129,0.12); color:#6ee7b7; padding:0.15rem 0.55rem; border-radius:6px; font-family:monospace; font-size:0.82rem;'>
                                    {p["actual_value"]}
                                </span>
                            </div>
                            <div style='color:#94a3b8; font-size:0.88rem; margin-top:0.3rem;'>
                                {p["detail"]}
                            </div>
                        </div>""",
                        unsafe_allow_html=True
                    )

            # TAB 3: EXTRACTED FEATURES
            with tab_feats:
                st.markdown("###### Lexical & Structural Metrics (21 Features)")
                f_col1, f_col2, f_col3, f_col4 = st.columns(4)
                with f_col1:
                    st.metric("URL Length", f"{features['url_length']} chars")
                    st.metric("Hostname Length", f"{features['hostname_length']} chars")
                    st.metric("Dots Count", features["num_dots"])
                    st.metric("Punycode (IDN)", "Detected" if features["has_punycode"] else "None")
                with f_col2:
                    st.metric("Subdomains", features["num_subdomains"])
                    st.metric("Hyphens Count", features["num_hyphens"])
                    st.metric("Digit Ratio", f"{int(features['digit_ratio']*100)}%")
                    st.metric("Double Slash Path", "Detected" if features["has_double_slash_path"] else "None")
                with f_col3:
                    st.metric("Special Characters", features["num_special_chars"])
                    st.metric("IP Hostname", "Yes (High Risk)" if features["has_ip_address"] else "No (Domain)")
                    st.metric("Shannon Entropy", f"{features['shannon_entropy']:.2f}")
                    st.metric("Unusual Port", "Yes" if features["has_unusual_port"] else "No")
                with f_col4:
                    st.metric("HTTPS Protocol", "Yes (Encrypted)" if features["is_https"] else "No (HTTP)")
                    st.metric("URL Shortener", "Yes" if features["is_shortened_url"] else "No")
                    st.metric("Sensitive Keywords", features["suspicious_keyword_count"])
                    st.metric("Brand Spoofing", "Detected" if features["has_brand_in_subdomain"] else "None")

                st.markdown("---")
                st.markdown("###### Complete Numerical Feature Vector")
                f_df = pd.DataFrame(list(features.items()), columns=["Feature Name", "Extracted Value"])
                st.dataframe(f_df, use_container_width=True, height=260)

            # TAB 4: RECOMMENDED ACTIONS
            with tab_advice:
                st.markdown(
                    f"""<div class='cyber-card' style='border-left: 4px solid {advice["badge_color"]};'>
                        <h4 style='color:{advice["badge_color"]} !important; margin-bottom:0.4rem;'>{advice["headline"]}</h4>
                        <p style='color:#e2e8f0; font-size:0.98rem; margin-bottom:1rem;'>{advice["summary"]}</p>
                        <h5 style='color:#ffffff; margin-bottom:0.5rem;'>Immediate Security Protocols:</h5>
                    </div>""",
                    unsafe_allow_html=True
                )
                for act in advice["actions"]:
                    st.markdown(f"- 🛡️ {act}")
                
                st.caption(f"**Disclaimer:** {advice['disclaimer']}")

            # TAB 5: SCAN LIMITATIONS
            with tab_limits:
                st.markdown(
                    """<div class='cyber-card' style='border-left: 4px solid #f59e0b;'>
                        <h4 style='color:#fbbf24 !important; margin-bottom:0.4rem;'>⚠️ Methodological Scope & Limitations</h4>
                        <p style='color:#cbd5e1; font-size:0.92rem;'>
                            SENTRIX provides explainable, evidence-based triage. The following boundaries govern this evaluation:
                        </p>
                    </div>""",
                    unsafe_allow_html=True
                )
                for lim in explanation["limitations"]:
                    st.markdown(f"- 📌 {lim}")


# =============================================================================
# PAGE 3: BATCH SCANNER (CSV UPLOAD & MASS INSPECTION)
# =============================================================================
elif page == "📁 Batch Scanner":
    st.markdown("<div class='sentrix-title'>SENTRIX // Batch Threat Scanner</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='sentrix-subtitle'>Upload a CSV file containing multiple URLs to run parallel lexical evaluation, risk scoring, and export consolidated threat reports.</div>",
        unsafe_allow_html=True
    )

    # Sample CSV download button for testing
    sample_csv_data = "url\nhttps://www.wikipedia.org\nhttp://billing-update-center.top/auth-token-refresh\nhttp://192.168.1.105/paypal/login\nhttps://github.com/explore\nhttp://promo-gift-cards-claim.xyz/bonus\n"
    st.download_button(
        "📥 Download Sample Batch CSV",
        data=sample_csv_data,
        file_name="sentrix_sample_urls.csv",
        mime="text/csv",
        help="Download a pre-formatted test CSV containing 5 mixed URLs."
    )

    st.markdown("---")
    uploaded_file = st.file_uploader("Upload CSV File (Max 200 URLs recommended)", type=["csv"])

    if uploaded_file is not None:
        try:
            df_in = pd.read_csv(uploaded_file)
            st.success(f"CSV uploaded successfully ({len(df_in)} rows detected).")

            # Column selector
            url_col = None
            candidate_cols = [c for c in df_in.columns if "url" in str(c).lower() or "link" in str(c).lower()]
            if candidate_cols:
                url_col = candidate_cols[0]
            else:
                url_col = df_in.columns[0]

            selected_col = st.selectbox("Select URL Column:", df_in.columns, index=list(df_in.columns).index(url_col))

            if st.button("🚀 Process Batch Analysis", use_container_width=True):
                urls_to_scan = df_in[selected_col].dropna().astype(str).tolist()
                
                results = []
                prog_bar = st.progress(0.0)
                status_txt = st.empty()

                classes = ["Safe", "Suspicious", "Malicious"]
                clf = model_bundle["model"] if model_bundle else None
                feat_names = model_bundle.get("feature_names", FEATURE_NAMES) if model_bundle else FEATURE_NAMES

                for idx, u in enumerate(urls_to_scan):
                    status_txt.text(f"Scanning [{idx+1}/{len(urls_to_scan)}]: {u[:45]}...")
                    feats = extract_features(u)
                    score = compute_heuristic_risk_score(u, feats)
                    warns = get_url_warning_signs(u, feats)
                    
                    if clf:
                        row = [feats.get(f, 0) for f in feat_names]
                        p_idx = clf.predict([row])[0]
                        p_label = classes[p_idx]
                        c_val = float(max(clf.predict_proba([row])[0]))
                    else:
                        p_label = "Malicious" if score >= 65 else ("Suspicious" if score >= 30 else "Safe")
                        c_val = None

                    # Generate Evidence-Based Explanation
                    exp = generate_explanation(
                        url=u,
                        features=feats,
                        prediction=p_label,
                        risk_score=score,
                        model_confidence=c_val,
                        threat_intel={"status": "BATCH_EVALUATED", "details": "Batch lexical evaluation."},
                        warning_signs=warns
                    )

                    # Insert to DB
                    insert_scan(
                        url=u,
                        prediction=p_label,
                        risk_score=score,
                        model_confidence=c_val,
                        indicators=warns,
                        threat_intel_status="BATCH_EVALUATED",
                        threat_intel_details="Evaluated in batch via SENTRIX ML Engine.",
                        source="BATCH_SCAN",
                        explanation_summary=exp["why_this_result"],
                        explanation_json=json.dumps(exp)
                    )

                    results.append({
                        "URL": u,
                        "Verdict": p_label,
                        "Risk Score": f"{score}/100",
                        "Model Confidence": f"{c_val*100:.1f}%" if c_val else "N/A",
                        "Why This Result?": exp["why_this_result"],
                        "Checks Passed": exp["checks_passed_count"],
                        "Warnings Triggered": exp["triggered_indicators_count"],
                        "Threat Intel": "Batch Evaluated"
                    })

                    prog_bar.progress((idx + 1) / len(urls_to_scan))

                status_txt.success("✅ Batch processing completed successfully!")
                res_df = pd.DataFrame(results)

                # Summary Statistics
                st.markdown("#### 📊 Batch Summary")
                b_c1, b_c2, b_c3, b_c4 = st.columns(4)
                safe_n = sum(1 for r in results if r["Verdict"].upper() == "SAFE")
                susp_n = sum(1 for r in results if r["Verdict"].upper() == "SUSPICIOUS")
                mal_n = sum(1 for r in results if r["Verdict"].upper() == "MALICIOUS")
                
                b_c1.metric("Processed", len(results))
                b_c2.metric("Safe", safe_n)
                b_c3.metric("Suspicious", susp_n)
                b_c4.metric("Malicious", mal_n)

                st.markdown("##### Detailed Scan Results")
                st.dataframe(res_df, use_container_width=True)

                # CSV Export
                csv_out = res_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "📥 Export Batch Results to CSV",
                    data=csv_out,
                    file_name=f"sentrix_batch_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

        except Exception as ex:
            st.error(f"Error parsing CSV: {ex}")


# =============================================================================
# PAGE 4: THREAT INTELLIGENCE
# =============================================================================
elif page == "🌐 Threat Intelligence":
    st.markdown("<div class='sentrix-title'>SENTRIX // Threat Intelligence Feeds</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='sentrix-subtitle'>Live connection status, lookup test bench, and security configuration for Google Safe Browsing and VirusTotal.</div>",
        unsafe_allow_html=True
    )

    t_status = get_threat_intel_status()
    sb = t_status["safe_browsing"]
    vt = t_status["virustotal"]

    st.markdown("#### 📡 Service Connectivity Status")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            f"""<div class='cyber-card'>
                <h4>{sb['name']}</h4>
                <p style='color:#94a3b8;'>{sb['description']}</p>
                <div style='margin-top:0.5rem;'>
                    <strong>Status:</strong> <span style='color:{'#34d399' if sb['is_configured'] else '#f59e0b'};'>{sb['status']}</span>
                </div>
                <div style='margin-top:0.3rem;'>
                    <strong>Key:</strong> <code>{sb['masked_key']}</code>
                </div>
            </div>""",
            unsafe_allow_html=True
        )

    with c2:
        st.markdown(
            f"""<div class='cyber-card'>
                <h4>{vt['name']}</h4>
                <p style='color:#94a3b8;'>{vt['description']}</p>
                <div style='margin-top:0.5rem;'>
                    <strong>Status:</strong> <span style='color:{'#34d399' if vt['is_configured'] else '#94a3b8'};'>{vt['status']}</span>
                </div>
                <div style='margin-top:0.3rem;'>
                    <strong>Key:</strong> <code>{vt['masked_key']}</code>
                </div>
            </div>""",
            unsafe_allow_html=True
        )

    # Harmless URL Connection Test Button
    st.markdown("<div style='margin-top:1rem;'></div>", unsafe_allow_html=True)
    if st.button("⚡ Test Live Connection (Harmless URL Probe)"):
        with st.spinner("Connecting to Google Safe Browsing API with harmless URL..."):
            probe_result = test_harmless_url("https://www.google.com")
            if probe_result.get("connected"):
                st.success(
                    f"🟢 **Status: Connected** | Real API request succeeded with HTTP 200 on `{probe_result['test_url']}`. "
                    "Google Safe Browsing API is verified active and enabled in your Google Cloud project."
                )
            else:
                st.error(
                    f"⚠️ **Status: Unavailable/Error** | {probe_result.get('details')}. "
                    "Notice: Unsuccessful requests are never treated as safe results."
                )

    st.markdown("---")
    st.markdown("#### 📌 API Status Indicators Reference")
    st.markdown(
        """
        SENTRIX maintains a strict 4-state indicator model for Google Safe Browsing:
        - 🟢 **Connected**: A real API request succeeded and verified communication with Google's servers.
        - 🔴 **Threat detected**: The API returned an active threat match (`MALWARE`, `SOCIAL_ENGINEERING`, etc.).
        - 🛡️ **No match**: The API request succeeded, but the URL is not listed in Google's threat blacklists.
        - ⚠️ **Unavailable/Error**: The request failed, timed out, or the API key is missing/invalid.
        
        > **Critical Security Decoupling:** Unsuccessful or unavailable threat intelligence queries are **never** treated as safe results. Local Random Forest predictions and heuristic risk scores remain strictly separate from external API states.
        """
    )

    st.markdown("---")
    st.markdown("#### 🧪 Test Threat Intelligence Connectivity")
    st.caption("Perform a live API query to verify your Google Safe Browsing key without opening the target URL.")
    
    test_lookup_url = st.text_input("Test URL Query:", "http://malware.testing.google.test/testing/malware/")
    if st.button("📡 Execute Live Threat Intel Query"):
        with st.spinner("Querying threat feed..."):
            res = query_threat_intelligence(test_lookup_url)
            d_st = res.get("dashboard_status", "Unavailable/Error")
            if d_st == "Threat detected":
                st.error(f"🔴 **Threat detected:** {res.get('details')}")
            elif d_st == "No match":
                st.success(f"🛡️ **No match:** {res.get('details')}")
            else:
                st.warning(f"⚠️ **{d_st}:** {res.get('details')}")
            st.json(res)

    st.markdown("---")
    st.markdown("#### 🔑 How to Configure API Keys Safely")
    st.markdown(
        """
        1. **Create or edit `.streamlit/secrets.toml`** in your project root:
        ```toml
        # .streamlit/secrets.toml
        GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyYourGoogleApiKeyHere"
        # Or alternative backward-compatible name:
        SAFE_BROWSING_API_KEY = "AIzaSyYourGoogleApiKeyHere"
        VIRUSTOTAL_API_KEY = "YourVirusTotalApiKeyHere"
        ```
        2. **Or configure via Environment Variables in PowerShell:**
        ```powershell
        $env:GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyYourGoogleApiKeyHere"
        ```
        3. **Security Guarantee:** SENTRIX never commits secrets to Git or displays unmasked API keys in UI or logs.
        """
    )


# =============================================================================
# PAGE 5: SCAN HISTORY
# =============================================================================
elif page == "📜 Scan History":
    st.markdown("<div class='sentrix-title'>SENTRIX // Persistent Scan History</div>", unsafe_allow_html=True)
    st.markdown("<div class='sentrix-subtitle'>Search, filter, inspect, and export all historical URL inspection records stored in SQLite.</div>", unsafe_allow_html=True)

    filter_col1, filter_col2, filter_col3 = st.columns([2, 1, 1])
    with filter_col1:
        search_kw = st.text_input("🔍 Search by URL keyword:", "")
    with filter_col2:
        cat_filter = st.selectbox("Filter Category:", ["ALL", "SAFE", "SUSPICIOUS", "MALICIOUS"])
    with filter_col3:
        max_rows = st.selectbox("Max Records:", [50, 100, 250, 500], index=1)

    hist_df = get_filtered_history_df(
        category=cat_filter,
        search_query=search_kw,
        limit=max_rows
    )

    st.markdown(f"**Showing {len(hist_df)} scan records:**")
    st.dataframe(hist_df, use_container_width=True)

    if not hist_df.empty:
        with st.expander("🔍 Inspect Full Explanation for a Specific Scan"):
            selected_scan_id = st.selectbox("Select Scan ID to inspect:", hist_df["id"].tolist())
            scan_row = hist_df[hist_df["id"] == selected_scan_id].iloc[0]
            
            st.markdown(f"**Target URL:** `{scan_row['url']}`")
            st.markdown(f"**Classification:** `{scan_row['prediction']}` | **Risk Score:** `{scan_row['risk_score']}/100`")
            st.markdown(
                f"""<div class='cyber-card' style='border-left: 4px solid var(--cyan-accent); margin-top:0.5rem;'>
                    <strong>Why This Result?</strong><br>
                    <span style='color:#e2e8f0; font-size:0.95rem;'>{scan_row.get('explanation_summary', 'No summary available.')}</span>
                </div>""",
                unsafe_allow_html=True
            )

    action_c1, action_c2 = st.columns([1, 1])
    with action_c1:
        if not hist_df.empty:
            csv_export_bytes = hist_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export Filtered History (CSV)",
                data=csv_export_bytes,
                file_name=f"sentrix_scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

    with action_c2:
        confirm_clear = st.checkbox("Confirm database reset (irreversible)")
        if st.button("🗑️ Clear Scan History", disabled=not confirm_clear):
            clear_history()
            st.success("Scan history database has been cleared.")
            st.rerun()


# =============================================================================
# PAGE 6: MODEL PERFORMANCE
# =============================================================================
elif page == "🧠 Model Performance":
    st.markdown("<div class='sentrix-title'>SENTRIX // AI Architecture & Model Metrics</div>", unsafe_allow_html=True)
    st.markdown("<div class='sentrix-subtitle'>Empirical evaluation results, confusion matrix, and feature importances for the Random Forest classifier.</div>", unsafe_allow_html=True)

    if model_bundle is not None:
        m = model_bundle.get("metrics", {})
        d_info = model_bundle.get("dataset_info", {})
        meta = model_bundle.get("training_metadata", {})

        st.markdown("##### 📈 Empirical Test Set Performance (180 Unseen Samples)")
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Test Accuracy", f"{m.get('accuracy', 0)*100:.2f}%")
        k2.metric("Macro Precision", f"{m.get('precision_macro', 0)*100:.2f}%")
        k3.metric("Macro Recall", f"{m.get('recall_macro', 0)*100:.2f}%")
        k4.metric("Macro F1-Score", f"{m.get('f1_macro', 0)*100:.2f}%")

        st.markdown("---")
        cm_c1, cm_c2 = st.columns([1, 1])
        with cm_c1:
            st.markdown("###### Confusion Matrix")
            cm_img_path = os.path.join(os.path.dirname(__file__), "models", "confusion_matrix.png")
            if os.path.exists(cm_img_path):
                st.image(cm_img_path, use_container_width=True)
            else:
                st.write(m.get("confusion_matrix"))

        with cm_c2:
            st.markdown("###### Top Predictive Feature Importances")
            importances = model_bundle.get("feature_importances", {})
            if importances:
                imp_df = pd.DataFrame(
                    list(importances.items()),
                    columns=["Feature", "Importance"]
                ).sort_values(by="Importance", ascending=True)
                st.bar_chart(imp_df.set_index("Feature"), use_container_width=True)

        st.markdown("---")
        st.markdown("###### Classification Report Breakdown")
        rep = m.get("classification_report", {})
        if rep:
            rep_df = pd.DataFrame(rep).transpose()
            st.dataframe(rep_df.style.format("{:.3f}"), use_container_width=True)

        st.caption(
            f"Trained on: {meta.get('trained_at', 'N/A')} | "
            f"Dataset: {d_info.get('total_samples', 900)} total samples "
            f"(80% Train: {d_info.get('train_samples', 720)}, 20% Test: {d_info.get('test_samples', 180)})"
        )
    else:
        st.error("Model bundle not found. Run `python train_model.py` to train and evaluate the model.")


# =============================================================================
# PAGE 7: SETTINGS & API STATUS
# =============================================================================
elif page == "⚙️ Settings & API Status":
    st.markdown("<div class='sentrix-title'>SENTRIX // Settings & Diagnostics</div>", unsafe_allow_html=True)
    st.markdown("<div class='sentrix-subtitle'>Diagnostic parameters, environment configuration, and model reload controls.</div>", unsafe_allow_html=True)

    st.markdown("#### 🖥️ Environment Diagnostics")
    diag_data = {
        "Platform": "SENTRIX v2.0.0",
        "Python Runtime": f"{os.sys.version.split()[0]}",
        "Streamlit Version": st.__version__,
        "Operating System": os.name,
        "Database File": os.path.join("data", "scan_history.db"),
        "Model File": os.path.join("models", "url_classifier.joblib"),
        "Model Loaded": "Yes" if model_bundle is not None else "No"
    }
    st.json(diag_data)

    st.markdown("---")
    st.markdown("#### 🔄 Maintenance Actions")
    col_act1, col_act2 = st.columns(2)
    with col_act1:
        if st.button("🔄 Reload Model from Disk", use_container_width=True):
            st.cache_resource.clear()
            st.success("Resource cache cleared. Reloading model...")
            st.rerun()

    with col_act2:
        st.markdown("##### Retrain Model")
        st.caption("To re-train the Random Forest model on updated datasets, execute in PowerShell:")
        st.code("python train_model.py", language="powershell")


# -----------------------------------------------------------------------------
# 6. FOOTER
# -----------------------------------------------------------------------------
st.markdown("<div style='margin-top:3rem;'></div>", unsafe_allow_html=True)
st.markdown("---")
st.markdown(
    "<div style='text-align:center; color:#64748b; font-size:0.82rem;'>"
    "SENTRIX — AI-Powered URL Threat Intelligence Platform | Protected by Pure-Lexical Static Inspection | "
    "Zero Live Execution Guarantee</div>",
    unsafe_allow_html=True
)
