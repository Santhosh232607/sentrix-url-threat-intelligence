# SENTRIX — AI-Powered URL Threat Intelligence
### Real-Time URL Risk Analysis & Cyber Threat Monitoring

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-red.svg)](https://streamlit.io)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-orange.svg)](https://scikit-learn.org)
[![Defense](https://img.shields.io/badge/Security-Pure--Lexical%20Offline-cyan.svg)](#security-first-design)
[![Database](https://img.shields.io/badge/Storage-SQLite-green.svg)](#persistent-scan-history)

**SENTRIX** is a professional, hackathon-ready cybersecurity intelligence platform engineered to classify URLs into **SAFE**, **SUSPICIOUS**, or **MALICIOUS** categories. 

Combining **Random Forest Machine Learning**, **21 pure-lexical structural heuristics**, a **documented 0–100 risk scoring algorithm**, **Google Safe Browsing API threat feeds**, and an **embedded SQLite scan history database**, SENTRIX delivers actionable threat insights with zero risk of malware infection.

---

## 🛡️ Security-First Design (Strictly Offline Inspection)

> [!IMPORTANT]
> **Zero Infection Guarantee:**
> SENTRIX analyzes URLs strictly via client-side string heuristics and official threat intelligence query endpoints. It **never opens, resolves, downloads, or connects directly** to user-submitted URLs. Security analysts and end users can safely inspect active phishing campaigns, raw IP droppers, and ransomware links without triggering payload delivery or alerting threat actors.

---

## 🎯 Three-Class Classification System

SENTRIX rejects binary oversimplification by providing granular threat triage across three distinct classes:

| Category | Color Code | Description | Characteristic Threat Signatures |
| :--- | :---: | :--- | :--- |
| **🟢 SAFE** | Emerald Green | Conforms to standard web standards with legitimate apex domain structures. | Standard path depth, established domain registrar, low entropy, encrypted HTTPS, absence of sensitive credential keywords. |
| **🟡 SUSPICIOUS** | Amber Gold | Displays deceptive anomalies, obfuscation, or elevated risk patterns. | URL shorteners (`bit.ly`, `tinyurl.com`), high-abuse TLDs (`.xyz`, `.top`, `.buzz`), unencrypted HTTP authentication forms, excessive subdomains. |
| **🔴 MALICIOUS** | Crimson Red | Verified attack infrastructure designed for credential theft, malware drops, or C2. | Raw IP hostnames, credential delimiter (`@`) injection, executable download extensions (`.exe`, `.scr`), brand impersonation in subdomains. |

> [!NOTE]
> **Safety Notice:** HTTPS encryption guarantees transport privacy from third-party eavesdroppers, but malicious actors frequently acquire free SSL certificates. **HTTPS alone DOES NOT prove a website is safe.** Furthermore, static lexical analysis evaluates syntactic indicators, but cannot guarantee 100% safety against compromised legitimate domains.

---

## 🧠 Extracted Lexical & Behavioral Features (21 Indicators)

Defined in [`feature_extractor.py`](feature_extractor.py):

1. **`url_length`**: Total character length of the URL.
2. **`hostname_length`**: Character count of the fully qualified domain or IP.
3. **`path_length`**: Depth of the resource path string.
4. **`num_dots`**: Frequency of dot characters (`.`).
5. **`num_subdomains`**: Count of nested subdomain tiers.
6. **`num_hyphens`**: Frequency of hyphens (`-`) used in deceptive brand-jacking.
7. **`num_special_chars`**: Count of delimiters (`@`, `?`, `=`, `&`, `%`, `!`, `~`, `_`, `+`, `#`).
8. **`has_at_symbol`**: Detection of `@` character (used to mask legitimate hosts).
9. **`has_ip_address`**: Detection of raw IPv4/IPv6 addresses used in place of domains.
10. **`is_https`**: Protocol security check (`1` for HTTPS, `0` for plain HTTP).
11. **`suspicious_keyword_count`**: Frequency of targeted phishing terms (`login`, `verify`, `banking`, `paypal`, `wallet`, etc.).
12. **`has_suspicious_keywords`**: Boolean flag indicating presence of one or more phishing keywords.
13. **`is_shortened_url`**: Recognition of known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, etc.).
14. **`is_suspicious_tld`**: Check against high-abuse top-level domains (`.xyz`, `.top`, `.tk`, `.buzz`, etc.).
15. **`shannon_entropy`**: Information entropy measuring character randomness (detects DGA botnets).
16. **`digit_ratio`**: Ratio of numeric digits to total URL string length.
17. **`has_double_slash_path`**: Detection of `//` inside URL path (open-redirect exploit marker).
18. **`has_punycode`**: Detection of `xn--` prefix indicating internationalized homograph domain attacks.
19. **`has_unusual_port`**: Detection of non-standard web ports (e.g., `:8080`, `:8888`, `:4444`).
20. **`num_encoded_chars`**: Frequency of `%xx` URL escape sequences.
21. **`has_brand_in_subdomain`**: Detection of high-value brands in subdomains or paths rather than apex domains.

---

## 📐 Documented 0–100 Heuristic Risk Score

Unlike black-box models, SENTRIX calculates a transparent, decoupled 0–100 Heuristic Risk Score:

$$\text{Risk Score} = \max\Big(0, \min\big(100, \text{Base} + \sum \text{Threat Penalties} - \text{Security Offsets}\big)\Big)$$

- **Base Risk:** 5 pts
- **Raw IP Address Hostname:** +35 pts
- **Deceptive `@` Delimiter:** +30 pts
- **Brand Impersonation in Subdomain/Path:** +25 pts
- **High-Abuse TLD:** +20 pts
- **URL Shortener Concealment:** +20 pts
- **Punycode (Homograph Attack):** +20 pts
- **Sensitive Security Keywords:** +12 pts each (max 30 pts)
- **Embedded Double Slash in Path (`//`):** +15 pts
- **Unusual Web Port:** +15 pts
- **Excessive Subdomain Stacking (>=3):** +15 pts
- **High Character Entropy (>4.2):** +15 pts
- **Excessive URL Encoding (>=3 `%xx`):** +10 pts
- **Abnormally Long URL (>85 chars):** +10 pts
- **High Numeric Digit Density (>25%):** +10 pts
- **Unencrypted HTTP Protocol:** +8 pts
- **HTTPS Protocol Security Offset:** -10 pts

### Risk Tiers
- **0 – 29:** Low Risk (Typically SAFE)
- **30 – 64:** Elevated / Suspicious Risk
- **65 – 100:** Critical Threat (Typically MALICIOUS)

---

## 📊 Model Training & Real Evaluation Metrics

The Random Forest model is trained on a stratified 3-class dataset in [`data/malicious_urls_dataset.csv`](data/malicious_urls_dataset.csv) using [`train_model.py`](train_model.py).

### Real Evaluation Results (Test Set: 180 unseen samples)
- **Overall Accuracy:** `100.00%`
- **Macro Precision:** `100.00%`
- **Macro Recall:** `100.00%`
- **Macro F1-Score:** `100.00%`
- **Weighted F1-Score:** `100.00%`

### Confusion Matrix
| True Class \ Predicted | Pred Safe | Pred Suspicious | Pred Malicious |
| :--- | :---: | :---: | :---: |
| **True Safe** | **60** | 0 | 0 |
| **True Suspicious** | 0 | **60** | 0 |
| **True Malicious** | 0 | 0 | **60** |

The confusion matrix visualization is saved to [`models/confusion_matrix.png`](models/confusion_matrix.png).

---

## 🌐 Real-Time Threat Intelligence Integration

Configured in [`threat_intelligence.py`](threat_intelligence.py):

- **Google Safe Browsing API v4:** Validates URLs against Google's global threat database.
- **VirusTotal v3 Support:** Optional multi-engine anti-malware verification.
- **Zero Key Exposure:** Keys are loaded strictly from `.streamlit/secrets.toml` or OS environment variables. Keys are masked in UI and logs.
- **Safe Fallback:** If API keys are not provided, SENTRIX smoothly falls back to local Random Forest ML and lexical scoring, clearly indicating offline mode.

---

## 🖥️ Platform Navigation & Pages

SENTRIX features 7 organized sections in [`app.py`](app.py):

1. **📊 Overview Dashboard:** Live KPI metrics, Safe/Suspicious/Malicious distribution chart, engine telemetry, and recent scan activity.
2. **🔍 URL Scanner:** Single URL inspection with verdict badge, 0–100 risk score, calibrated ML confidence, Google Safe Browsing status, detected warning indicators, and safety advice.
3. **📁 Batch Scanner:** Upload CSV files to analyze dozens of URLs in batch, preview per-URL predictions, inspect summary statistics, and export results as CSV.
4. **🌐 Threat Intelligence:** Live API connectivity status, live test query console, and API key configuration instructions.
5. **📜 Scan History:** SQLite-powered historical log with search by keyword, category filter, CSV export, and clear history with confirmation.
6. **🧠 Model Performance:** Model accuracy, precision, recall, F1-scores, confusion matrix heatmap, and top predictive feature importances.
7. **⚙️ Settings & API Status:** System diagnostics, platform versioning, and cache reload tools.

---

## 🔍 Explainable URL Risk Detection Engine

SENTRIX features an **Evidence-Based Explanation Engine** ([`explanation_engine.py`](explanation_engine.py)) that answers **WHY** a URL was classified as **SAFE**, **SUSPICIOUS**, or **MALICIOUS**.

Rather than relying on black-box heuristics or hallucinating LLMs, the engine deterministically synthesizes actual observed features, model confidence, and external threat intelligence feeds:

```text
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│ Extracted Lexical Feats │     │  Random Forest Model    │     │ Threat Intelligence Feed│
│ (21 verifiable values)  │     │ (Calibrated Confidence) │     │ (Clean / Threat / None) │
└────────────┬────────────┘     └────────────┬────────────┘     └────────────┬────────────┘
             │                               │                               │
             └───────────────────────┬───────┴───────────────────────────────┘
                                     ▼
                      ┌─────────────────────────────┐
                      │    EXPLANATION ENGINE       │
                      │   (explanation_engine.py)   │
                      └──────────────┬──────────────┘
                                     │
    ┌────────────────────────────────┼────────────────────────────────┐
    ▼                                ▼                                ▼
[Why This Result?]          [Detected Indicators]             [Checks Passed]
Plain-English summary        Actual detected values            Genuinely verified checks
with evidence hierarchy      & cyber risk rationale            with observed values
    │                                │                                │
    └────────────────────────────────┼────────────────────────────────┘
                                     ▼
                        [Limitations & Disclaimers]
                        Clear distinction between
                        "clean indicators" vs "safe"
```

### Key Explainability Principles:
1. **Evidence-Based & Deterministic:** Every reason maps to an extracted lexical feature, a model tree path, or a threat intelligence response.
2. **Actual Observed Values:** Explanations show real detected values (e.g., `"URL length is 96 chars (exceeds threshold 85)"`, `"Domain ends in .top (elevated abuse frequency)"`).
3. **No Unwarranted Safety Claims:** If threat intelligence is not configured or unavailable, SENTRIX explicitly notes `"Threat intelligence check unavailable"` rather than claiming the URL is verified safe.
4. **Contextual Limitations:** Explicitly reminds analysts that lexical analysis cannot inspect dynamic page contents, and HTTPS transport encryption does not prove site legitimacy.
5. **Applied Everywhere:** Explanations appear in the Single Scanner, Batch Scanner (CSV export includes explanations), Scan History inspection modal, and exported CSV reports.

---

## 📁 Project Structure

```text
├── app.py                         # Streamlit Cybersecurity Platform (7 Pages)
├── explanation_engine.py          # Evidence-Based Explainable Risk Detection Engine
├── feature_extractor.py           # 21-Feature Extractor & 0–100 Risk Engine
├── train_model.py                 # Multi-class Random Forest Trainer & Evaluator
├── threat_intelligence.py         # Google Safe Browsing API Client & Fallbacks
├── database.py                    # SQLite Scan History & Statistics Engine
├── requirements.txt               # Python Dependencies
├── README.md                      # Comprehensive Documentation & Guide
│
├── .streamlit/
│   ├── config.toml                # Dark Navy & Cyan Theme Configuration
│   └── secrets.toml.example       # API Key Secrets Template
│
├── data/
│   ├── build_dataset.py           # Balanced 3-Class Dataset Compiler
│   ├── malicious_urls_dataset.csv # 900 Labelled URL Records
│   └── scan_history.db            # Persistent SQLite Database
│
├── models/
│   ├── url_classifier.joblib      # Trained Random Forest Model Artifact
│   └── confusion_matrix.png       # Test Set Confusion Matrix Heatmap
│
└── tests/
    ├── test_system.py             # 5-Suite Automated End-to-End Test Suite
    └── test_explanation_engine.py # 7-Suite Explanation Engine Test Suite
```

---

## 🚀 Beginner Quickstart (Windows PowerShell)

### Step 1: Open PowerShell in the Project Directory
```powershell
cd "c:\Malicious URL Detector by NEXORA"
```

### Step 2: Activate the Virtual Environment
```powershell
.\.venv\Scripts\Activate.ps1
```
*(If execution of scripts is disabled, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Train the Random Forest Model
```powershell
python train_model.py
```

### Step 5: Run the Automated Test Suites
```powershell
# 1. Run Core System Test Suite (5/5 tests)
python tests\test_system.py

# 2. Run Evidence-Based Explanation Engine Test Suite (7/7 tests)
python tests\test_explanation_engine.py

# 3. Run Google Safe Browsing API Live Integration Test (4/4 tests)
python tests\test_api_integration.py
```

### Step 6: Launch the SENTRIX Platform
```powershell
streamlit run app.py
```
The application will open in your browser at `http://localhost:8501`.

---

## 🌐 Online Deployment Guide (Streamlit Community Cloud)

Follow these steps to deploy SENTRIX online with a public live URL:

### 1. Push to GitHub
1. Create a new repository on [GitHub](https://github.com).
2. Initialize git and commit your files:
   ```bash
   git init
   git add .
   git commit -m "Deploy SENTRIX AI URL Threat Intelligence Platform"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/sentrix-threat-intel.git
   git push -u origin main
   ```
   *(Ensure `.streamlit/secrets.toml` is included in `.gitignore` if you use local private keys).*

### 2. Deploy on Streamlit Cloud
1. Go to [share.streamlit.io](https://share.streamlit.io) and log in with GitHub.
2. Click **New app**.
3. Select your repository (`sentrix-threat-intel`), branch (`main`), and main file (`app.py`).
4. Click **Advanced settings...** -> **Secrets**.
5. Add your optional API keys into the Secrets field:
   ```toml
   SAFE_BROWSING_API_KEY = "AIzaSyYourGoogleApiKeyHere"
   ```
6. Click **Deploy!**

### Difference Between Localhost & Public Deployment
- **Localhost (`http://localhost:8501`):** Accessible only on your local workstation. Changes are immediate, and the SQLite database stores scans locally.
- **Public Deployment URL (`https://your-app-name.streamlit.app`):** Globally accessible via HTTPS by hackathon evaluators, teammates, and users on any computer or smartphone.

---

## 🧪 Safe Sample Test Cases

| Case | Sample URL | Expected Verdict | Risk Score | Key Flags |
| :--- | :--- | :---: | :---: | :--- |
| **🟢 Safe** | `https://www.wikipedia.org/wiki/Computer_security` | **SAFE** | 0/100 | Clean structure, HTTPS, standard domain |
| **🟡 Suspicious** | `http://billing-update-center.top/auth-token-refresh?ref=33530` | **SUSPICIOUS** | ~72/100 | High-abuse `.top` TLD, `billing` & `auth` keywords, unencrypted HTTP |
| **🔴 Malicious** | `http://192.168.1.105/paypal/verify-identity-confirm/login?auth_session=25084` | **MALICIOUS** | ~93/100 | Raw IP host, `paypal` & `login` credential theft keywords |

---

## 🛡️ License & Educational Disclaimer
Created as an advanced educational and threat monitoring prototype for cybersecurity awareness, security operations center (SOC) triage, and machine learning research.
