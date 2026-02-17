import joblib
from urllib.parse import urlparse
import requests
import re
from typing import Any, Dict

from ml.feature_extractor import extract_features
from whois_utils.whois_lookup import get_domain_age

# =========================
# Configuration
# =========================

FEATURE_ORDER = [
    "url_length",
    "dot_count",
    "special_char_count",
    "has_https",
    "has_ip",
    "suspicious_words",
    "subdomain_count",
]

TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "youtube.com",
    "gmail.com",
    "microsoft.com",
    "amazon.com",
    "amazon.in",
    "linkedin.com",
    "facebook.com",
    "vercel.com",
    "crunchbase.com",
    "wikipedia.org",
}

PHISHING_THRESHOLD = 75
SUSPICIOUS_THRESHOLD = 45

MODEL_PATH = "models/xgboost_model.pkl"
USER_AGENT = "Mozilla/5.0 (PhishingDetector/1.0)"

# =========================
# Load model
# =========================

model = joblib.load(MODEL_PATH)

# =========================
# Helpers
# =========================

def get_root_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False

    host = parsed.hostname
    if not host:
        return False

    domain_pattern = re.compile(r"^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

    return bool(domain_pattern.match(host) or ip_pattern.match(host))


def is_reachable(url: str) -> bool:
    try:
        headers = {"User-Agent": USER_AGENT}
        r = requests.head(url, timeout=5, allow_redirects=True, headers=headers)
        if r.status_code == 405:
            r = requests.get(url, timeout=5, allow_redirects=True, headers=headers)
        return r.status_code < 500
    except requests.RequestException:
        return False


# =========================
# AI Intent Analysis
# =========================

def ai_intent_analysis(text: str) -> Dict[str, Any]:
    phishing_patterns = {
        "verify your account": 20,
        "urgent": 15,
        "account suspended": 25,
        "confirm your identity": 20,
        "login immediately": 20,
        "security alert": 15,
        "unauthorized access": 20,
        "update your account": 15,
        "click below": 10,
    }

    score = 0
    reasons = []

    lower_text = text.lower()

    for pattern, weight in phishing_patterns.items():
        if pattern in lower_text:
            score += weight
            reasons.append(pattern)

    return {
        "ai_score": min(score, 100),
        "ai_reasons": reasons,
    }


def extract_page_text(url: str) -> str:
    try:
        r = requests.get(url, timeout=5, headers={"User-Agent": USER_AGENT})
        return r.text[:5000]  # limit for safety
    except Exception:
        return ""


# =========================
# Prediction Function
# =========================

def predict_url(url: str) -> Dict[str, Any]:

    # 1️⃣ Validation
    if not is_valid_url(url):
        return {
            "label": "Invalid URL",
            "risk_level": "INVALID",
            "confidence": 0,
            "reason": "Input is not a valid URL format",
            "tips": "Enter a valid URL starting with http:// or https://",
        }

    if not is_reachable(url):
        return {
            "label": "Offline / Unreachable",
            "risk_level": "UNKNOWN",
            "confidence": 0,
            "reason": "Website is not reachable or does not exist",
            "tips": "Verify the URL or try again later",
        }

    root_domain = get_root_domain(url)

    # 2️⃣ Trusted domain shortcut
    if root_domain in TRUSTED_DOMAINS:
        return {
            "label": "Legitimate",
            "risk_level": "SAFE",
            "confidence": 2.0,
            "reason": "Known trusted domain",
            "tips": "No additional tips.",
        }

    # 3️⃣ ML Feature Extraction
    features = extract_features(url)

    whois_data = get_domain_age(root_domain) or {}
    domain_age = whois_data.get("domain_age_days", 365)  # neutral fallback

    feature_vector = [features.get(f, 0) for f in FEATURE_ORDER]
    feature_vector.append(domain_age)
    feature_vector.append(0)  # whois_missing neutralized

    ml_score = model.predict_proba([feature_vector])[0][1] * 100

    # 4️⃣ AI Intent Analysis
    page_text = extract_page_text(url)
    ai_result = ai_intent_analysis(page_text)
    ai_score = ai_result["ai_score"]

    # 5️⃣ HYBRID SCORE
    final_score = (ml_score * 0.6) + (ai_score * 0.4)

    # 6️⃣ Final Decision
    if final_score >= PHISHING_THRESHOLD:
        label = "Phishing"
        risk = "DANGEROUS"
        tips = "Do not enter credentials or personal data."
    elif final_score >= SUSPICIOUS_THRESHOLD:
        label = "Suspicious"
        risk = "SUSPICIOUS"
        tips = "Verify the website carefully before proceeding."
    else:
        label = "Legitimate"
        risk = "SAFE"
        tips = "No additional tips."

    return {
        "label": label,
        "risk_level": risk,
        "confidence": round(final_score, 2),
        "ml_score": round(ml_score, 2),
        "ai_score": ai_score,
        "ai_reasons": ai_result["ai_reasons"],
        "reason": "Hybrid analysis using rules, ML patterns, and AI intent detection",
        "tips": tips,
    }
