import joblib
from urllib.parse import urlparse
import requests
import re
from ml.feature_extractor import extract_features   # ✅ REQUIRED
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
    "subdomain_count"
]

TRUSTED_DOMAINS = {
    "google.com",
    "www.google.com",
    "youtube.com",
    "gmail.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "amazon.in",
    "linkedin.com",
    "facebook.com",
    "vercel.com"
}

PHISHING_THRESHOLD = 0.7
SUSPICIOUS_THRESHOLD = 0.5

# =========================
# Load model
# =========================

model = joblib.load("models/xgboost_model.pkl")

# =========================
# Prediction Function
# =========================

def is_reachable(url: str) -> bool:
    try:
        r = requests.head(url, timeout=5, allow_redirects=True)
        return r.status_code < 500
    except Exception:
        return False

def is_valid_url(url: str) -> bool:
    pattern = re.compile(
        r'^(https?:\/\/)'           # http:// or https://
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,})'  # domain
        r'(\/.*)?$'                 # optional path
    )
    return bool(pattern.match(url))

def predict_url(url):
    # ❌ Invalid format
    if not is_valid_url(url):
        return {
            "label": "Invalid URL",
            "risk_level": "INVALID",
            "phishing_probability": 0,
            "reason": "Input is not a valid URL format",
            "tips": "Please enter a valid URL starting with http:// or https://",
            "whois": {}
        }

    # 🌐 Not reachable
    if not is_reachable(url):
        return {
            "label": "Offline / Unreachable",
            "risk_level": "UNKNOWN",
            "phishing_probability": 0,
            "reason": "Website is not reachable or does not exist",
            "tips": "Verify the URL or try again later",
            "whois": {}
        }

    features = extract_features(url)

    domain = urlparse(url).hostname

    # Trusted domain shortcut
    if domain in TRUSTED_DOMAINS:
        return {
            "label": "Legitimate",
            "risk_level": "SAFE",
            "phishing_probability": 5,
            "reason": "Known legitimate domain",
            "tips": "No additional tips.",
            "whois": {
                "registered": "Yes",
                "domain": domain,
                "created": "Unknown",
                "expires": "Unknown"
            }
        }

    whois_data = get_domain_age(domain)
    domain_age = whois_data["domain_age_days"]

    whois_missing = 1 if domain_age == -1 else 0

    feature_vector = [features[f] for f in FEATURE_ORDER]
    feature_vector.append(domain_age)
    feature_vector.append(whois_missing)

    probability = model.predict_proba([feature_vector])[0][1] * 100

    if probability >= 70:
        label = "Phishing"
        risk = "DANGEROUS"
        reason = "URL shows strong phishing patterns"
        tips = "Do not enter credentials or personal data."
    elif probability >= 40:
        label = "Suspicious"
        risk = "SUSPICIOUS"
        reason = "URL contains suspicious characteristics"
        tips = "Verify the website before proceeding."
    else:
        label = "Legitimate"
        risk = "SAFE"
        reason = "No significant phishing indicators detected"
        tips = "No additional tips."

    return {
        "label": label,
        "risk_level": risk,
        "phishing_probability": round(probability, 2),
        "reason": reason,
        "tips": tips,
        "whois": {
            "registered": "Yes" if domain_age != -1 else "No",
            "domain": domain,
            "created": "Unknown",
            "expires": "Unknown"
        }
    }
