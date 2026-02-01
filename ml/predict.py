import joblib
from urllib.parse import urlparse

from ml.feature_extractor import extract_features
from whois_utils.whois_lookup import get_domain_age
from utils.site_status import check_website_online


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
    "facebook.com"
}

PHISHING_THRESHOLD = 0.7
SUSPICIOUS_THRESHOLD = 0.5


# =========================
# Load model once
# =========================

model = joblib.load("models/xgboost_model.pkl")


# =========================
# Prediction Function
# =========================

def predict_url(url):
    site_status = check_website_online(url)

    if not site_status["online"]:
        return {
            "label": "Offline / Unreachable",
            "confidence": 0
        }
    features = extract_features(url)

    host = urlparse(url).hostname

    # 🔒 Whitelist trusted domains
    if host in TRUSTED_DOMAINS:
        return {
            "label": "Legitimate",
            "confidence": 99.0
        }

    # Use ROOT domain for WHOIS
    domain = ".".join(host.split(".")[-2:])
    whois_data = get_domain_age(domain)
    domain_age = whois_data["domain_age_days"]

    whois_missing = 1 if domain_age == -1 else 0

    # Build feature vector
    feature_vector = [features[f] for f in FEATURE_ORDER]
    feature_vector.append(domain_age)
    feature_vector.append(whois_missing)

    # 🔹 Raw ML probability (phishing probability)
    probability = model.predict_proba([feature_vector])[0][1]

    # =========================
    # CONFIDENCE CALIBRATION (KEY PART)
    # =========================
    safe_signals = 0

    if features["has_https"] == 1:
        safe_signals += 1
    if features["suspicious_words"] == 0:
        safe_signals += 1
    if features["has_ip"] == 0:
        safe_signals += 1

    # If at least 2 strong safety signals → reduce phishing probability
    if safe_signals >= 2:
        probability *= 0.6

    # =========================
    # Risk-based decision
    # =========================
    if probability >= PHISHING_THRESHOLD:
        label = "Phishing"
    elif probability >= SUSPICIOUS_THRESHOLD:
        label = "Suspicious"
    else:
        label = "Legitimate"

    return {
        "label": label,
        "confidence": round(probability * 100, 2)
    }
