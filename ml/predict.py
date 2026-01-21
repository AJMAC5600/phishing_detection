import joblib
from urllib.parse import urlparse

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
    features = extract_features(url)

    domain = urlparse(url).hostname

    # 🔒 Whitelist trusted domains
    if domain in TRUSTED_DOMAINS:
        return {
            "label": "Legitimate",
            "confidence": 99.0
        }

    whois_data = get_domain_age(domain)
    domain_age = whois_data["domain_age_days"]

    # WHOIS-derived feature
    whois_missing = 1 if domain_age == -1 else 0

    # Build feature vector in FIXED ORDER
    feature_vector = [features[f] for f in FEATURE_ORDER]
    feature_vector.append(domain_age)
    feature_vector.append(whois_missing)

    probability = model.predict_proba([feature_vector])[0][1]

    # 🎯 Risk-based decision
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
