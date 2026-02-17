import joblib
from urllib.parse import urlparse
import requests
import re
from typing import Any, Dict
from bs4 import BeautifulSoup
from ml.feature_extractor import extract_features
from whois_utils.whois_lookup import get_domain_age
from ai_utils.gemini_explainer import generate_explanation
import tldextract
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
    "www.google.com",
    "youtube.com",
    "gmail.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "amazon.in",
    "linkedin.com",
    "facebook.com",
    "vercel.com",
}

PHISHING_THRESHOLD = 0.70
SUSPICIOUS_THRESHOLD = 0.40

MODEL_PATH = "models/xgboost_model.pkl"
USER_AGENT = "Mozilla/5.0 (compatible; PhishingDetector/1.0)"

# =========================
# Load model
# =========================

model = joblib.load(MODEL_PATH)

# =========================
# Prediction Function
# =========================
def fetch_page_text(url):
    try:
        headers = {
            "User-Agent": USER_AGENT
        }

        response = requests.get(url, timeout=5, headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")

        # Remove scripts and styles
        for script in soup(["script", "style"]):
            script.extract()

        text = soup.get_text(separator=" ")

        return text.lower()

    except Exception:
        return ""
    

def content_risk_score(page_text):
    suspicious_phrases = [
        "verify your account",
        "login immediately",
        "account suspended",
        "confirm your identity",
        "security alert",
        "unauthorized access",
        "update your payment",
        "reset your password",
    ]

    score = 0

    for phrase in suspicious_phrases:
        if phrase in page_text:
            score += 15

    return min(score, 100)


def is_reachable(url: str) -> bool:
    try:
        headers = {"User-Agent": USER_AGENT}
        r = requests.head(url, timeout=5, allow_redirects=True, headers=headers)
        if r.status_code == 405:
            r = requests.get(url, timeout=5, allow_redirects=True, headers=headers)
        return r.status_code < 500
    except requests.RequestException:
        return False


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


def predict_url(url: str) -> Dict[str, Any]:

    # 1️⃣ URL Validation
    if not is_valid_url(url):
        return {
            "label": "Invalid URL",
            "risk_level": "INVALID",
            "confidence": 0,
            "reason": "Input is not a valid URL format",
            "tips": "Please enter a valid URL starting with http:// or https://",
        }

    # 2️⃣ Reachability Check
    if not is_reachable(url):
        return {
            "label": "Offline / Unreachable",
            "risk_level": "UNKNOWN",
            "confidence": 0,
            "reason": "Website is not reachable or does not exist",
            "tips": "Verify the URL or try again later",
        }

    # 3️⃣ Feature Extraction
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}".lower()
    features = extract_features(url)
    # domain = (urlparse(url).hostname or "").lower()


    # 8️⃣ Content Analysis
    page_text = fetch_page_text(url)
    content_score = content_risk_score(page_text)


    # 4️⃣ Trusted Domain Shortcut
    if domain in TRUSTED_DOMAINS:
        return {
            "label": "Legitimate",
            "risk_level": "SAFE",
            "confidence": 5.0,
            "reason": "Known legitimate domain",
            "tips": "No additional tips.",
        }
    

    # 5️⃣ WHOIS
    whois_data = get_domain_age(domain) or {}
    domain_age = whois_data.get("domain_age_days", -1)
    # print("Checking WHOIS for:", domain)
    # print("WHOIS Data:", whois_data)

    whois_missing = 1 if domain_age == -1 else 0

    # 6️⃣ Build Feature Vector
    feature_vector = [features.get(f, 0) for f in FEATURE_ORDER]
    feature_vector.append(domain_age)
    feature_vector.append(whois_missing)

    # 7️⃣ ML Score
    ml_score = model.predict_proba([feature_vector])[0][1] * 100

    # 🔹 If you don't yet use separate AI intent score:
    ai_score = 0  # temporary (until intent module added)

    # 🔹 For now final_score = ML only
    # Weighted Hybrid Score
    final_score = (ml_score * 0.6) + (content_score * 0.4)


    # 8️⃣ Decision Logic
    if final_score >= PHISHING_THRESHOLD * 100:
        label = "Phishing"
        risk = "DANGEROUS"
        tips = "Do not enter credentials or personal data."
    elif final_score >= SUSPICIOUS_THRESHOLD * 100:
        label = "Suspicious"
        risk = "SUSPICIOUS"
        tips = "Verify the website before proceeding."
    else:
        label = "Legitimate"
        risk = "SAFE"
        tips = "No additional tips."

    # 9️⃣ Gemini Explanation
    # try:
    #     explanation = generate_explanation(
    #         url=url,
    #         ml_score=ml_score,
    #         ai_score=content_score,
    #         final_score=final_score,
    #         risk_level=risk,
    #     )
    # except Exception as e:
    #     print("🔥 GEMINI ERROR:", e)
    #     explanation = f"Gemini error: {str(e)}"

    # 🔟 Final Response
    return {
        "label": label,
        "risk_level": risk,
        "confidence": round(final_score, 2),
        "ml_score": round(ml_score, 2),
        "ai_score": ai_score,
        "gemini_explanation": None,
        "reason": "Hybrid ML + AI analysis with Gemini explanation",
        "tips": tips,
        "whois": {
            "registered": "Yes" if domain_age != -1 else "No",
            "domain": domain,
            "created": whois_data.get("created") or "Unknown",
            "expires": whois_data.get("expires") or "Unknown",
        },

    }
