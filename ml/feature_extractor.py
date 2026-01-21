import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "confirm", "signin", "payment"
]

def extract_features(url):
    parsed = urlparse(url)

    features = {}

    # 1. URL length
    features["url_length"] = len(url)

    # 2. Count dots
    features["dot_count"] = url.count(".")

    # 3. Count special characters
    features["special_char_count"] = len(re.findall(r"[@\-_=]", url))

    # 4. HTTPS presence
    features["has_https"] = 1 if parsed.scheme == "https" else 0

    # 5. IP address in URL
    features["has_ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

    # 6. Suspicious keywords
    features["suspicious_words"] = sum(
        1 for word in SUSPICIOUS_KEYWORDS if word in url.lower()
    )

    # 7. Subdomain count
    features["subdomain_count"] = (
        parsed.hostname.count(".") - 1 if parsed.hostname else 0
    )

    return features
