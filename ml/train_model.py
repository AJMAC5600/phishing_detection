import pandas as pd
import joblib

from xgboost import XGBClassifier
from urllib.parse import urlparse

from ml.feature_extractor import extract_features
from whois_utils.whois_lookup import get_domain_age


FEATURE_ORDER = [
    "url_length",
    "dot_count",
    "special_char_count",
    "has_https",
    "has_ip",
    "suspicious_words",
    "subdomain_count"
]

# Load dataset
df = pd.read_csv("data/urls.csv")

X = []
y = df["label"]

for url in df["url"]:
    features = extract_features(url)

    domain = urlparse(url).hostname
    whois_data = get_domain_age(domain)

    whois_missing = 1 if whois_data["domain_age_days"] == -1 else 0

    # Build feature vector in FIXED ORDER
    feature_vector = [features[f] for f in FEATURE_ORDER]
    feature_vector.append(whois_data["domain_age_days"])
    feature_vector.append(whois_missing)

    X.append(feature_vector)

# Train model
model = XGBClassifier(
    n_estimators=100,
    max_depth=5,
    learning_rate=0.1,
    eval_metric="logloss"
)

model.fit(X, y)

# Save model
joblib.dump(model, "models/xgboost_model.pkl")

print("✅ Model trained and saved successfully")
