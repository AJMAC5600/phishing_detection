import pandas as pd
import joblib
import numpy as np

from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from ml.feature_extractor import extract_features


# =========================
# Feature Order (MUST MATCH predict.py)
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


print("[+] Loading dataset...")
df = pd.read_csv("data/live_urls.csv")

X = []
y = df["label"].values


# =========================
# Feature Extraction (NO WHOIS)
# =========================
print("[+] Extracting features...")

for url in df["url"]:
    features = extract_features(url)

    # Build feature vector in fixed order
    feature_vector = [features[f] for f in FEATURE_ORDER]

    # WHOIS features are DISABLED during training
    # (-1 = unknown age, 1 = whois missing)
    feature_vector.append(-1)  # domain_age_days
    feature_vector.append(1)   # whois_missing

    X.append(feature_vector)

X = np.array(X)


# =========================
# Train / Test Split
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y if len(np.unique(y)) > 1 else None
)


# =========================
# Handle Class Imbalance Safely
# =========================
if len(np.unique(y_train)) > 1:
    neg, pos = np.bincount(y_train)
    scale_pos_weight = neg / pos
else:
    scale_pos_weight = 1.0

print(f"[+] scale_pos_weight = {scale_pos_weight:.2f}")


# =========================
# XGBoost Model (TUNED)
# =========================
model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    eval_metric="logloss",
    random_state=42
)


print("[+] Training model...")
model.fit(X_train, y_train)


# =========================
# Evaluation
# =========================
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print("\n[✔] Model Accuracy:", round(accuracy * 100, 2), "%")

print("\n[✔] Classification Report:")
print(classification_report(y_test, y_pred, zero_division=0))


# =========================
# Save Model
# =========================
joblib.dump(model, "models/xgboost_model.pkl")

print("\n[✔] Model trained and saved successfully")
