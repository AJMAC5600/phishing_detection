import requests
import pandas as pd
import zipfile
import io
from datetime import datetime

# =========================
# Configuration
# =========================

PHISHING_LIMIT = 5000
LEGIT_LIMIT = 5000

OUTPUT_FILE = "data/live_urls.csv"


# =========================
# Fetch phishing URLs (OpenPhish)
# =========================

def fetch_phishing_urls(limit):
    print("[+] Fetching phishing URLs (OpenPhish)...")

    feed_url = "https://openphish.com/feed.txt"

    try:
        r = requests.get(feed_url, timeout=10)
        r.raise_for_status()

        urls = r.text.splitlines()[:limit]
        return [(u.strip(), 1) for u in urls]

    except Exception as e:
        print("[!] Failed to fetch phishing URLs:", e)
        return []


# =========================
# Fetch trusted URLs (Tranco)
# =========================

def fetch_trusted_urls(limit):
    print("[+] Fetching trusted domains (Tranco)...")

    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"

    try:
        r = requests.get(tranco_url, timeout=15)
        r.raise_for_status()

        zip_data = zipfile.ZipFile(io.BytesIO(r.content))
        csv_name = zip_data.namelist()[0]

        df = pd.read_csv(zip_data.open(csv_name), header=None)
        domains = df[1].head(limit)

        return [(f"https://{d}", 0) for d in domains]

    except Exception as e:
        print("[!] Failed to fetch trusted domains:", e)
        return []


# =========================
# Create dataset
# =========================

def create_live_dataset():
    phishing = fetch_phishing_urls(PHISHING_LIMIT)
    legit = fetch_trusted_urls(LEGIT_LIMIT)

    data = phishing + legit

    if not data:
        print("[!] Dataset is empty")
        return

    df = pd.DataFrame(data, columns=["url", "label"])
    df.to_csv(OUTPUT_FILE, index=False)

    print("\n[✔] Live dataset created successfully")
    print(f"[✔] File: {OUTPUT_FILE}")
    print(f"[✔] Records: {len(df)}")
    print(f"[✔] Generated on: {datetime.now()}")


# =========================
# Run
# =========================

if __name__ == "__main__":
    create_live_dataset()
