import requests
from bs4 import BeautifulSoup

def extract_text_from_url(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        return soup.get_text(separator=" ")
    except Exception:
        return ""
