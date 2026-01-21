import whois
from datetime import datetime

def get_domain_age(domain):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
        else:
            age_days = -1

        return {
            "domain_age_days": age_days
        }

    except Exception:
        return {
            "domain_age_days": -1
        }
