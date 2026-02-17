import whois
from datetime import datetime, timezone

def get_domain_age(domain):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        expiration_date = w.expiration_date

        # Sometimes WHOIS returns list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if not creation_date:
            return {
                "domain_age_days": -1,
                "created": None,
                "expires": None
            }

        now = datetime.now(timezone.utc)
        age = (now - creation_date).days

        return {
            "domain_age_days": age,
            "created": creation_date.strftime("%d %b %Y"),
            "expires": expiration_date.strftime("%d %b %Y") if expiration_date else None
        }

    except Exception as e:
        print("WHOIS ERROR:", e)
        return {
            "domain_age_days": -1,
            "created": None,
            "expires": None
        }
