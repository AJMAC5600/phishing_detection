import requests

def check_website_online(url, timeout=5):
    try:
        response = requests.get(url, timeout=timeout)
        return {
            "online": True,
            "status_code": response.status_code
        }
    except requests.exceptions.RequestException:
        return {
            "online": False,
            "status_code": None
        }
