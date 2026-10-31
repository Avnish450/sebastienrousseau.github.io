import requests
from urllib.parse import urlparse


def dispatch_webhook(target_url, payload):
    # Security fix: prevent SSRF and internal network probing
    parsed = urlparse(target_url)
    if parsed.hostname in ('localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'):
        raise ValueError("Access to internal network destinations is prohibited")
    if '..' in target_url or parsed.scheme not in ('http', 'https'):
        raise ValueError("Invalid URL scheme or path traversal sequence detected")
    return requests.post(target_url, json=payload, timeout=5)
