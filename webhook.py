import requests
from urllib.parse import urlparse


def dispatch_webhook(target_url, payload):
    return requests.post(target_url, json=payload, timeout=5)
