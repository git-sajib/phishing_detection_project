import re
import tldextract
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

def extract_url_features(url):

    features = {}

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    features['url_length'] = len(url)
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special_chars'] = len(re.findall(r'[@\-_=]', url))
    features['has_ip'] = 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0
    features['num_subdomains'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
    features['uses_https'] = 1 if parsed.scheme == "https" else 0

    features['domain_length'] = len(ext.domain)
    features['tld_length'] = len(ext.suffix)

    try:
        response = requests.get(url, timeout=3)
        soup = BeautifulSoup(response.text, "html.parser")

        features['num_iframes'] = len(soup.find_all("iframe"))
        features['num_forms'] = len(soup.find_all("form"))
        features['num_links'] = len(soup.find_all("a"))

    except:
        features['num_iframes'] = 0
        features['num_forms'] = 0
        features['num_links'] = 0

    return features