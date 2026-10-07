import re
from urllib.parse import urlparse


def extract_url_features(url):

    # Add scheme if user does not provide one
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""

    features = {}

    # 1. URL Length
    features["URL_Length"] = len(url)

    # 2. @ Symbol
    if "@" in url:
        features["having_At_Symbol"] = -1
    else:
        features["having_At_Symbol"] = 1

    # 3. Prefix / Suffix
    if "-" in hostname:
        features["Prefix_Suffix"] = -1
    else:
        features["Prefix_Suffix"] = 1

    # 4. Sub Domain
    # www is treated as a normal prefix, not a suspicious sub-domain
    hostname_parts = hostname.split(".")

    if hostname.startswith("www."):
        hostname_parts = hostname_parts[1:]

    if len(hostname_parts) <= 2:
        features["having_Sub_Domain"] = 1
    else:
        features["having_Sub_Domain"] = -1

    # 5. SSL / HTTPS
    if parsed_url.scheme.lower() == "https":
        features["SSLfinal_State"] = 1
    else:
        features["SSLfinal_State"] = -1

    # 6. IP Address
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        features["having_IP_Address"] = -1
    else:
        features["having_IP_Address"] = 1

    # 7. URL Shortening Service
    shortening_services = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "shorturl.at"
    ]

    if any(
        service in hostname.lower()
        for service in shortening_services
    ):
        features["Shortining_Service"] = -1
    else:
        features["Shortining_Service"] = 1

    # 8. HTTPS Token
    if "https" in hostname.lower():
        features["HTTPS_token"] = -1
    else:
        features["HTTPS_token"] = 1

    return features