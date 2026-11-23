import math
import re
from collections import Counter
from urllib.parse import urlsplit


class FeatureExtractor:
    SUSPICIOUS_WORDS = ["login", "signin", "verify", "update", "secure", "account",
                        "banking", "confirm", "password", "wallet", "suspend",
                        "unlock", "billing", "invoice", "paypal", "apple",
                        "microsoft", "amazon", "support", "webscr"]
    SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
                       "country", "zip", "work", "support", "rest", "icu", "buzz"}
    SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                  "buff.ly", "cutt.ly", "rebrand.ly"}

    def normalize(self, url):
        url = url.strip()
        if "://" not in url:
            url = "http://" + url
        return url

    def entropy(self, text):
        if not text:
            return 0.0
        total = len(text)
        counts = Counter(text)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    def is_ip(self, host):
        return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host))



    def extract(self, url):
        url = self.normalize(url)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        labels = host.split(".")
        digits = sum(ch.isdigit() for ch in host)

        return {
            "host_length": len(host),
            "num_dots": host.count("."),
            "num_hyphens": host.count("-"),
            "num_digits": digits,
            "digit_ratio": digits / max(len(host), 1),
            "subdomain_count": max(len(labels) - 2, 0),
            "has_ip_host": int(self.is_ip(host)),
            "has_at": int(parts.username is not None),
            "has_punycode": int("xn--" in host),
            "suspicious_tld": int(labels[-1] in self.SUSPICIOUS_TLDS),
            "is_shortener": int(host in self.SHORTENERS),
            "suspicious_word_count": sum(w in host for w in self.SUSPICIOUS_WORDS),
            "host_entropy": self.entropy(host),
        }


    def rule_signals(self, url):
        """Facts about the WHOLE link. Used by the rule-based checks."""
        url = self.normalize(url)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host:
            raise ValueError("invalid URL")
        labels = host.split(".")
        is_ip = self.is_ip(host)
        main_name = labels[max(len(labels) - 2, 0)]
        lowered = url.lower()
        return {
            "url": url,
            "host": host,
            "tld": labels[-1],
            "is_ip": is_ip,
            "has_at": parts.username is not None,
            "has_punycode": "xn--" in host,
            "suspicious_tld": labels[-1] in self.SUSPICIOUS_TLDS,
            "is_shortener": host in self.SHORTENERS,
            "uses_https": parts.scheme == "https",
            "subdomain_count": max(len(labels) - 2, 0),
            "hyphen_count": host.count("-"),
            "suspicious_words": [w for w in self.SUSPICIOUS_WORDS if w in lowered],
            "url_length": len(url),
            "double_slash_in_path": "//" in parts.path,
            "host_entropy": self.entropy(host),
            "digits_in_name": (not is_ip) and bool(re.search(r"[a-z]\d[a-z]|[a-z]\d$", main_name)),
        }
if __name__ == "__main__":
    fx = FeatureExtractor()
    tests = ["https://www.bbc.com",
             "http://paypa1-secure-login.verify-account.xyz/webscr?id=1",
             "http://192.168.4.5/login"]
    for u in tests:
        print(u)
        for name, value in fx.extract(u).items():
            print("   ", name, "=", value)
