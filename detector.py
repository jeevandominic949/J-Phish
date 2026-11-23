import joblib
import pandas as pd

from feature_extraction import FeatureExtractor


class PhishingDetector:
    PHISHING_AT = 5      # rule score >= 5 -> strong warning
    SUSPICIOUS_AT = 3    # rule score >= 3 -> some warning

    # Official domains of well-known sites. A link matches only if its real host
    # IS the domain or a subdomain of it, so paypal.com.evil.tk does NOT match.
    TRUSTED_DOMAINS = {
        "google.com", "youtube.com", "gmail.com", "microsoft.com", "microsoftonline.com",
        "live.com", "office.com", "outlook.com", "apple.com", "icloud.com",
        "amazon.com", "amazon.in", "amazon.de", "amazon.co.uk", "paypal.com",
        "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com", "twitter.com",
        "x.com", "netflix.com", "dropbox.com", "github.com", "wikipedia.org",
        "ebay.com", "adobe.com", "dhl.com", "fedex.com", "ups.com", "usps.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "hsbc.com",
        "sparkasse.de", "deutsche-bank.de", "commerzbank.de", "ing.de", "dkb.de",
        "postbank.de", "bahn.de", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com",
        "icicibank.com", "axisbank.com", "irctc.co.in", "flipkart.com", "paytm.com",
        "phonepe.com", "incometax.gov.in", "bbc.com", "bbc.co.uk", "nytimes.com",
        "stackoverflow.com", "reddit.com", "mozilla.org", "python.org", "coursera.org",
        "booking.com", "spiegel.de", "who.int", "steampowered.com", "zoom.us",
    }

    def __init__(self, model_file="phish_model.joblib"):
        self.extractor = FeatureExtractor()
        saved = joblib.load(model_file)
        self.model = saved["model"]
        self.columns = saved["features"]

    def is_trusted(self, host):
        return any(host == d or host.endswith("." + d) for d in self.TRUSTED_DOMAINS)

    def ml_chance(self, url):
        """Chance (0 to 1) that the WEBSITE NAME is phishing, from the trained model."""
        row = pd.DataFrame([self.extractor.extract(url)], columns=self.columns)
        return float(self.model.predict_proba(row)[0][1])

    def rule_check(self, f):
        """Each warning sign adds points. Returns a list of {points, text}."""
        hits = []

        def add(points, text):
            hits.append({"points": points, "text": text})

        if f["is_ip"]:
            add(3, "Uses a raw IP address instead of a domain name")
        if f["has_at"]:
            add(3, "Contains '@', which can hide the real destination")
        if f["has_punycode"]:
            add(2, "Punycode domain, which may imitate another site")
        if f["suspicious_tld"]:
            add(2, f"Domain ends in '.{f['tld']}', a TLD often abused for phishing")
        if f["is_shortener"]:
            add(1, "URL shortener hides the real destination")
        if not f["uses_https"]:
            add(1, "Not using HTTPS")
        if f["subdomain_count"] >= 3 and not f["is_ip"]:
            add(2, f"Many subdomains ({f['subdomain_count']})")
        if f["hyphen_count"] >= 2:
            add(1, "Several hyphens in the domain name")
        if len(f["suspicious_words"]) >= 2:
            add(2, "Several phishing-style words: " + ", ".join(f["suspicious_words"][:5]))
        if f["url_length"] > 90:
            add(1, f"Very long URL ({f['url_length']} characters)")
        if f["double_slash_in_path"]:
            add(1, "Double slash in the path (possible hidden redirect)")
        if not f["is_ip"] and f["host_entropy"] > 3.8:
            add(1, "Domain name looks random")
        if f["digits_in_name"]:
            add(1, "Digits mixed into letters in the domain (like 'paypa1')")
        return hits

    def analyze(self, url):
        f = self.extractor.rule_signals(url)      # raises ValueError for a bad URL
        hits = self.rule_check(f)
        score = sum(h["points"] for h in hits)
        chance = self.ml_chance(url)

        rules_strong = score >= self.PHISHING_AT
        rules_some = score >= self.SUSPICIOUS_AT
        ml_flag = chance >= 0.5

        if self.is_trusted(f["host"]):
            if rules_strong:
                verdict, level = "Suspicious", "warn"
                note = "Well-known website, but the link itself has strong warning signs."
            else:
                verdict, level = "Trusted website", "ok"
                note = "The domain belongs to a well-known website."
        elif rules_strong or (ml_flag and rules_some):
            verdict, level = "Likely phishing", "bad"
            note = "Strong warning signs were found. Do not open this link."
        elif ml_flag or rules_some:
            verdict, level = "Suspicious", "warn"
            note = "Some warning signs were found. Be careful with this link."
        else:
            verdict, level = "Looks OK", "ok"
            note = "No strong warning signs, but this is not a guarantee of safety."

        return {"url": f["url"], "verdict": verdict, "level": level, "note": note,
                "score": score, "ml_percent": round(chance * 100, 1), "reasons": hits}


if __name__ == "__main__":
    detector = PhishingDetector()
    tests = [
        "https://github.com/python/cpython/issues/12345",
        "https://www.paypal.com/signin",
        "https://www.bbc.com",
        "https://www.geeksforgeeks.org/python-programming-language/",
        "http://paypa1-secure-login.verify-account.xyz/webscr?id=1",
        "http://192.168.4.5/login",
        "http://paypal.com.evil-site.tk/login",
        "http://facebook.com@evil-site.tk/login",
    ]
    for t in tests:
        r = detector.analyze(t)
        print(f"{r['verdict']:16s} rules={r['score']}  ml={r['ml_percent']:5.1f}%  {t}")