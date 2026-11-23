import unittest

from app import app
from detector import PhishingDetector
from feature_extraction import FeatureExtractor


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.fx = FeatureExtractor()

    def test_adds_http_when_missing(self):
        self.assertEqual(self.fx.normalize("example.com"), "http://example.com")

    def test_ip_host_detected(self):
        self.assertEqual(self.fx.extract("http://192.168.4.5/login")["has_ip_host"], 1)

    def test_at_trick_detected(self):
        self.assertEqual(self.fx.extract("http://facebook.com@evil.tk/login")["has_at"], 1)

    def test_at_in_path_is_not_the_trick(self):
        self.assertEqual(self.fx.extract("https://medium.com/@someone")["has_at"], 0)

    def test_risky_tld_detected(self):
        self.assertEqual(self.fx.extract("http://shop.example.xyz")["suspicious_tld"], 1)

    def test_subdomain_count(self):
        self.assertEqual(self.fx.extract("http://a.b.c.d.evil.com")["subdomain_count"], 4)

    def test_phishing_words_in_host(self):
        self.assertEqual(self.fx.extract("http://secure-login.example.com")["suspicious_word_count"], 2)

    def test_rule_signals_reject_bad_url(self):
        with self.assertRaises(ValueError):
            self.fx.rule_signals("http://")


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = PhishingDetector()        # loads the trained model once

    def test_trusted_domain_matches_subdomains(self):
        self.assertTrue(self.d.is_trusted("accounts.google.com"))

    def test_lookalike_is_not_trusted(self):
        self.assertFalse(self.d.is_trusted("paypal.com.evil-site.tk"))
        self.assertFalse(self.d.is_trusted("notpaypal.com"))

    def test_fake_paypal_is_phishing(self):
        r = self.d.analyze("http://paypa1-secure-login.verify-account.xyz/webscr?id=1")
        self.assertEqual(r["verdict"], "Likely phishing")
        self.assertEqual(r["score"], 7)

    def test_ip_address_is_phishing(self):
        self.assertEqual(self.d.analyze("http://192.168.4.5/login")["verdict"], "Likely phishing")

    def test_lookalike_domain_is_phishing(self):
        self.assertEqual(self.d.analyze("http://paypal.com.evil-site.tk/login")["verdict"], "Likely phishing")

    def test_github_issue_is_trusted(self):
        self.assertEqual(self.d.analyze("https://github.com/python/cpython/issues/12345")["verdict"], "Trusted website")

    def test_reasons_are_listed(self):
        reasons = self.d.analyze("http://192.168.4.5/login")["reasons"]
        self.assertTrue(any("IP address" in r["text"] for r in reasons))

    def test_bad_url_raises(self):
        with self.assertRaises(ValueError):
            self.d.analyze("http://")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_page(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_health(self):
        self.assertEqual(self.client.get("/api/health").get_json(), {"status": "ok"})

    def test_check_with_post(self):
        r = self.client.post("/api/check", json={"url": "http://192.168.4.5/login"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["verdict"], "Likely phishing")

    def test_check_with_get(self):
        self.assertEqual(self.client.get("/api/check?url=https://www.bbc.com").status_code, 200)

    def test_empty_url_rejected(self):
        self.assertEqual(self.client.post("/api/check", json={"url": ""}).status_code, 400)

    def test_invalid_url_rejected(self):
        self.assertEqual(self.client.post("/api/check", json={"url": "http://"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()