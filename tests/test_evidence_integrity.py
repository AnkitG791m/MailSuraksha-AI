import unittest
import hashlib
from core.parser import EmailParser
from core.risk_scorer import RiskScorer


class TestEvidenceIntegrity(unittest.TestCase):

    def test_pre_parse_hash_stability(self):
        """Verify that pre-parse SHA-256 and MD5 hashes match parser output."""
        sample_email = (
            b"From: security@paypal.com\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: Security Alert\r\n"
            b"Date: Mon, 12 Sep 2026 12:00:00 +0000\r\n"
            b"\r\n"
            b"Please verify your account immediately at http://paypal-verify.com\r\n"
        )
        expected_sha256 = hashlib.sha256(sample_email).hexdigest()
        expected_md5 = hashlib.md5(sample_email).hexdigest()

        parser = EmailParser(sample_email)
        parsed = parser.parse_all()

        self.assertEqual(parsed["hashes"]["sha256"], expected_sha256)
        self.assertEqual(parsed["hashes"]["md5"], expected_md5)
        self.assertEqual(parsed["hashes"]["size_bytes"], len(sample_email))

    def test_calibrated_scoring_schema_and_decoupling(self):
        """Verify factor schema, signal capping, and decoupled confidence."""
        scorer = RiskScorer()
        
        parsed_email = {
            "headers": {
                "from": {"domain": "paypal.com", "lookalike": {"target_brand": "paypal.com"}},
                "reply_to": {"domain": "hacker.top", "mismatch_with_from": True}
            },
            "urls": {"has_mismatches": True, "has_shortened_urls": False},
            "attachments": [{"is_dangerous": True}]
        }
        auth_results = {
            "dmarc": {"result": "fail", "reason": "DMARC failed"},
            "spf": {"result": "fail"},
            "alignment": {"effective_dmarc_status": "fail", "reply_to_mismatch": True}
        }
        whois_data = {"is_young": True, "age_days": 5, "data_mode": "LIVE"}
        geo_data = {"isp": "DigitalOcean"}
        threat_intel = {"threat_risk_score": 85, "virustotal": {"data_mode": "LIVE"}}
        ml_results = {"ml_risk_score": 75}

        res = scorer.calculate_verdict(
            parsed_email=parsed_email,
            auth_results=auth_results,
            whois_data=whois_data,
            geo_data=geo_data,
            threat_intel=threat_intel,
            ml_results=ml_results
        )

        # Assert score bounds [0, 100]
        self.assertGreaterEqual(res["risk_score"], 0.0)
        self.assertLessEqual(res["risk_score"], 100.0)
        self.assertEqual(res["verdict"], "Malicious")
        self.assertIn(res["risk_band"], ("high", "critical"))

        # Assert decoupled confidence
        self.assertGreaterEqual(res["analysis_confidence"], 0.5)
        self.assertLessEqual(res["analysis_confidence"], 1.0)

        # Assert factor schema: each factor must have signal, name, impact, severity, evidence, confidence
        self.assertGreater(len(res["factors"]), 0)
        for f in res["factors"]:
            self.assertIn("signal", f)
            self.assertIn("impact", f)
            self.assertIn("severity", f)
            self.assertIn("evidence", f)
            self.assertIn("confidence", f)

        # Assert playbook structure
        self.assertGreater(len(res["playbook_items"]), 0)
        for p in res["playbook_items"]:
            self.assertIn("action", p)
            self.assertIn("scope", p)
            self.assertIn("impact_level", p)
            self.assertIn("requires_approval", p)


if __name__ == "__main__":
    unittest.main()
