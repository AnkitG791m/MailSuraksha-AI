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

    def test_secure_processor_standard_mode(self):
        """Verify SecureProcessor abstraction in standard mode."""
        from core.secure_processor import SecureProcessor
        proc = SecureProcessor(mode="standard")
        sample_bytes = b"Subject: Secure Test\r\n\r\nHello World"
        
        hashes = proc.compute_evidence_hashes(sample_bytes)
        self.assertEqual(hashes["sha256"], hashlib.sha256(sample_bytes).hexdigest())
        self.assertEqual(hashes["md5"], hashlib.md5(sample_bytes).hexdigest())
        self.assertEqual(hashes["byte_size"], len(sample_bytes))

        # Attestation metadata must be honest and not fake a verified enclave
        meta = proc.get_attestation_metadata()
        self.assertEqual(meta["mode"], "standard")
        self.assertEqual(meta["attestation"], "not-available-in-this-mode")
        self.assertIn("planned for production", meta["note"])

    def test_secure_processor_enclave_interface(self):
        """Verify SecureProcessor enclave interface placeholder."""
        from core.secure_processor import SecureProcessor
        proc = SecureProcessor(mode="enclave")
        meta = proc.get_attestation_metadata()
        self.assertEqual(meta["mode"], "enclave")
        self.assertEqual(meta["attestation"], "enclave-interface-ready")
        self.assertIn("AWS Nitro Enclave", meta["enclave_provider"])

    def test_secure_processor_pii_sanitization(self):
        """Verify SecureProcessor wraps PII sanitization."""
        from core.secure_processor import SecureProcessor
        proc = SecureProcessor()
        text_with_pii = "My password: SuperSecretPassword123 and card 4111 2222 3333 4444"
        sanitized = proc.sanitize_content(text_with_pii)
        self.assertNotIn("SuperSecretPassword123", sanitized)
        self.assertNotIn("4111 2222 3333 4444", sanitized)
        self.assertIn("[REDACTED_PASSWORD]", sanitized)
        self.assertIn("[REDACTED_CARD_NUMBER]", sanitized)


if __name__ == "__main__":
    unittest.main()

