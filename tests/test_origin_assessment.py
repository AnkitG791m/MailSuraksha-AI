import unittest
from core.origin_ip import OriginIPExtractor


class TestOriginAssessment(unittest.TestCase):

    def test_clock_inversion_anomaly_detection(self):
        """Verify non-monotonic Received timestamps are detected as header anomalies."""
        hops = [
            # Hop 0 (Top / latest): Recipient MTA at 12:00:00 UTC
            {
                "raw": "from mx.google.com by internal.company.com; Mon, 12 Sep 2026 12:00:00 +0000",
                "timestamp": "Mon, 12 Sep 2026 12:00:00 +0000"
            },
            # Hop 1 (Middle): Inverted timestamp at 12:15:00 UTC (15 mins in future!)
            {
                "raw": "from relay.sender.com by mx.google.com with ESMTP id 123 (198.51.100.25); Mon, 12 Sep 2026 12:15:00 +0000",
                "timestamp": "Mon, 12 Sep 2026 12:15:00 +0000"
            },
            # Hop 2 (Earliest): Earliest hop at 12:05:00 UTC
            {
                "raw": "from client.internal by relay.sender.com (203.0.113.10); Mon, 12 Sep 2026 12:05:00 +0000",
                "timestamp": "Mon, 12 Sep 2026 12:05:00 +0000"
            }
        ]
        extractor = OriginIPExtractor(hops)
        res = extractor.extract()

        self.assertIn(res["forgery_assessment"], ("anomalies_detected", "likely_untrusted"))
        self.assertTrue(any(a["type"] == "timestamp_inversion" for a in res["header_anomalies"]))
        self.assertIn("non_monotonic_timestamp", res["forgery_indicators"])

    def test_relay_trust_model_and_candidate_attribution(self):
        """Verify relay trust basis and candidate origin IP attribution."""
        hops = [
            # Top hop: Recipient MX
            {
                "from_host": "mail-relay.google.com",
                "by_host": "mx.corporate.in",
                "raw": "from mail-relay.google.com by mx.corporate.in with ESMTP id abc (209.85.220.41); Mon, 12 Sep 2026 10:00:00 +0000",
                "timestamp": "Mon, 12 Sep 2026 10:00:00 +0000"
            },
            # Bottom hop: Sender external submission
            {
                "from_host": "client.sender.org",
                "by_host": "mail-relay.google.com",
                "raw": "from client.sender.org by mail-relay.google.com with ESMTP id def (192.0.2.75); Mon, 12 Sep 2026 09:59:50 +0000",
                "timestamp": "Mon, 12 Sep 2026 09:59:50 +0000"
            }
        ]
        extractor = OriginIPExtractor(hops)
        res = extractor.extract()

        # Check candidate origin attribution
        self.assertEqual(res["candidate_origin_ip"], "192.0.2.75")
        self.assertGreaterEqual(res["candidate_attribution_confidence"], 0.5)

        # Check first trusted relay evaluation
        first_relay = res["first_trusted_relay"]
        self.assertIn("provider_metadata", first_relay.get("trust_basis", []))
        self.assertIn(first_relay.get("trust_level"), ("high", "medium"))


if __name__ == "__main__":
    unittest.main()
