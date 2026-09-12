import unittest
from core.auth_check import AuthChecker, get_organizational_domain


class TestRFCAlignment(unittest.TestCase):

    def test_public_suffix_organizational_domain(self):
        """Verify Public Suffix List logic handles multi-part ccTLDs correctly."""
        self.assertEqual(get_organizational_domain("mail.corp.co.in"), "corp.co.in")
        self.assertEqual(get_organizational_domain("sbi.co.in"), "sbi.co.in")
        self.assertEqual(get_organizational_domain("portal.cybercrime.gov.in"), "cybercrime.gov.in")
        self.assertEqual(get_organizational_domain("support.amazon.co.uk"), "amazon.co.uk")
        self.assertEqual(get_organizational_domain("sub.example.com"), "example.com")
        self.assertEqual(get_organizational_domain("example.com"), "example.com")
        self.assertEqual(get_organizational_domain("service.anz.com.au"), "anz.com.au")

    def test_spf_strict_vs_relaxed_alignment(self):
        """Test strict vs relaxed SPF alignment against Header From."""
        # 1. Strict alignment: exact match
        headers_strict = {
            "from": {"domain": "example.com", "email": "alice@example.com"},
            "return_path": {"domain": "example.com", "email": "bounces@example.com"},
            "auth_results": "mailsuraksha.internal; spf=pass smtp.mailfrom=example.com"
        }
        checker_strict = AuthChecker(headers_strict)
        res_strict = checker_strict.check_all()
        self.assertTrue(res_strict["alignment"]["spf_strict"])
        self.assertTrue(res_strict["alignment"]["spf_aligned"])

        # 2. Relaxed alignment: subdomains share organizational domain
        headers_relaxed = {
            "from": {"domain": "example.com", "email": "alice@example.com"},
            "return_path": {"domain": "mail.example.com", "email": "bounces@mail.example.com"},
            "auth_results": "mailsuraksha.internal; spf=pass smtp.mailfrom=mail.example.com"
        }
        checker_relaxed = AuthChecker(headers_relaxed)
        res_relaxed = checker_relaxed.check_all()
        self.assertFalse(res_relaxed["alignment"]["spf_strict"])
        self.assertTrue(res_relaxed["alignment"]["spf_relaxed"])
        self.assertTrue(res_relaxed["alignment"]["spf_aligned"])

        # 3. Unaligned domains
        headers_unaligned = {
            "from": {"domain": "bank.com", "email": "security@bank.com"},
            "return_path": {"domain": "attacker.net", "email": "drop@attacker.net"},
            "auth_results": "mailsuraksha.internal; spf=pass smtp.mailfrom=attacker.net"
        }
        checker_unaligned = AuthChecker(headers_unaligned)
        res_unaligned = checker_unaligned.check_all()
        self.assertFalse(res_unaligned["alignment"]["spf_aligned"])
        self.assertEqual(res_unaligned["alignment"]["effective_dmarc_status"], "fail")

    def test_multi_dkim_signatures_evaluation(self):
        """Test evaluation of multiple DKIM signatures independently."""
        headers = {
            "from": {"domain": "acme.com", "email": "ceo@acme.com"},
            "return_path": {"domain": "acme.com", "email": "bounces@acme.com"},
            "dkim_signatures": [
                "v=1; a=rsa-sha256; c=relaxed/relaxed; d=sendgrid.net; s=smtp; bh=xyz; b=abc",
                "v=1; a=rsa-sha256; c=relaxed/relaxed; d=acme.com; s=s1; bh=xyz; b=123"
            ],
            "auth_results": "mailsuraksha.internal; dkim=pass header.d=sendgrid.net; dkim=pass header.d=acme.com"
        }
        checker = AuthChecker(headers)
        res = checker.check_all()

        # Both signatures should be extracted
        self.assertEqual(len(res["dkim_signatures"]), 2)
        # acme.com signature aligns with Header From
        self.assertTrue(res["alignment"]["dkim_aligned"])
        self.assertEqual(res["dmarc"]["result"], "pass")
        self.assertEqual(res["dmarc"]["disposition"], "none")

    def test_untrusted_auth_results_filtering(self):
        """Test that Authentication-Results from untrusted authserv-id are not authoritative."""
        headers = {
            "from": {"domain": "legitimate.com", "email": "admin@legitimate.com"},
            "return_path": {"domain": "legitimate.com", "email": "admin@legitimate.com"},
            # Injected attacker header claiming spf=pass
            "auth_results": "evil-hacker.com; spf=pass header.from=legitimate.com"
        }
        checker = AuthChecker(headers)
        self.assertEqual(len(checker.trusted_auth_results), 0)
        self.assertEqual(len(checker.untrusted_auth_results), 1)
        res = checker.check_all()
        # Because the only header was untrusted and no DNS/live pass exists, it shouldn't pass as trusted header pass
        self.assertFalse(res["trusted_auth_results_found"])


if __name__ == "__main__":
    unittest.main()
