import re
from typing import Dict, Any, Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class AuthChecker:
    """
    Step 3: SPF, DKIM, and DMARC Authentication Checker.
    1. Examines Authentication-Results, Received-SPF, DKIM-Signature headers.
    2. If headers are absent/inconclusive, performs live DNS queries for:
       - SPF record on <domain>
       - DMARC record on _dmarc.<domain>
    """

    def __init__(self, headers: Dict[str, Any]):
        self.headers = headers
        self.auth_results = headers.get("auth_results", "")
        self.received_spf = headers.get("received_spf", "")
        self.dkim_sig = headers.get("dkim_signature", "")
        self.from_domain = headers.get("from", {}).get("domain", "")

    def check_all(self) -> Dict[str, Any]:
        spf_res = self._check_spf()
        dkim_res = self._check_dkim()
        dmarc_res = self._check_dmarc()

        # Overall authentication verdict
        is_spoofed = (
            spf_res["status"] in ("fail", "softfail") or
            dmarc_res["status"] == "fail" or
            self.headers.get("reply_to", {}).get("mismatch_with_from", False)
        )

        all_passed = (
            spf_res["status"] == "pass" and
            dkim_res["status"] == "pass" and
            dmarc_res["status"] in ("pass", "policy_present")
        )

        return {
            "spf": spf_res,
            "dkim": dkim_res,
            "dmarc": dmarc_res,
            "is_spoofed": is_spoofed,
            "all_passed": all_passed,
            "summary": self._generate_summary(spf_res, dkim_res, dmarc_res, is_spoofed)
        }

    def _check_spf(self) -> Dict[str, Any]:
        combined_text = f"{self.auth_results} {self.received_spf}".lower()
        
        # Check explicit header results
        if "spf=pass" in combined_text or combined_text.startswith("pass"):
            return {
                "status": "pass",
                "source": "header",
                "details": "SPF passed according to email headers."
            }
        elif "spf=fail" in combined_text or combined_text.startswith("fail"):
            return {
                "status": "fail",
                "source": "header",
                "details": "SPF failed: sending IP is unauthorized for domain."
            }
        elif "spf=softfail" in combined_text or combined_text.startswith("softfail"):
            return {
                "status": "softfail",
                "source": "header",
                "details": "SPF softfail: domain is transitioning or questionable authorization."
            }
        elif "spf=neutral" in combined_text:
            return {
                "status": "neutral",
                "source": "header",
                "details": "SPF neutral: domain does not assert whether IP is authorized."
            }

        # Fallback: Live DNS TXT query for SPF record
        dns_spf = self._query_dns_spf(self.from_domain)
        if dns_spf:
            return {
                "status": "record_present",
                "source": "dns",
                "record": dns_spf,
                "details": f"DNS SPF record found for {self.from_domain}: {dns_spf}"
            }

        return {
            "status": "none",
            "source": "header_and_dns",
            "details": "No SPF authentication headers or DNS SPF record found."
        }

    def _check_dkim(self) -> Dict[str, Any]:
        auth_lower = self.auth_results.lower()
        
        if "dkim=pass" in auth_lower:
            return {
                "status": "pass",
                "source": "header",
                "details": "DKIM cryptographic signature verified and passed."
            }
        elif "dkim=fail" in auth_lower:
            return {
                "status": "fail",
                "source": "header",
                "details": "DKIM cryptographic signature verification failed (possible tampering)."
            }
        elif bool(self.dkim_sig):
            return {
                "status": "present_unverified",
                "source": "header",
                "details": "DKIM-Signature header present; receiver did not publish status in Auth-Results."
            }

        return {
            "status": "none",
            "source": "header",
            "details": "No DKIM signature found on email."
        }

    def _check_dmarc(self) -> Dict[str, Any]:
        auth_lower = self.auth_results.lower()

        if "dmarc=pass" in auth_lower:
            return {
                "status": "pass",
                "source": "header",
                "details": "DMARC policy verified and passed."
            }
        elif "dmarc=fail" in auth_lower:
            return {
                "status": "fail",
                "source": "header",
                "details": "DMARC failed: email violates domain's published authentication policy."
            }

        # Fallback: Live DNS TXT query for _dmarc.<domain>
        dns_dmarc = self._query_dns_dmarc(self.from_domain)
        if dns_dmarc:
            policy_match = re.search(r'p\s*=\s*([a-zA-Z]+)', dns_dmarc, re.IGNORECASE)
            policy_val = policy_match.group(1).lower() if policy_match else "none"
            return {
                "status": "policy_present",
                "source": "dns",
                "record": dns_dmarc,
                "policy": policy_val,
                "details": f"Live DMARC record found on _dmarc.{self.from_domain} with policy p={policy_val}."
            }

        return {
            "status": "none",
            "source": "header_and_dns",
            "details": f"No DMARC record configured for domain {self.from_domain}."
        }

    def _query_dns_spf(self, domain: str) -> Optional[str]:
        if not DNS_AVAILABLE or not domain:
            return None
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 2.0
            answers = resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = "".join(b.decode('utf-8', errors='ignore') for b in rdata.strings)
                if txt.startswith("v=spf1"):
                    return txt
        except Exception:
            return None
        return None

    def _query_dns_dmarc(self, domain: str) -> Optional[str]:
        if not DNS_AVAILABLE or not domain:
            return None
        try:
            dmarc_host = f"_dmarc.{domain}"
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 2.0
            answers = resolver.resolve(dmarc_host, 'TXT')
            for rdata in answers:
                txt = "".join(b.decode('utf-8', errors='ignore') for b in rdata.strings)
                if "v=dmarc1" in txt.lower():
                    return txt
        except Exception:
            return None
        return None

    def _generate_summary(self, spf: dict, dkim: dict, dmarc: dict, is_spoofed: bool) -> str:
        if is_spoofed:
            return "High risk of email spoofing or unauthorized sender identity."
        if spf["status"] == "pass" and dkim["status"] == "pass":
            return "Domain authentication verified (SPF & DKIM valid)."
        return "Incomplete or weak authentication configuration."
