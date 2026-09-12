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
        
        from_dict = headers.get("from", {}) if isinstance(headers.get("from"), dict) else {}
        self.header_from_domain = from_dict.get("domain", "").lower().strip()
        self.from_raw = from_dict.get("raw", "")
        
        return_path_dict = headers.get("return_path", {}) if isinstance(headers.get("return_path"), dict) else {}
        self.mail_from_domain = return_path_dict.get("domain", "").lower().strip()
        
        reply_to_dict = headers.get("reply_to", {}) if isinstance(headers.get("reply_to"), dict) else {}
        self.reply_to_domain = reply_to_dict.get("domain", "").lower().strip()

    def check_all(self) -> Dict[str, Any]:
        spf_res = self._check_spf()
        dkim_res = self._check_dkim()
        dmarc_res = self._check_dmarc()
        alignment_data = self._check_alignment(spf_res, dkim_res, dmarc_res)

        # Standards-aware overall verdict
        is_spoofed = (
            alignment_data["effective_dmarc_status"] in ("fail", "reject") or
            (spf_res["status"] in ("fail", "softfail") and not dkim_res.get("aligned")) or
            alignment_data.get("identity_mismatch_detected", False)
        )

        all_passed = (
            alignment_data["effective_dmarc_status"] == "pass" or
            (spf_res["status"] == "pass" and dkim_res["status"] == "pass" and alignment_data["spf_aligned"])
        )

        return {
            "spf": spf_res,
            "dkim": dkim_res,
            "dmarc": dmarc_res,
            "alignment": alignment_data,
            "alignment_matrix": alignment_data.get("matrix", []),
            "is_spoofed": is_spoofed,
            "all_passed": all_passed,
            "summary": self._generate_summary(spf_res, dkim_res, dmarc_res, alignment_data)
        }

    @staticmethod
    def get_org_domain(domain: str) -> str:
        """Extracts apex/organizational domain (e.g., mail.example.com -> example.com)."""
        if not domain:
            return ""
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain.lower()

    def _check_spf(self) -> Dict[str, Any]:
        combined_text = f"{self.auth_results} {self.received_spf}".lower()
        spf_domain = self.mail_from_domain or self.header_from_domain

        if "spf=pass" in combined_text or combined_text.startswith("pass"):
            return {
                "status": "pass",
                "source": "header",
                "domain": spf_domain,
                "details": "SPF passed: Originating mail server is explicitly authorized in sender DNS."
            }
        elif "spf=fail" in combined_text or combined_text.startswith("fail"):
            return {
                "status": "fail",
                "source": "header",
                "domain": spf_domain,
                "details": "SPF hard-fail: Originating IP is not authorized by the domain owner."
            }
        elif "spf=softfail" in combined_text or combined_text.startswith("softfail"):
            return {
                "status": "softfail",
                "source": "header",
                "domain": spf_domain,
                "details": "SPF softfail: Domain does not explicitly authorize sending IP (~all)."
            }
        elif "spf=neutral" in combined_text:
            return {
                "status": "neutral",
                "source": "header",
                "domain": spf_domain,
                "details": "SPF neutral: Domain makes no explicit assertion regarding authorized IPs."
            }

        # Fallback: Live DNS TXT query for SPF record
        dns_spf = self._query_dns_spf(self.header_from_domain)
        if dns_spf:
            return {
                "status": "record_present",
                "source": "dns",
                "domain": self.header_from_domain,
                "record": dns_spf,
                "details": f"DNS SPF record found for {self.header_from_domain}: {dns_spf[:60]}..."
            }

        return {
            "status": "none",
            "source": "header_and_dns",
            "domain": self.header_from_domain,
            "details": "No SPF authentication headers or DNS SPF record published."
        }

    def _check_dkim(self) -> Dict[str, Any]:
        auth_lower = self.auth_results.lower()
        
        # Extract DKIM d= domain and s= selector from signature header
        d_match = re.search(r'\bd\s*=\s*([a-zA-Z0-9\.\-_]+)', self.dkim_sig)
        s_match = re.search(r'\bs\s*=\s*([a-zA-Z0-9\.\-_]+)', self.dkim_sig)
        signing_domain = d_match.group(1).lower() if d_match else ""
        selector = s_match.group(1) if s_match else "unknown"

        if "dkim=pass" in auth_lower:
            return {
                "status": "pass",
                "source": "header",
                "signing_domain": signing_domain or self.header_from_domain,
                "selector": selector,
                "details": f"DKIM signature valid and verified (selector: '{selector}', domain: '{signing_domain or self.header_from_domain}')."
            }
        elif "dkim=fail" in auth_lower:
            return {
                "status": "fail",
                "source": "header",
                "signing_domain": signing_domain,
                "selector": selector,
                "details": "DKIM cryptographic signature check failed (possible content tampering in transit)."
            }
        elif bool(self.dkim_sig):
            return {
                "status": "present_unverified",
                "source": "header",
                "signing_domain": signing_domain,
                "selector": selector,
                "details": f"DKIM-Signature present for domain '{signing_domain}' (receiver published no validation status)."
            }

        return {
            "status": "none",
            "source": "header",
            "signing_domain": "",
            "selector": "",
            "details": "No DKIM cryptographic signature found in email headers."
        }

    def _check_dmarc(self) -> Dict[str, Any]:
        auth_lower = self.auth_results.lower()

        if "dmarc=pass" in auth_lower:
            return {
                "status": "pass",
                "source": "header",
                "policy": "enforced",
                "details": "DMARC policy verified and passed in Authentication-Results."
            }
        elif "dmarc=fail" in auth_lower:
            return {
                "status": "fail",
                "source": "header",
                "policy": "fail",
                "details": "DMARC failed: Email violates the domain's published DMARC authentication policy."
            }

        # Fallback: Live DNS TXT query for _dmarc.<domain>
        dns_dmarc = self._query_dns_dmarc(self.header_from_domain)
        if dns_dmarc:
            policy_match = re.search(r'p\s*=\s*([a-zA-Z]+)', dns_dmarc, re.IGNORECASE)
            policy_val = policy_match.group(1).lower() if policy_match else "none"
            return {
                "status": "policy_present",
                "source": "dns",
                "record": dns_dmarc,
                "policy": policy_val,
                "details": f"Live DMARC record discovered on _dmarc.{self.header_from_domain} (Policy: p={policy_val})."
            }

        return {
            "status": "none",
            "source": "header_and_dns",
            "policy": "none",
            "details": f"No DMARC policy record configured for domain '{self.header_from_domain}'."
        }

    def _check_alignment(self, spf: dict, dkim: dict, dmarc: dict) -> Dict[str, Any]:
        """
        RFC 7489 Standards-Based Alignment Check.
        Computes strict (exact) and relaxed (organizational domain) alignment:
        1. SPF Alignment: MAIL FROM (Return-Path) vs Header From.
        2. DKIM Alignment: DKIM d= signing domain vs Header From.
        3. Effective DMARC Status based on alignment.
        """
        h_from = self.header_from_domain
        h_org = self.get_org_domain(h_from)
        
        # 1. SPF Alignment
        m_from = self.mail_from_domain or spf.get("domain", "")
        m_org = self.get_org_domain(m_from)
        
        spf_strict = bool(h_from and m_from and h_from == m_from)
        spf_relaxed = bool(h_org and m_org and h_org == m_org)
        spf_aligned = spf_strict or spf_relaxed
        
        # 2. DKIM Alignment
        d_sign = dkim.get("signing_domain", "")
        d_org = self.get_org_domain(d_sign)
        
        dkim_strict = bool(h_from and d_sign and h_from == d_sign)
        dkim_relaxed = bool(h_org and d_org and h_org == d_org)
        dkim_aligned = dkim_strict or dkim_relaxed
        
        # 3. Identity Inconsistencies
        reply_to_mismatch = bool(self.reply_to_domain and h_from and self.get_org_domain(self.reply_to_domain) != h_org)
        return_path_mismatch = bool(m_from and h_from and not spf_aligned)
        
        # 4. RFC 7489 Effective DMARC Evaluation
        # DMARC passes IF AND ONLY IF (SPF pass AND SPF aligned) OR (DKIM pass AND DKIM aligned)
        spf_pass_and_aligned = (spf.get("status") == "pass" and spf_aligned)
        dkim_pass_and_aligned = (dkim.get("status") == "pass" and dkim_aligned)
        
        if spf_pass_and_aligned or dkim_pass_and_aligned:
            effective_dmarc = "pass"
            dmarc_verdict_reason = f"DMARC compliant via {'SPF' if spf_pass_and_aligned else 'DKIM'} identifier alignment."
        elif dmarc.get("status") == "fail":
            effective_dmarc = "fail"
            dmarc_verdict_reason = "DMARC failed: Neither SPF nor DKIM passed in alignment with Header From."
        elif dmarc.get("policy") in ("reject", "quarantine") and not (spf_pass_and_aligned or dkim_pass_and_aligned):
            effective_dmarc = "fail"
            dmarc_verdict_reason = f"Domain mandates p={dmarc.get('policy')} but identifiers are unaligned."
        elif dmarc.get("status") == "pass":
            effective_dmarc = "pass"
            dmarc_verdict_reason = "Receiver reported DMARC pass in Authentication-Results."
        else:
            effective_dmarc = "unaligned" if (return_path_mismatch or reply_to_mismatch) else "neutral"
            dmarc_verdict_reason = "Insufficient cryptographic authentication or domain misalignment."

        # Alignment Matrix for Dashboard and Forensic PDF Tables
        matrix = [
            {
                "protocol": "SPF (RFC 7208)",
                "result": spf.get("status", "none").upper(),
                "domain": m_from or "N/A",
                "alignment": "PASS (Relaxed)" if spf_relaxed else ("PASS (Strict)" if spf_strict else "FAIL (Unaligned)"),
                "evidence": f"MAIL FROM: '{m_from}' vs Header From: '{h_from}'"
            },
            {
                "protocol": "DKIM (RFC 6376)",
                "result": dkim.get("status", "none").upper(),
                "domain": d_sign or "None",
                "alignment": "PASS (Relaxed)" if dkim_relaxed else ("PASS (Strict)" if dkim_strict else "FAIL (Unaligned)"),
                "evidence": f"d='{d_sign}' (Selector: {dkim.get('selector', 'N/A')})"
            },
            {
                "protocol": "DMARC (RFC 7489)",
                "result": effective_dmarc.upper(),
                "domain": h_from or "N/A",
                "alignment": "COMPLIANT" if effective_dmarc == "pass" else "POLICY VIOLATION",
                "evidence": dmarc_verdict_reason
            }
        ]

        return {
            "header_from_domain": h_from,
            "mail_from_domain": m_from,
            "dkim_signing_domain": d_sign,
            "spf_strict": spf_strict,
            "spf_relaxed": spf_relaxed,
            "spf_aligned": spf_aligned,
            "dkim_strict": dkim_strict,
            "dkim_relaxed": dkim_relaxed,
            "dkim_aligned": dkim_aligned,
            "effective_dmarc_status": effective_dmarc,
            "dmarc_reason": dmarc_verdict_reason,
            "identity_mismatch_detected": reply_to_mismatch or return_path_mismatch,
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch,
            "matrix": matrix
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

    def _generate_summary(self, spf: dict, dkim: dict, dmarc: dict, alignment: dict) -> str:
        if alignment.get("effective_dmarc_status") == "pass":
            return "RFC 7489 DMARC Compliant: Authenticated identity matches visible Header From."
        if alignment.get("identity_mismatch_detected"):
            return "Critical Identity Misalignment: Envelope MAIL FROM or Reply-To diverges from Header From."
        if spf["status"] in ("fail", "softfail") or dmarc["status"] == "fail":
            return "Domain Authentication Failure: Unauthorized relay infrastructure detected."
        return "Incomplete Authentication: Missing cryptographic DKIM signatures or unverified DMARC policy."

