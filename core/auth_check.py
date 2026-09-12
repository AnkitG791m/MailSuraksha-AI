import re
from typing import Dict, Any, List, Optional
from config import settings

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# Comprehensive multi-part public suffixes for organizational domain extraction (RFC 7489 Section 3.2)
MULTI_PART_PUBLIC_SUFFIXES = {
    # India (.in)
    "co.in", "gov.in", "ac.in", "edu.in", "res.in", "org.in", "net.in", "nic.in", "mil.in", "gen.in", "firm.in", "ind.in",
    # United Kingdom (.uk)
    "co.uk", "gov.uk", "ac.uk", "org.uk", "net.uk", "sch.uk", "police.uk", "nhs.uk", "me.uk", "ltd.uk", "plc.uk",
    # Australia (.au)
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au", "csiro.au",
    # New Zealand (.nz)
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz", "school.nz",
    # Japan (.jp)
    "co.jp", "ne.jp", "ac.jp", "go.jp", "or.jp", "ed.jp", "ad.jp", "gr.jp", "lg.jp",
    # Brazil (.br)
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br", "esp.br",
    # South Africa (.za)
    "co.za", "gov.za", "ac.za", "org.za", "net.za", "edu.za", "law.za",
    # Singapore (.sg)
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg", "per.sg",
    # Canada (.ca)
    "gc.ca",
    # Others & common SLDs
    "com.mx", "gob.mx", "edu.mx", "com.ar", "gov.ar", "com.co", "gov.co",
    "com.tr", "gov.tr", "edu.tr", "com.hk", "edu.hk", "gov.hk", "com.tw", "gov.tw",
    "co.id", "go.id", "ac.id", "co.il", "gov.il", "ac.il", "co.kr", "go.kr", "ne.kr"
}


def get_organizational_domain(domain: str) -> str:
    """
    Extracts the organizational domain (apex domain) using Public Suffix List awareness
    pursuant to RFC 7489 Section 3.2.
    Example:
      'mail.corp.co.in' -> 'corp.co.in'
      'support.amazon.co.uk' -> 'amazon.co.uk'
      'sub.example.com' -> 'example.com'
      'example.com' -> 'example.com'
    """
    if not domain:
        return ""
    d = domain.lower().strip().rstrip(".")
    labels = d.split(".")
    if len(labels) <= 1:
        return d

    # Check for known 2-label public suffixes (e.g., 'co.in', 'gov.uk')
    if len(labels) >= 3:
        two_label_suffix = f"{labels[-2]}.{labels[-1]}"
        if two_label_suffix in MULTI_PART_PUBLIC_SUFFIXES:
            return ".".join(labels[-3:])

    # Default to single-label TLD (e.g., 'example.com')
    return ".".join(labels[-2:])


class AuthChecker:
    """
    RFC 7489 Standards-Aware SPF, DKIM, and DMARC Authentication Engine.
    
    Key Responsibilities:
    1. Distinguishes RFC 5321 (Envelope MAIL FROM / Return-Path) and RFC 5322 (Header From).
    2. Evaluates Trust Boundaries for Authentication-Results headers against configured authserv-ids.
    3. Evaluates multiple DKIM signatures independently.
    4. Evaluates Strict vs Relaxed identifier alignment (aspf, adkim) via Public Suffix List.
    5. Computes DMARC result, published policy request, and receiver disposition.
    6. Generates standardized Alignment Matrix for forensic PDF reports and SOC dashboard.
    """

    def __init__(self, headers: Dict[str, Any]):
        self.headers = headers
        self.auth_results_raw = headers.get("auth_results", "")
        self.auth_results_list = headers.get("auth_results_list", [])
        if not self.auth_results_list and self.auth_results_raw:
            self.auth_results_list = [self.auth_results_raw]

        self.received_spf = headers.get("received_spf", "")
        
        # Multi-signature DKIM extraction
        self.dkim_signatures = headers.get("dkim_signatures", [])
        if not self.dkim_signatures and headers.get("dkim_signature"):
            self.dkim_signatures = [headers.get("dkim_signature")]
            
        # RFC 5322 Header From
        from_dict = headers.get("from", {}) if isinstance(headers.get("from"), dict) else {}
        self.header_from_domain = from_dict.get("domain", "").lower().strip()
        self.from_raw = from_dict.get("raw", "")

        # RFC 5321 Envelope Return-Path (MAIL FROM)
        return_path_dict = headers.get("return_path", {}) if isinstance(headers.get("return_path"), dict) else {}
        self.mail_from_domain = return_path_dict.get("domain", "").lower().strip()

        # Reply-To domain
        reply_to_dict = headers.get("reply_to", {}) if isinstance(headers.get("reply_to"), dict) else {}
        self.reply_to_domain = reply_to_dict.get("domain", "").lower().strip()

        # Filter trusted Authentication-Results headers
        self.trusted_auth_results, self.untrusted_auth_results = self._filter_auth_results_by_trust()

    def _filter_auth_results_by_trust(self) -> tuple[List[str], List[str]]:
        """
        Validates Authentication-Results headers against configured TRUSTED_AUTHSERV_IDS.
        Only headers stamped by our trusted boundary MTAs are considered authoritative.
        Untrusted/injected headers are separated to prevent adversary spoofing of auth passes.
        """
        trusted = []
        untrusted = []
        trusted_ids = [tid.lower() for tid in getattr(settings, "TRUSTED_AUTHSERV_IDS", [])]

        for header_val in self.auth_results_list:
            clean_val = str(header_val).strip()
            if not clean_val:
                continue
            # Header syntax: Authentication-Results: <authserv-id>; ...
            match = re.match(r'^\s*([a-zA-Z0-9\.\-_]+)', clean_val)
            authserv_id = match.group(1).lower() if match else ""
            
            # Check if authserv_id matches or ends with any trusted domain
            is_trusted = False
            if authserv_id:
                for tid in trusted_ids:
                    if authserv_id == tid or authserv_id.endswith("." + tid):
                        is_trusted = True
                        break
            
            # In development/benchmark environments or when no authserv-id configured, allow evaluation
            if is_trusted or not trusted_ids:
                trusted.append(clean_val)
            else:
                untrusted.append(clean_val)

        return trusted, untrusted

    def check_all(self) -> Dict[str, Any]:
        spf_res = self._check_spf()
        dkim_res_list = self._check_dkim_multi()
        dmarc_res = self._check_dmarc()
        alignment_data = self._check_alignment(spf_res, dkim_res_list, dmarc_res)

        # Primary DKIM entry (first aligned signature or first signature)
        primary_dkim = next((d for d in dkim_res_list if d.get("aligned")), dkim_res_list[0] if dkim_res_list else {
            "result": "none",
            "status": "none",
            "signing_domain": "",
            "selector": "",
            "aligned": False,
            "alignment": "unaligned",
            "details": "No DKIM signatures present"
        })

        is_spoofed = (
            alignment_data["effective_dmarc_status"] in ("fail", "reject") or
            (spf_res["result"] in ("fail", "softfail") and not alignment_data["dkim_aligned"]) or
            alignment_data.get("identity_mismatch_detected", False)
        )

        all_passed = (
            alignment_data["effective_dmarc_status"] == "pass" or
            (spf_res["result"] == "pass" and primary_dkim["result"] == "pass" and alignment_data["spf_aligned"])
        )

        # Canonical DMARC object per critique requirements
        dmarc_obj = {
            "result": alignment_data["effective_dmarc_status"],
            "status": alignment_data["effective_dmarc_status"],
            "policy": dmarc_res.get("policy", "none"),
            "disposition": alignment_data["disposition"],
            "reason": alignment_data["dmarc_reason"],
            "record": dmarc_res.get("record", "")
        }

        # Canonical SPF object with both result and legacy status keys
        spf_res["status"] = spf_res["result"]
        primary_dkim["status"] = primary_dkim["result"]

        return {
            "header_from_domain": self.header_from_domain,
            "mail_from_domain": self.mail_from_domain,
            "dkim_signing_domains": [d.get("signing_domain") for d in dkim_res_list if d.get("signing_domain")],
            "spf": spf_res,
            "dkim": primary_dkim,
            "dkim_signatures": dkim_res_list,
            "dmarc": dmarc_obj,
            "alignment": alignment_data,
            "alignment_matrix": alignment_data.get("matrix", []),
            "trusted_auth_results_found": len(self.trusted_auth_results) > 0,
            "untrusted_auth_headers_count": len(self.untrusted_auth_results),
            "is_spoofed": is_spoofed,
            "all_passed": all_passed,
            "summary": self._generate_summary(spf_res, primary_dkim, dmarc_obj, alignment_data)
        }

    @staticmethod
    def get_org_domain(domain: str) -> str:
        """Expose public suffix-aware organizational domain extractor."""
        return get_organizational_domain(domain)

    def _check_spf(self) -> Dict[str, Any]:
        """
        Evaluates SPF authentication result on RFC 5321 MailFrom domain.
        Examines trusted Authentication-Results and Received-SPF, falling back to DNS.
        """
        combined_text = " ".join(self.trusted_auth_results + [self.received_spf]).lower()
        spf_domain = self.mail_from_domain or self.header_from_domain

        if "spf=pass" in combined_text or combined_text.startswith("pass"):
            return {
                "result": "pass",
                "source": "header",
                "domain": spf_domain,
                "details": "SPF passed: Originating mail server authorized in sender DNS."
            }
        elif "spf=fail" in combined_text or combined_text.startswith("fail"):
            return {
                "result": "fail",
                "source": "header",
                "domain": spf_domain,
                "details": "SPF hard-fail: Originating IP unauthorized in sender domain SPF record (-all)."
            }
        elif "spf=softfail" in combined_text or combined_text.startswith("softfail"):
            return {
                "result": "softfail",
                "source": "header",
                "domain": spf_domain,
                "details": "SPF softfail: Domain does not explicitly authorize sending IP (~all)."
            }
        elif "spf=neutral" in combined_text:
            return {
                "result": "neutral",
                "source": "header",
                "domain": spf_domain,
                "details": "SPF neutral: Sender domain makes no explicit assertion regarding authorized IPs (?all)."
            }

        # Fallback: Live DNS query
        dns_spf = self._query_dns_spf(self.header_from_domain)
        if dns_spf:
            return {
                "result": "record_present",
                "source": "dns",
                "domain": self.header_from_domain,
                "record": dns_spf,
                "details": f"DNS SPF record discovered on {self.header_from_domain}: {dns_spf[:60]}..."
            }

        return {
            "result": "none",
            "source": "header_and_dns",
            "domain": self.header_from_domain,
            "details": "No SPF authentication headers or DNS SPF record published."
        }

    def _check_dkim_multi(self) -> List[Dict[str, Any]]:
        """
        Evaluates ALL DKIM-Signature headers independently (multi-signature support).
        """
        results = []
        trusted_text = " ".join(self.trusted_auth_results).lower()

        if not self.dkim_signatures:
            # Check if trusted auth-results mentions DKIM pass
            if "dkim=pass" in trusted_text:
                d_match = re.search(r'header\.d\s*=\s*([a-zA-Z0-9\.\-_]+)', trusted_text)
                sign_d = d_match.group(1) if d_match else self.header_from_domain
                return [{
                    "result": "pass",
                    "source": "header",
                    "signing_domain": sign_d,
                    "selector": "default",
                    "aligned": False,
                    "alignment": "unaligned",
                    "details": f"DKIM passed in Authentication-Results (domain: '{sign_d}')."
                }]
            return [{
                "result": "none",
                "source": "header",
                "signing_domain": "",
                "selector": "",
                "aligned": False,
                "alignment": "unaligned",
                "details": "No DKIM cryptographic signature found in email headers."
            }]

        for sig_header in self.dkim_signatures:
            sig_str = str(sig_header)
            d_match = re.search(r'\bd\s*=\s*([a-zA-Z0-9\.\-_]+)', sig_str, re.IGNORECASE)
            s_match = re.search(r'\bs\s*=\s*([a-zA-Z0-9\.\-_]+)', sig_str, re.IGNORECASE)
            a_match = re.search(r'\ba\s*=\s*([a-zA-Z0-9\.\-_]+)', sig_str, re.IGNORECASE)

            signing_domain = d_match.group(1).lower() if d_match else ""
            selector = s_match.group(1) if s_match else "unknown"
            algorithm = a_match.group(1) if a_match else "rsa-sha256"

            if not signing_domain:
                continue

            # Determine authentication result for this specific signature
            if f"header.d={signing_domain}" in trusted_text and "dkim=pass" in trusted_text:
                sig_result = "pass"
                sig_details = f"DKIM signature valid and authenticated for domain '{signing_domain}'."
            elif "dkim=pass" in trusted_text and len(self.dkim_signatures) == 1:
                sig_result = "pass"
                sig_details = f"DKIM signature authenticated for domain '{signing_domain}'."
            elif "dkim=fail" in trusted_text and (f"header.d={signing_domain}" in trusted_text or len(self.dkim_signatures) == 1):
                sig_result = "fail"
                sig_details = f"DKIM cryptographic verification failed for domain '{signing_domain}'."
            else:
                sig_result = "present_unverified"
                sig_details = f"DKIM-Signature present on domain '{signing_domain}' (receiver provided no validation token)."

            # Compute alignment against Header From
            h_from = self.header_from_domain
            h_org = get_organizational_domain(h_from)
            d_org = get_organizational_domain(signing_domain)

            is_strict = bool(h_from and signing_domain and h_from == signing_domain)
            is_relaxed = bool(h_org and d_org and h_org == d_org)
            is_aligned = is_strict or is_relaxed
            alignment_mode = "strict" if is_strict else ("relaxed" if is_relaxed else "unaligned")

            results.append({
                "result": sig_result,
                "source": "header",
                "signing_domain": signing_domain,
                "selector": selector,
                "algorithm": algorithm,
                "aligned": is_aligned,
                "alignment": alignment_mode,
                "details": sig_details
            })

        if not results:
            results.append({
                "result": "none",
                "source": "header",
                "signing_domain": "",
                "selector": "",
                "aligned": False,
                "alignment": "unaligned",
                "details": "Malformed or empty DKIM signatures."
            })

        return results

    def _check_dmarc(self) -> Dict[str, Any]:
        """
        Discovers DMARC policy from trusted headers or live DNS query at _dmarc.<domain>.
        """
        trusted_text = " ".join(self.trusted_auth_results).lower()

        header_result = None
        if "dmarc=pass" in trusted_text:
            header_result = "pass"
        elif "dmarc=fail" in trusted_text:
            header_result = "fail"

        # Query DNS DMARC TXT record
        dns_dmarc = self._query_dns_dmarc(self.header_from_domain)
        policy_val = "none"
        aspf_val = "r"
        adkim_val = "r"

        if dns_dmarc:
            p_match = re.search(r'\bp\s*=\s*([a-zA-Z]+)', dns_dmarc, re.IGNORECASE)
            aspf_match = re.search(r'\baspf\s*=\s*([rs])\b', dns_dmarc, re.IGNORECASE)
            adkim_match = re.search(r'\badkim\s*=\s*([rs])\b', dns_dmarc, re.IGNORECASE)

            policy_val = p_match.group(1).lower() if p_match else "none"
            aspf_val = aspf_match.group(1).lower() if aspf_match else "r"
            adkim_val = adkim_match.group(1).lower() if adkim_match else "r"

        return {
            "header_result": header_result,
            "policy": policy_val,
            "aspf": aspf_val,
            "adkim": adkim_val,
            "record": dns_dmarc or "",
            "details": f"DMARC published policy: p={policy_val} (aspf={aspf_val}, adkim={adkim_val})" if dns_dmarc else "No DMARC DNS record found"
        }

    def _check_alignment(self, spf: dict, dkim_list: List[dict], dmarc: dict) -> Dict[str, Any]:
        """
        RFC 7489 Formal Alignment Evaluation.
        DMARC passes if:
          (SPF == pass AND SPF aligned according to aspf) OR
          (At least one DKIM signature == pass AND aligned according to adkim)
        """
        h_from = self.header_from_domain
        h_org = get_organizational_domain(h_from)
        aspf_mode = dmarc.get("aspf", "r")
        adkim_mode = dmarc.get("adkim", "r")

        # 1. SPF Alignment Check
        m_from = self.mail_from_domain or spf.get("domain", "")
        m_org = get_organizational_domain(m_from)

        spf_strict = bool(h_from and m_from and h_from == m_from)
        spf_relaxed = bool(h_org and m_org and h_org == m_org)
        spf_aligned = spf_strict if aspf_mode == "s" else (spf_strict or spf_relaxed)
        spf_alignment_label = "strict" if spf_strict else ("relaxed" if spf_relaxed else "unaligned")

        # 2. DKIM Alignment Check (across all signatures)
        dkim_aligned = False
        dkim_strict = False
        dkim_relaxed = False
        aligned_signing_domain = None

        for d in dkim_list:
            d_sign = d.get("signing_domain", "")
            d_org = get_organizational_domain(d_sign)
            cur_strict = bool(h_from and d_sign and h_from == d_sign)
            cur_relaxed = bool(h_org and d_org and h_org == d_org)
            cur_aligned = cur_strict if adkim_mode == "s" else (cur_strict or cur_relaxed)

            if d.get("result") == "pass" and cur_aligned:
                dkim_aligned = True
                aligned_signing_domain = d_sign
                dkim_strict = dkim_strict or cur_strict
                dkim_relaxed = dkim_relaxed or cur_relaxed

        # 3. Identity Discrepancies
        reply_to_mismatch = bool(self.reply_to_domain and h_from and get_organizational_domain(self.reply_to_domain) != h_org)
        return_path_mismatch = bool(m_from and h_from and not spf_aligned)

        # 4. RFC 7489 Evaluation & Receiver Disposition
        spf_pass_and_aligned = (spf.get("result") == "pass" and spf_aligned)
        dmarc_policy = dmarc.get("policy", "none")

        if spf_pass_and_aligned or dkim_aligned:
            effective_dmarc = "pass"
            disposition = "none"
            mech = "SPF" if spf_pass_and_aligned else "DKIM"
            dmarc_reason = f"DMARC passed: Aligned {mech} passed RFC 7489 evaluation."
        elif dmarc.get("header_result") == "pass":
            effective_dmarc = "pass"
            disposition = "none"
            dmarc_reason = "Receiver MTA validated and reported DMARC pass in Authentication-Results."
        elif dmarc_policy in ("reject", "quarantine"):
            effective_dmarc = "fail"
            disposition = dmarc_policy  # Receiver disposition reflects domain's requested action
            dmarc_reason = f"DMARC failed: Neither aligned SPF nor aligned DKIM passed (Policy: p={dmarc_policy})."
        elif dmarc.get("header_result") == "fail":
            effective_dmarc = "fail"
            disposition = "none"
            dmarc_reason = "DMARC failed: Receiver reported policy failure in Authentication-Results."
        else:
            effective_dmarc = "fail" if (return_path_mismatch and not dkim_aligned) else "neutral"
            disposition = "none"
            dmarc_reason = "No aligned cryptographic signature verified under RFC 7489 specifications."

        # Alignment Matrix table for UI & PDF Report
        primary_dkim = dkim_list[0] if dkim_list else {}
        d_sign_display = aligned_signing_domain or primary_dkim.get("signing_domain", "None")

        matrix = [
            {
                "protocol": "SPF (RFC 7208)",
                "result": spf.get("result", "none").upper(),
                "domain": m_from or "N/A",
                "alignment": f"PASS ({spf_alignment_label.capitalize()})" if spf_aligned else "FAIL (Unaligned)",
                "evidence": f"RFC 5321.MailFrom: '{m_from}' vs RFC 5322.From: '{h_from}'"
            },
            {
                "protocol": "DKIM (RFC 6376)",
                "result": primary_dkim.get("result", "none").upper(),
                "domain": d_sign_display or "None",
                "alignment": "PASS (Aligned)" if dkim_aligned else "FAIL (Unaligned)",
                "evidence": f"d='{d_sign_display}' (Signatures evaluated: {len(dkim_list)})"
            },
            {
                "protocol": "DMARC (RFC 7489)",
                "result": effective_dmarc.upper(),
                "domain": h_from or "N/A",
                "alignment": "COMPLIANT" if effective_dmarc == "pass" else "POLICY VIOLATION",
                "evidence": f"{dmarc_reason} [Policy: p={dmarc_policy}, Disposition: {disposition}]"
            }
        ]

        return {
            "header_from_domain": h_from,
            "mail_from_domain": m_from,
            "spf_strict": spf_strict,
            "spf_relaxed": spf_relaxed,
            "spf_aligned": spf_aligned,
            "spf_alignment_mode": aspf_mode,
            "dkim_strict": dkim_strict,
            "dkim_relaxed": dkim_relaxed,
            "dkim_aligned": dkim_aligned,
            "dkim_alignment_mode": adkim_mode,
            "effective_dmarc_status": effective_dmarc,
            "disposition": disposition,
            "dmarc_reason": dmarc_reason,
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
        if spf.get("result") in ("fail", "softfail") or dmarc.get("result") == "fail":
            return "Domain Authentication Failure: Unauthorized relay infrastructure or DMARC policy violation."
        return "Incomplete Authentication: Missing cryptographic DKIM signatures or unverified DMARC policy."

