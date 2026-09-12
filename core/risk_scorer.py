from typing import Dict, Any

class RiskScorer:
    """
    Step 9: Weighted Risk Engine.
    Combines authentication checks, WHOIS domain age, IP geolocation,
    multi-source threat intel, ML classifier output, and forensic heuristics.
    Returns composite score (0-100), Verdict (Clean / Suspicious / Malicious),
    and confidence percentage.
    """

    def __init__(self, clean_threshold: float = 30.0, suspicious_threshold: float = 70.0):
        self.clean_threshold = clean_threshold
        self.suspicious_threshold = suspicious_threshold

    def calculate_verdict(self, parsed_email: Dict[str, Any], auth_results: Dict[str, Any],
                          whois_data: Dict[str, Any], geo_data: Dict[str, Any],
                          threat_intel: Dict[str, Any], ml_results: Dict[str, Any]) -> Dict[str, Any]:

        auth_subscore = 0.0
        whois_subscore = 0.0
        intel_subscore = 0.0
        content_subscore = 0.0
        ml_subscore = (ml_results.get("ml_risk_score", 0.0) / 100.0) * 20.0  # Max 20 points

        factors = []

        # 1. Authentication Pillar (Max 25 pts)
        spf_status = auth_results.get("spf", {}).get("status")
        dkim_status = auth_results.get("dkim", {}).get("status")
        dmarc_status = auth_results.get("dmarc", {}).get("status")
        reply_mismatch = parsed_email.get("headers", {}).get("reply_to", {}).get("mismatch_with_from", False)

        if spf_status in ("fail", "softfail"):
            auth_subscore += 15.0
            factors.append(f"SPF authentication failed ({spf_status})")
        if dmarc_status == "fail":
            auth_subscore += 10.0
            factors.append("DMARC verification failed")
        if dkim_status in ("none", "fail"):
            auth_subscore += 5.0
        if reply_mismatch:
            auth_subscore += 10.0
            factors.append("Reply-To address differs from Sender (potential fraud redirect)")
        auth_subscore = min(25.0, auth_subscore)

        # 2. WHOIS & Domain Age Pillar (Max 20 pts)
        if whois_data.get("is_young", False):
            whois_subscore += 20.0
            factors.append(f"Sender domain is brand new ({whois_data.get('age_days', 0)} days old)")
        elif whois_data.get("status") == "error":
            whois_subscore += 5.0
        whois_subscore = min(20.0, whois_subscore)

        # 3. Threat Intel Pillar (Max 25 pts)
        threat_raw_score = threat_intel.get("threat_risk_score", 0.0)
        intel_subscore = (threat_raw_score / 100.0) * 25.0
        if threat_raw_score > 30:
            factors.append(f"Threat intelligence flagged origin IP or URLs (Threat Score: {threat_raw_score}/100)")

        # 4. Content & Forensics Heuristics (Max 25 pts)
        urls_info = parsed_email.get("urls", {})
        if urls_info.get("has_mismatches", False):
            content_subscore += 15.0
            factors.append("Deceptive hyperlink anchor mismatch detected (phishing redirection)")

        if urls_info.get("has_shortened_urls", False):
            content_subscore += 10.0
            factors.append(f"Suspicious URL shortener detected ({len(urls_info.get('shortened_urls', []))} shortened link(s))")

        lookalike = parsed_email.get("headers", {}).get("from", {}).get("lookalike")
        if lookalike:
            content_subscore += 20.0
            target_b = lookalike.get("target_brand", "known brand")
            factors.append(f"Lookalike / spoofed sender domain detected (impersonating {target_b})")

        attachments = parsed_email.get("attachments", [])
        if any(a.get("is_dangerous", False) for a in attachments):
            content_subscore += 20.0
            factors.append("High-risk executable/script attachment detected (.exe, .scr, .bat, .js)")
        content_subscore = min(25.0, content_subscore)

        # Total Composite Score (0 to 100)
        total_score = auth_subscore + whois_subscore + intel_subscore + ml_subscore + content_subscore
        total_score = round(min(100.0, max(0.0, total_score)), 1)

        # Determine Verdict & Risk Level (Low 0-30, Medium 31-60, High 61-100)
        if total_score <= 30.0:
            verdict = "Clean"
            risk_level = "Low"
            badge_color = "green"
            confidence = round(100.0 - total_score, 1)
        elif total_score <= 60.0:
            verdict = "Suspicious"
            risk_level = "Medium"
            badge_color = "yellow"
            confidence = round(total_score, 1)
        else:
            verdict = "Malicious"
            risk_level = "High"
            badge_color = "red"
            confidence = round(total_score, 1)

        if not factors:
            factors.append("Email exhibits clean indicators across authentication, domain age, and content.")

        return {
            "verdict": verdict,
            "risk_level": risk_level,
            "badge_color": badge_color,
            "risk_score": total_score,
            "confidence_pct": confidence,
            "breakdown": {
                "authentication_risk": round(auth_subscore, 1),
                "domain_age_risk": round(whois_subscore, 1),
                "threat_intel_risk": round(intel_subscore, 1),
                "ai_ml_nlp_risk": round(ml_subscore, 1),
                "content_heuristics_risk": round(content_subscore, 1)
            },
            "primary_risk_factors": factors
        }
