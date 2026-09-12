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
        scoring_explanations = []
        playbook_actions = []

        # 1. Authentication Pillar (Max 25 pts)
        alignment_data = auth_results.get("alignment", {})
        spf_status = auth_results.get("spf", {}).get("status", "none")
        dkim_status = auth_results.get("dkim", {}).get("status", "none")
        dmarc_status = auth_results.get("dmarc", {}).get("status", "none")
        effective_dmarc = alignment_data.get("effective_dmarc_status", dmarc_status)
        reply_mismatch = parsed_email.get("headers", {}).get("reply_to", {}).get("mismatch_with_from", False)

        if effective_dmarc in ("fail", "reject"):
            auth_subscore += 20.0
            factors.append("RFC 7489 DMARC alignment validation failed")
            scoring_explanations.append({
                "signal": "DMARC Policy Failure",
                "impact": 20,
                "severity": "high",
                "evidence": alignment_data.get("dmarc_reason", "Header From violates domain DMARC authentication policy.")
            })
            playbook_actions.append("Block or quarantine incoming messages from unauthenticated sender domain.")
        elif spf_status in ("fail", "softfail"):
            auth_subscore += 12.0
            factors.append(f"SPF authentication failed ({spf_status})")
            scoring_explanations.append({
                "signal": "SPF Authorization Failure",
                "impact": 12,
                "severity": "medium",
                "evidence": f"Sending relay IP is unauthorized in sender DNS ({spf_status})."
            })

        if reply_mismatch or alignment_data.get("reply_to_mismatch"):
            auth_subscore += 15.0
            factors.append("Reply-To address diverges from Header From domain (potential credential/wire redirection)")
            scoring_explanations.append({
                "signal": "Reply-To Redirection Mismatch",
                "impact": 15,
                "severity": "high",
                "evidence": f"Reply-To domain differs from visible sender {parsed_email.get('headers', {}).get('from', {}).get('domain', '')}."
            })
            playbook_actions.append("Search enterprise mailbox gateways for matching fraudulent Reply-To addresses.")

        auth_subscore = min(25.0, auth_subscore)

        # 2. Domain & Infrastructure Pillar (Max 20 pts)
        if whois_data.get("is_young", False):
            whois_subscore += 18.0
            age = whois_data.get("age_days", 0)
            factors.append(f"Sender domain registered recently ({age} days old; < 30 day threat window)")
            scoring_explanations.append({
                "signal": "Newly Registered Domain (NRD)",
                "impact": 18,
                "severity": "high",
                "evidence": f"Domain created only {age} days ago (typical of disposable phishing infrastructure)."
            })
            playbook_actions.append("Add domain to perimeter proxy / web-filter zero-trust blocklist.")
        elif whois_data.get("status") == "error":
            whois_subscore += 4.0

        whois_subscore = min(20.0, whois_subscore)

        # 3. Threat Intelligence Reputation Pillar (Max 25 pts)
        threat_raw_score = threat_intel.get("threat_risk_score", 0.0)
        intel_subscore = (threat_raw_score / 100.0) * 25.0
        if threat_raw_score > 30:
            factors.append(f"Threat intelligence flagged origin IP or URLs (Threat Score: {threat_raw_score}/100)")
            scoring_explanations.append({
                "signal": "Global Threat Intel Detections",
                "impact": round(intel_subscore),
                "severity": "high" if threat_raw_score >= 60 else "medium",
                "evidence": f"Corroborated by external intelligence feeds (AbuseIPDB / OTX / VirusTotal)."
            })
            playbook_actions.append("Enforce perimeter firewall block on flagged origin IP and infrastructure.")

        # 4. Content, Heuristics & Brand Impersonation Pillar (Max 25 pts)
        urls_info = parsed_email.get("urls", {})
        if urls_info.get("has_mismatches", False):
            content_subscore += 20.0
            factors.append("Deceptive hyperlink anchor mismatch detected (phishing redirection)")
            scoring_explanations.append({
                "signal": "Anchor / Destination URL Mismatch",
                "impact": 20,
                "severity": "high",
                "evidence": "Displayed text link diverges from actual hyperlinked destination URL."
            })
            playbook_actions.append("Revoke active user sessions for any employees who clicked the disguised link.")

        if urls_info.get("has_shortened_urls", False):
            content_subscore += 8.0
            factors.append(f"URL shortener detected ({len(urls_info.get('shortened_urls', []))} link(s))")
            scoring_explanations.append({
                "signal": "Obfuscated URL Shortener",
                "impact": 8,
                "severity": "low",
                "evidence": "Shortened redirect link masking final target destination."
            })

        lookalike = parsed_email.get("headers", {}).get("from", {}).get("lookalike")
        if lookalike:
            content_subscore += 20.0
            target_b = lookalike.get("target_brand", "targeted organization")
            factors.append(f"Lookalike / typosquatted sender domain detected (impersonating {target_b})")
            scoring_explanations.append({
                "signal": "Brand Typosquatting / Impersonation",
                "impact": 20,
                "severity": "high",
                "evidence": f"Sender domain closely resembles {target_b} using deceptive character substitutions."
            })
            playbook_actions.append(f"Issue internal warning alert regarding targeted {target_b} spoofing wave.")

        attachments = parsed_email.get("attachments", [])
        if any(a.get("is_dangerous", False) for a in attachments):
            content_subscore += 20.0
            factors.append("High-risk executable/script attachment detected (.exe, .scr, .bat, .js)")
            scoring_explanations.append({
                "signal": "Dangerous Executable Attachment",
                "impact": 20,
                "severity": "high",
                "evidence": "Attachment contains executable or scripting payload capable of remote execution."
            })
            playbook_actions.append("Quarantine attachment across mail gateway; submit sample to EDR sandbox.")

        content_subscore = min(25.0, content_subscore)

        # 5. Machine Learning NLP Scoring
        if ml_subscore > 10.0:
            scoring_explanations.append({
                "signal": "NLP Deception & Urgency Heuristics",
                "impact": round(ml_subscore),
                "severity": "medium",
                "evidence": f"NLP model identified linguistic patterns typical of credential harvesting / BEC."
            })

        # Total Composite Score (0 to 100)
        total_score = auth_subscore + whois_subscore + intel_subscore + ml_subscore + content_subscore
        total_score = round(min(100.0, max(0.0, total_score)), 1)

        # Determine Verdict & Risk Level (Low 0-30, Medium 31-60, High 61-100)
        if total_score <= self.clean_threshold:
            verdict = "Clean"
            risk_level = "Low"
            badge_color = "green"
            confidence = round(100.0 - total_score, 1)
            playbook_actions = ["Preserve message in compliance archive.", "No active containment required."]
        elif total_score <= self.suspicious_threshold:
            verdict = "Suspicious"
            risk_level = "Medium"
            badge_color = "yellow"
            confidence = round(total_score, 1)
            if not playbook_actions:
                playbook_actions = ["Deliver message to recipient Quarantine/Junk folder.", "Warn user not to enter passwords."]
        else:
            verdict = "Malicious"
            risk_level = "High"
            badge_color = "red"
            confidence = round(total_score, 1)
            playbook_actions.insert(0, "IMMEDIATE ACTION: Quarantine message globally across all recipient inboxes.")
            playbook_actions.append("Trigger automated IOC hunting in SIEM/EDR for origin infrastructure.")

        if not factors:
            factors.append("Email exhibits clean indicators across authentication, domain age, and content.")

        # Deduplicate playbook actions preserving order
        seen_actions = set()
        clean_playbook = []
        for act in playbook_actions:
            if act not in seen_actions:
                seen_actions.add(act)
                clean_playbook.append(act)

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
            "primary_risk_factors": factors,
            "scoring_explanations": scoring_explanations,
            "playbook_actions": clean_playbook,
            "attribution_disclaimer": "Geolocation and origin indicators are probabilistic leads; physical actor identity cannot be solely inferred from network routing."
        }
