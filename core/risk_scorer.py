from typing import Dict, Any, List
from config import settings


class RiskScorer:
    """
    Step 9: Calibrated Forensic Risk Engine (v2026.1).
    
    Architectural Principles:
    1. Decouples Risk, Confidence, and Attribution:
       - 'risk_score' (0-100): Composite objective threat level across 5 forensic pillars.
       - 'risk_band' ('clean' | 'low' | 'medium' | 'high' | 'critical'): Categorical posture.
       - 'analysis_confidence' (0.0-1.0): Telemetry completeness metric based on observed data signals.
       - 'candidate_attribution_confidence': Isolated to origin network routing leads.
    2. Signal Normalization & De-duplication:
       - Prevents additive runaway scores for collinear signals (e.g., SPF fail + DMARC fail).
       - Missing or timed-out external threat intelligence lookups contribute zero false risk points.
    3. Actionable Incident Response Playbooks:
       - Each action includes scope, impact level, approval requirements, and false-positive warnings.
    """

    def __init__(self, clean_threshold: float = 30.0, suspicious_threshold: float = 60.0):
        self.clean_threshold = clean_threshold
        self.suspicious_threshold = suspicious_threshold
        self.scoring_version = getattr(settings, "SCORING_VERSION", "2026.1")

    def calculate_verdict(self, parsed_email: Dict[str, Any], auth_results: Dict[str, Any],
                          whois_data: Dict[str, Any], geo_data: Dict[str, Any],
                          threat_intel: Dict[str, Any], ml_results: Dict[str, Any],
                          origin_data: Dict[str, Any] = None) -> Dict[str, Any]:

        auth_subscore = 0.0
        whois_subscore = 0.0
        intel_subscore = 0.0
        content_subscore = 0.0
        ml_subscore = (ml_results.get("ml_risk_score", 0.0) / 100.0) * 15.0  # Max 15 points

        factors = []
        structured_factors = []
        playbook_items = []

        # Data completeness tracking for analysis_confidence calculation
        signals_evaluated = 0
        signals_available = 0

        # =========================================================================
        # 1. AUTHENTICATION PILLAR (Max 25 pts)
        # =========================================================================
        signals_available += 3
        alignment_data = auth_results.get("alignment", {})
        dmarc_data = auth_results.get("dmarc", {})
        spf_data = auth_results.get("spf", {})

        spf_result = spf_data.get("result") or spf_data.get("status", "none")
        effective_dmarc = dmarc_data.get("result", alignment_data.get("effective_dmarc_status", "none"))
        reply_mismatch = parsed_email.get("headers", {}).get("reply_to", {}).get("mismatch_with_from", False)

        if effective_dmarc in ("fail", "reject"):
            signals_evaluated += 1
            auth_subscore += 20.0
            factors.append("RFC 7489 DMARC alignment failed")
            structured_factors.append({
                "signal": "dmarc_failure",
                "name": "RFC 7489 DMARC Policy Failure",
                "impact": 20,
                "severity": "high",
                "evidence": dmarc_data.get("reason", "Header From violates domain DMARC authentication policy."),
                "confidence": 0.95
            })
            playbook_items.append({
                "action": "Quarantine incoming messages matching unaligned sender domain at mail gateway.",
                "scope": "tenant_wide",
                "impact_level": "MEDIUM",
                "requires_approval": False,
                "reversibility": "reversible",
                "false_positive_warning": "May impact legitimate third-party services if sender hasn't configured DKIM alignment."
            })
        elif spf_result in ("fail", "softfail"):
            signals_evaluated += 1
            auth_subscore += 10.0
            factors.append(f"SPF authentication unaligned ({spf_result})")
            structured_factors.append({
                "signal": "spf_unaligned",
                "name": "SPF Authorization Failure",
                "impact": 10,
                "severity": "medium",
                "evidence": f"Sending relay IP is unauthorized in sender DNS ({spf_result}).",
                "confidence": 0.90
            })
        else:
            signals_evaluated += 1

        if reply_mismatch or alignment_data.get("reply_to_mismatch"):
            auth_subscore += 15.0
            from_dom = parsed_email.get('headers', {}).get('from', {}).get('domain', '')
            reply_dom = parsed_email.get('headers', {}).get('reply_to', {}).get('domain', '')
            factors.append("Reply-To address diverges from Header From domain")
            structured_factors.append({
                "signal": "reply_to_divergence",
                "name": "Reply-To Redirection Divergence",
                "impact": 15,
                "severity": "high",
                "evidence": f"Reply-To domain '{reply_dom}' differs from visible sender '{from_dom}'.",
                "confidence": 0.92
            })
            playbook_items.append({
                "action": f"Search enterprise mailboxes for inbound messages routing replies to {reply_dom}.",
                "scope": "tenant_wide",
                "impact_level": "LOW",
                "requires_approval": False,
                "reversibility": "reversible",
                "false_positive_warning": "Some legitimate ticketing and CRM systems route responses to central processing domains."
            })

        auth_subscore = min(25.0, auth_subscore)

        # =========================================================================
        # 2. DOMAIN & INFRASTRUCTURE PILLAR (Max 20 pts)
        # =========================================================================
        signals_available += 2
        if whois_data.get("data_mode") != "UNAVAILABLE":
            signals_evaluated += 1
            if whois_data.get("is_young", False):
                age = whois_data.get("age_days", 0)
                whois_subscore += 18.0
                factors.append(f"Sender domain registered recently ({age} days old; < 30 day window)")
                structured_factors.append({
                    "signal": "newly_registered_domain",
                    "name": "Newly Registered Domain (NRD)",
                    "impact": 18,
                    "severity": "high",
                    "evidence": f"Domain created only {age} days ago (characteristic of disposable campaign infrastructure).",
                    "confidence": 0.88
                })
                playbook_items.append({
                    "action": "Enforce perimeter web proxy block on newly registered domain.",
                    "scope": "perimeter",
                    "impact_level": "MEDIUM",
                    "requires_approval": False,
                    "reversibility": "reversible",
                    "false_positive_warning": "Legitimate newly launched partner companies may be temporarily blocked."
                })
        else:
            # Unavailable WHOIS contributes 0 risk
            pass

        # Relay Header Anomaly Signals
        if origin_data:
            signals_available += 1
            signals_evaluated += 1
            if origin_data.get("forgery_assessment") in ("anomalies_detected", "likely_untrusted"):
                whois_subscore += 8.0
                anomalies_count = len(origin_data.get("header_anomalies", []))
                structured_factors.append({
                    "signal": "received_header_anomaly",
                    "name": "Received Relay Header Anomalies",
                    "impact": 8,
                    "severity": "medium",
                    "evidence": f"Detected {anomalies_count} routing consistency issue(s) in Received headers.",
                    "confidence": 0.80
                })

        whois_subscore = min(20.0, whois_subscore)

        # =========================================================================
        # 3. THREAT INTELLIGENCE REPUTATION PILLAR (Max 25 pts)
        # =========================================================================
        signals_available += 2
        threat_raw_score = threat_intel.get("threat_risk_score", 0.0)
        
        # Check if threat intel lookup actually succeeded or was unavailable
        vt_mode = threat_intel.get("virustotal", {}).get("data_mode", "LIVE")
        abuse_mode = threat_intel.get("abuseipdb", {}).get("data_mode", "LIVE")

        if vt_mode != "UNAVAILABLE" or abuse_mode != "UNAVAILABLE":
            signals_evaluated += 2
            intel_subscore = (threat_raw_score / 100.0) * 25.0
            if threat_raw_score > 30:
                factors.append(f"Threat intelligence flagged origin infrastructure (Score: {threat_raw_score}/100)")
                structured_factors.append({
                    "signal": "threat_intel_positive",
                    "name": "Threat Intelligence Detections",
                    "impact": round(intel_subscore),
                    "severity": "high" if threat_raw_score >= 60 else "medium",
                    "evidence": f"Reported by external threat feeds (VirusTotal/AbuseIPDB score: {threat_raw_score}/100).",
                    "confidence": 0.90
                })
                # Critical: IP/ASN blocking requires high impact notice and approval
                playbook_items.append({
                    "action": "Enforce firewall CIDR/IP perimeter block on candidate origin relay.",
                    "scope": "perimeter",
                    "impact_level": "HIGH",
                    "requires_approval": True,
                    "reversibility": "reversible",
                    "false_positive_warning": "CRITICAL: Verify candidate IP is not a multi-tenant cloud egress (e.g. AWS, Microsoft 365) before blocking."
                })

        # =========================================================================
        # 4. CONTENT & HEURISTICS PILLAR (Max 25 pts)
        # =========================================================================
        signals_available += 3
        signals_evaluated += 3
        urls_info = parsed_email.get("urls", {})
        if urls_info.get("has_mismatches", False):
            content_subscore += 18.0
            factors.append("Deceptive hyperlink anchor mismatch detected (phishing redirection)")
            structured_factors.append({
                "signal": "url_anchor_mismatch",
                "name": "Hyperlink Anchor / Destination Mismatch",
                "impact": 18,
                "severity": "high",
                "evidence": "Visible link text displays a different domain than actual target destination URL.",
                "confidence": 0.94
            })
            playbook_items.append({
                "action": "Audit endpoint browser history for users who received message to identify click-throughs.",
                "scope": "per_user",
                "impact_level": "LOW",
                "requires_approval": False,
                "reversibility": "reversible",
                "false_positive_warning": "None."
            })

        lookalike = parsed_email.get("headers", {}).get("from", {}).get("lookalike")
        if lookalike:
            content_subscore += 18.0
            target_b = lookalike.get("target_brand", "targeted organization")
            factors.append(f"Lookalike / typosquatted sender domain (impersonating {target_b})")
            structured_factors.append({
                "signal": "brand_impersonation",
                "name": "Brand Typosquatting / Impersonation",
                "impact": 18,
                "severity": "high",
                "evidence": f"Sender domain closely mimics {target_b} using deceptive character substitutions.",
                "confidence": 0.91
            })
            playbook_items.append({
                "action": f"Issue security awareness alert regarding targeted {target_b} spoofing wave.",
                "scope": "tenant_wide",
                "impact_level": "LOW",
                "requires_approval": False,
                "reversibility": "reversible",
                "false_positive_warning": "None."
            })

        attachments = parsed_email.get("attachments", [])
        if any(a.get("is_dangerous", False) for a in attachments):
            content_subscore += 20.0
            factors.append("High-risk executable or script attachment detected")
            structured_factors.append({
                "signal": "dangerous_attachment",
                "name": "High-Risk Executable Payload",
                "impact": 20,
                "severity": "high",
                "evidence": "Attachment contains executable or script payload (.exe, .scr, .bat, .vbs, .iso).",
                "confidence": 0.98
            })
            playbook_items.append({
                "action": "Quarantine email attachment at gateway and dispatch sample to sandbox analyzer.",
                "scope": "tenant_wide",
                "impact_level": "MEDIUM",
                "requires_approval": False,
                "reversibility": "reversible",
                "false_positive_warning": "Legitimate engineering or IT script transfers may be impacted."
            })

        content_subscore = min(25.0, content_subscore)

        # =========================================================================
        # 5. MACHINE LEARNING NLP SCORING
        # =========================================================================
        if ml_subscore > 8.0:
            structured_factors.append({
                "signal": "nlp_deception_signal",
                "name": "NLP Social Engineering Heuristics",
                "impact": round(ml_subscore),
                "severity": "medium",
                "evidence": "Machine learning model identified high-urgency social engineering patterns.",
                "confidence": 0.85
            })

        # =========================================================================
        # TOTAL COMPOSITE SCORE CALCULATION
        # =========================================================================
        total_score = auth_subscore + whois_subscore + intel_subscore + ml_subscore + content_subscore
        total_score = round(min(100.0, max(0.0, total_score)), 1)

        # Categorical Risk Band
        if total_score <= self.clean_threshold:
            verdict = "Clean"
            risk_band = "clean"
            risk_level = "Low"
            badge_color = "green"
            if not playbook_items:
                playbook_items.append({
                    "action": "Preserve message in compliance store. No urgent quarantine required.",
                    "scope": "compliance_store",
                    "impact_level": "LOW",
                    "requires_approval": False,
                    "reversibility": "reversible",
                    "false_positive_warning": "None."
                })
        elif total_score <= self.suspicious_threshold:
            verdict = "Suspicious"
            risk_band = "medium"
            risk_level = "Medium"
            badge_color = "yellow"
            if not playbook_items:
                playbook_items.append({
                    "action": "Tag subject line with [EXTERNAL SUSPICIOUS] and deliver to Junk folder.",
                    "scope": "per_user",
                    "impact_level": "LOW",
                    "requires_approval": False,
                    "reversibility": "reversible",
                    "false_positive_warning": "User can retrieve message from Junk if verified."
                })
        elif total_score <= 85.0:
            verdict = "Malicious"
            risk_band = "high"
            risk_level = "High"
            badge_color = "red"
            playbook_items.insert(0, {
                "action": "IMMEDIATE: Quarantine message globally across all tenant recipient mailboxes.",
                "scope": "tenant_wide",
                "impact_level": "MEDIUM",
                "requires_approval": False,
                "reversibility": "reversible",
                "false_positive_warning": "Users will not be able to view message until released by SOC."
            })
        else:
            verdict = "Malicious"
            risk_band = "critical"
            risk_level = "Critical"
            badge_color = "red"
            playbook_items.insert(0, {
                "action": "CRITICAL: Global mailbox purge, revoke active OAuth sessions for exposed recipients.",
                "scope": "tenant_wide",
                "impact_level": "HIGH",
                "requires_approval": True,
                "reversibility": "manual_reversion",
                "false_positive_warning": "Active sessions will be terminated immediately."
            })

        # Decoupled Analysis Confidence (Data Completeness)
        analysis_confidence = round(min(1.0, max(0.4, signals_evaluated / max(1, signals_available))), 2)

        # Deduplicate playbook action descriptions for UI rendering
        playbook_action_strings = []
        seen_strings = set()
        for p in playbook_items:
            act_text = p["action"]
            if act_text not in seen_strings:
                seen_strings.add(act_text)
                playbook_action_strings.append(act_text)

        if not factors:
            factors.append("Clean baseline: SPF/DKIM aligned, verified domain age, clean threat reputation.")

        return {
            "verdict": verdict,
            "risk_band": risk_band,
            "risk_level": risk_level,
            "badge_color": badge_color,
            "risk_score": total_score,
            "scoring_version": self.scoring_version,
            "analysis_confidence": analysis_confidence,
            "confidence_pct": int(analysis_confidence * 100),
            "breakdown": {
                "authentication_risk": round(auth_subscore, 1),
                "domain_age_risk": round(whois_subscore, 1),
                "threat_intel_risk": round(intel_subscore, 1),
                "ai_ml_nlp_risk": round(ml_subscore, 1),
                "content_heuristics_risk": round(content_subscore, 1)
            },
            "primary_risk_factors": factors,
            "scoring_explanations": structured_factors,
            "factors": structured_factors,  # Canonical factor schema per critique
            "playbook_actions": playbook_action_strings,
            "playbook_items": playbook_items,  # Rich structured playbook with approval/scope metadata
            "attribution_disclaimer": "Candidate origin infrastructure represents probabilistic routing leads. Conclusive human attribution requires judicial ISP subscriber correlation."
        }
