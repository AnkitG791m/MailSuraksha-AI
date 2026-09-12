import re
from typing import Dict, Any, List, Optional

URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate", "action required", "account suspended",
    "within 24 hours", "terminate", "verify password", "unauthorized login",
    "wire transfer", "confidential", "critical security alert", "expires today",
    "direct deposit", "unclaimed refund", "security advisory alert", "act now",
    "click here urgently", "security team", "it helpdesk"
]

TARGETED_BRANDS = [
    "microsoft", "office", "365", "outlook", "google", "paypal", "apple",
    "amazon", "chase", "bank of america", "wells fargo", "dhl", "fedex",
    "dropbox", "netflix", "meta", "facebook", "executive", "ceo", "cfo",
    "it support", "payroll department"
]


class LocalAnalyzer:
    """
    Layer 1: Local Threat Analysis Engine.
    Executes entirely offline without external API calls:
    - SPF / DKIM / DMARC authentication status
    - Header anomaly & Return-Path verification
    - Reply-To mismatch detection
    - Display name spoofing detection (e.g. Display says 'Microsoft Security' but domain is not microsoft.com)
    - Urgency & pressure keyword detection
    - URL analysis (anchor mismatch, URL shorteners, lookalike/typosquatting domains)
    - Risky attachment analysis (.exe, .scr, .bat, .js, etc.)
    Generates a localized risk score from 0 to 100.
    """

    def __init__(self):
        pass

    def analyze(self, parsed_email: Dict[str, Any], auth_results: Dict[str, Any]) -> Dict[str, Any]:
        score = 0.0
        triggered_rules = []
        rule_breakdown = {}

        headers = parsed_email.get("headers", {})
        from_data = headers.get("from", {})
        from_name = from_data.get("name", "").lower()
        from_email = from_data.get("email", "").lower()
        from_domain = from_data.get("domain", "").lower()

        # 1. SPF / DKIM / DMARC Authentication Checks
        auth_score = 0.0
        spf_status = auth_results.get("spf", {}).get("status", "none")
        dkim_status = auth_results.get("dkim", {}).get("status", "none")
        dmarc_status = auth_results.get("dmarc", {}).get("status", "none")

        if spf_status in ("fail", "softfail"):
            auth_score += 25.0
            triggered_rules.append(f"SPF authentication failed ({spf_status})")
        elif spf_status in ("none", "neutral"):
            auth_score += 8.0

        if dmarc_status == "fail":
            auth_score += 20.0
            triggered_rules.append("DMARC domain policy validation failed")

        if dkim_status in ("fail", "none"):
            auth_score += 10.0
        auth_score = min(35.0, auth_score)
        rule_breakdown["authentication"] = auth_score
        score += auth_score

        # 2. Display Name Spoofing Detection
        display_name_spoofed = False
        if from_name:
            for brand in TARGETED_BRANDS:
                if brand in from_name and brand not in from_domain:
                    display_name_spoofed = True
                    triggered_rules.append(f"Display Name Spoofing: claims '{brand.title()}' but domain is '{from_domain}'")
                    score += 25.0
                    rule_breakdown["display_name_spoofing"] = 25.0
                    break

        # 3. Reply-To & Return-Path Mismatches
        mismatch_score = 0.0
        reply_to = headers.get("reply_to", {})
        if reply_to.get("mismatch_with_from"):
            mismatch_score += 20.0
            triggered_rules.append(f"Reply-To mismatch: responses redirected to '{reply_to.get('email')}'")

        return_path = headers.get("return_path", {})
        if return_path.get("mismatch_with_from"):
            mismatch_score += 10.0
            triggered_rules.append("Return-Path bounce domain differs from Sender domain")

        mismatch_score = min(25.0, mismatch_score)
        rule_breakdown["header_anomalies"] = mismatch_score
        score += mismatch_score

        # 4. Lookalike / Typosquatting Domain Detection
        lookalike = from_data.get("lookalike")
        if lookalike:
            target_b = lookalike.get("target_brand", "protected brand")
            score += 30.0
            rule_breakdown["lookalike_domain"] = 30.0
            triggered_rules.append(f"Lookalike Typosquatting: '{from_domain}' impersonates '{target_b}'")

        # 5. URL Analysis (Mismatches & Shorteners)
        urls_data = parsed_email.get("urls", {})
        url_score = 0.0
        if urls_data.get("has_mismatches"):
            url_score += 25.0
            count_m = len(urls_data.get("mismatched_links", []))
            triggered_rules.append(f"Deceptive hyperlink target: {count_m} link(s) hide true destination")

        if urls_data.get("has_shortened_urls"):
            url_score += 15.0
            count_s = len(urls_data.get("shortened_urls", []))
            triggered_rules.append(f"Suspicious URL shortener detected ({count_s} link(s))")

        url_score = min(30.0, url_score)
        rule_breakdown["url_analysis"] = url_score
        score += url_score

        # 6. Urgency Keywords Analysis
        subject = headers.get("subject", "")
        body_text = parsed_email.get("body", {}).get("text", "")
        combined_text = f"{subject} {body_text}".lower()

        found_keywords = [kw for kw in URGENCY_KEYWORDS if kw in combined_text]
        if found_keywords:
            kw_score = min(20.0, len(found_keywords) * 8.0)
            score += kw_score
            rule_breakdown["urgency_keywords"] = kw_score
            triggered_rules.append(f"High urgency phrasing detected: '{', '.join(found_keywords[:3])}'")

        # 7. Attachment Risk Analysis
        attachments = parsed_email.get("attachments", [])
        dangerous_atts = [a for a in attachments if a.get("is_dangerous")]
        if dangerous_atts:
            score += 35.0
            rule_breakdown["dangerous_attachments"] = 35.0
            exts = list(set([a.get("extension") for a in dangerous_atts]))
            triggered_rules.append(f"Dangerous attachment extensions: {', '.join(exts)}")

        # Normalize score to 0 - 100
        final_local_score = round(min(100.0, max(0.0, score)), 1)

        # Classification
        if final_local_score < 50.0:
            classification = "Low"
            action_recommendation = "Low Risk - External APIs Skipped"
        elif final_local_score <= 70.0:
            classification = "Medium"
            action_recommendation = "Medium Risk - Local Cache & Selective Enrichment"
        else:
            classification = "High"
            action_recommendation = "High Risk - Full External Enrichment Triggered"

        return {
            "local_risk_score": final_local_score,
            "classification": classification,
            "action_recommendation": action_recommendation,
            "display_name_spoofed": display_name_spoofed,
            "triggered_rules": triggered_rules,
            "rule_breakdown": rule_breakdown,
            "urgency_keywords": found_keywords,
            "dangerous_attachments_count": len(dangerous_atts)
        }

local_analyzer = LocalAnalyzer()
