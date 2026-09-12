import logging
from typing import Dict, Any, List, Optional
from core.llm_client import llm_client
from core.prompts import AI_ANALYSIS_SYSTEM_PROMPT, build_analysis_prompt

logger = logging.getLogger("securex.ai")

VALID_CLASSIFICATIONS = [
    "Legitimate",
    "Suspicious",
    "Phishing",
    "Business Email Compromise (BEC)",
    "Credential Harvesting",
    "Invoice Fraud",
    "Executive Impersonation",
    "Malware Delivery",
    "Financial Fraud"
]

class AIIntelligenceEngine:
    """
    SecureX AI Intelligence Layer.
    Consumes outputs of deterministic modules:
    - SPF / DKIM / DMARC
    - WHOIS & Domain Age
    - GeoLocation & Infrastructure
    - Threat Intelligence (VT, AbuseIPDB, OTX)
    - Heuristics (Lookalikes, Deceptive Links, Urgency)
    - Threat Memory Correlations
    
    Generates:
    - Feature 1: Threat Classification (with Confidence Score)
    - Feature 2: Threat Explanation
    - Feature 3: Recommendation Engine
    - Feature 4: Executive Summary (<= 150 words)
    - Feature 5: Campaign Correlation Assistant
    - Feature 6: User-Friendly Translation
    """

    def __init__(self):
        self.client = llm_client

    def analyze_email(
        self,
        headers: Dict[str, Any],
        auth: Dict[str, Any],
        whois: Dict[str, Any],
        geo: Dict[str, Any],
        threat_intel: Dict[str, Any],
        local_score: float,
        risk_verdict: Dict[str, Any],
        threat_memory: Dict[str, Any],
        body_text: str,
        urls: Dict[str, Any],
        attachments: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        user_prompt = build_analysis_prompt(
            headers=headers,
            auth=auth,
            whois=whois,
            geo=geo,
            threat_intel=threat_intel,
            local_score=local_score,
            risk_verdict=risk_verdict,
            threat_memory=threat_memory,
            body_text=body_text,
            urls=urls,
            attachments=attachments
        )

        raw_json, telemetry = self.client.generate(
            system_prompt=AI_ANALYSIS_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            expect_json=True
        )

        # Normalize and validate outputs
        classification = raw_json.get("classification")
        if classification not in VALID_CLASSIFICATIONS:
            # Map or default based on verdict
            verdict = risk_verdict.get("verdict", "Clean")
            if verdict == "Malicious":
                classification = "Phishing"
            elif verdict == "Suspicious":
                classification = "Suspicious"
            else:
                classification = "Legitimate"

        conf_score = raw_json.get("confidence_score")
        try:
            conf_score = int(float(conf_score))
            conf_score = max(0, min(100, conf_score))
        except (ValueError, TypeError):
            conf_score = int(risk_verdict.get("confidence_pct", 85))

        threat_explanation = raw_json.get("threat_explanation") or "Automated forensic inspection completed across authentication, origin IP, and content signals."
        recommendations = raw_json.get("recommendations") or [
            "Do not click untrusted links or open unexpected attachments.",
            "Verify sender credentials via secondary channels.",
            "Report suspicious activity to your security operations team."
        ]
        if not isinstance(recommendations, list):
            recommendations = [str(recommendations)]

        exec_summary = raw_json.get("executive_summary") or "Forensic evaluation concluded with no anomalous high-risk indicators detected."
        # Ensure <= 150 words constraint
        words = exec_summary.split()
        if len(words) > 150:
            exec_summary = " ".join(words[:147]) + "..."

        campaign_correlation = raw_json.get("campaign_correlation") or {
            "possible_campaign_relation": threat_memory.get("detected_campaign", "Isolated Attack"),
            "similarity_score": 75 if threat_memory.get("has_correlation") else 0,
            "reasoning": "Correlated based on threat memory historical attack patterns." if threat_memory.get("has_correlation") else "No recurring campaign links identified."
        }

        user_friendly_translation = raw_json.get("user_friendly_translation") or (
            "This email appears safe to open. Its sending source is verified and no harmful elements were detected."
            if risk_verdict.get("verdict") == "Clean" else
            "Warning: This email is suspicious and may be attempting to deceive you. Do not click links or send information."
        )

        return {
            "classification": classification,
            "confidence_score": conf_score,
            "threat_explanation": threat_explanation,
            "recommendations": recommendations,
            "executive_summary": exec_summary,
            "campaign_correlation": campaign_correlation,
            "user_friendly_translation": user_friendly_translation,
            "telemetry": telemetry
        }

ai_engine = AIIntelligenceEngine()
