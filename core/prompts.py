import re
from typing import Dict, Any, List, Optional

# --- PII & Sensitive Information Sanitizer ---

CREDIT_CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
PHONE_REGEX = re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
PASSWORD_REGEX = re.compile(r'(?i)(?:password|passwd|pwd|secret|passphrase)\s*[:=]\s*([^\s,;]+)')
BEARER_TOKEN_REGEX = re.compile(r'(?i)(?:bearer\s+|token\s*[:=]\s*|api[_-]?key\s*[:=]\s*)([a-zA-Z0-9_\-\.]{16,})')


def sanitize_email_content(text: str, max_chars: int = 3000) -> str:
    """
    Sanitizes and masks potential sensitive PII / secrets before transmitting to LLM.
    Truncates content to max_chars to optimize latency and token budgeting.
    """
    if not text:
        return ""

    sanitized = text
    # Mask secrets
    sanitized = PASSWORD_REGEX.sub(r'password: [REDACTED_PASSWORD]', sanitized)
    sanitized = BEARER_TOKEN_REGEX.sub(r'token: [REDACTED_TOKEN]', sanitized)
    # Mask financial / personal PII
    sanitized = CREDIT_CARD_REGEX.sub('[REDACTED_CARD_NUMBER]', sanitized)
    sanitized = SSN_REGEX.sub('[REDACTED_SSN]', sanitized)
    sanitized = PHONE_REGEX.sub('[REDACTED_PHONE]', sanitized)

    # Truncate
    if len(sanitized) > max_chars:
        sanitized = sanitized[:max_chars] + "\n...[CONTENT TRUNCATED FOR FORENSIC PRIVACY]..."

    return sanitized


# --- System & User Prompts ---

AI_ANALYSIS_SYSTEM_PROMPT = """You are the AI Forensic Intelligence Core of MailGuardian AI, an enterprise email threat detection and forensic intelligence platform.
Your role is to consume multi-layer forensic signals (SPF, DKIM, DMARC, WHOIS, Geolocation, Threat Intelligence, Heuristics, Threat Memory) and generate intelligent, human-readable forensic insights.

CRITICAL RULES:
1. You MUST NOT replace or overturn deterministic security checks. The rule-based findings are established ground truth.
2. Provide deep, accurate, and professional cybersecurity reasoning.
3. You must output strictly valid JSON matching the requested schema. Do not enclose in markdown ticks if possible, or use standard ```json blocks.
4. Output MUST contain:
   - "classification": One of ["Legitimate", "Suspicious", "Phishing", "Business Email Compromise (BEC)", "Credential Harvesting", "Invoice Fraud", "Executive Impersonation", "Malware Delivery", "Financial Fraud"]
   - "confidence_score": Integer (0 to 100)
   - "threat_explanation": A thorough forensic explanation of why this email is classified as such, contextualizing auth failures, deceptive links, and IOC reputations.
   - "recommendations": An array of 4 to 6 actionable, priority-ordered security recommendations.
   - "executive_summary": A concise forensic executive summary strictly 150 words or fewer, written for Security Analysts and CISO leadership.
   - "campaign_correlation": An object with:
       - "possible_campaign_relation": Name/theme of potential campaign or "Isolated Attack"
       - "similarity_score": Integer (0 to 100)
       - "reasoning": Explanation linking current indicators to historical threat memory patterns.
   - "user_friendly_translation": A plain-language translation (1-2 paragraphs) for non-technical employees explaining the risk without jargon.
"""


def build_analysis_prompt(
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
) -> str:
    sanitized_body = sanitize_email_content(body_text, max_chars=2500)

    auth = auth or {}
    whois = whois or {}
    geo = geo or {}
    threat_intel = threat_intel or {}
    risk_verdict = risk_verdict or {}
    threat_memory = threat_memory or {}
    urls = urls if isinstance(urls, dict) else {}
    attachments = attachments if isinstance(attachments, list) else []

    # Summarize auth
    spf_dict = auth.get("spf") or {}
    dkim_dict = auth.get("dkim") or {}
    dmarc_dict = auth.get("dmarc") or {}
    spf_stat = spf_dict.get("status", "unknown")
    dkim_stat = dkim_dict.get("status", "unknown")
    dmarc_stat = dmarc_dict.get("status", "unknown")

    # Summarize geo
    origin_ip = geo.get("query_ip") or "Unknown"
    country = geo.get("country", "Unknown")
    city = geo.get("city", "Unknown")
    isp = geo.get("isp", "Unknown")

    # Summarize whois
    age_days = whois.get("age_days")
    is_young = whois.get("is_young", False)

    # Threat intel
    ip_intel = threat_intel.get("origin_ip_intel") or {}
    vt = ip_intel.get("virustotal") or {}
    abuse = ip_intel.get("abuseipdb") or {}
    otx = ip_intel.get("alienvault") or {}

    # Links & attachments
    mismatched_links = urls.get("mismatched_links", [])
    shortened_urls = urls.get("shortened_urls", [])
    dangerous_atts = [a for a in attachments if isinstance(a, dict) and a.get("is_dangerous")]

    prompt_lines = [
        "EVIDENCE DATA FOR EMAIL INVESTIGATION:",
        "",
        "[HEADERS]",
        f"- Subject: {headers.get('subject', 'N/A')}",
        f"- From: {(headers.get('from') or {}).get('raw', 'N/A')}",
        f"- From Domain: {(headers.get('from') or {}).get('domain', 'N/A')}",
        f"- Lookalike Alert: {(headers.get('from') or {}).get('lookalike')}",
        f"- Reply-To: {(headers.get('reply_to') or {}).get('raw', 'N/A')} (Mismatch: {(headers.get('reply_to') or {}).get('mismatch_with_from', False)})",
        f"- Return-Path: {(headers.get('return_path') or {}).get('raw', 'N/A')} (Mismatch: {(headers.get('return_path') or {}).get('mismatch_with_from', False)})",
        f"- Message-ID: {headers.get('message_id', 'N/A')}",
        "",
        "[AUTHENTICATION]",
        f"- SPF: {spf_stat} ({spf_dict.get('details', '')})",
        f"- DKIM: {dkim_stat} ({dkim_dict.get('details', '')})",
        f"- DMARC: {dmarc_stat} ({dmarc_dict.get('details', '')})",
        "",
        "[ORIGIN INFRASTRUCTURE & GEO]",
        f"- Origin IP: {origin_ip}",
        f"- Location: {city}, {country}",
        f"- ISP / ASN: {isp} ({geo.get('as_number', '')})",
        "",
        "[WHOIS DOMAIN METRICS]",
        f"- Domain Age: {age_days} days (Younger than 30 days: {is_young})",
        f"- Registrar: {whois.get('registrar', 'Unknown')}",
        "",
        "[THREAT INTELLIGENCE REPUTATION]",
        f"- VirusTotal Detections: {vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious (Reputation: {vt.get('reputation', 0)})",
        f"- AbuseIPDB Confidence: {abuse.get('abuse_score', 0)}% (Total Reports: {abuse.get('total_reports', 0)}, Whitelisted: {abuse.get('is_whitelisted', False)})",
        f"- AlienVault OTX: {otx.get('pulse_count', 0)} pulses, Tags: {', '.join(otx.get('tags', []))}",
        "",
        "[CONTENT & FORENSIC HEURISTICS]",
        f"- Deceptive Anchor/Href Link Mismatches: {len(mismatched_links)} detected",
        f"- URL Shorteners: {len(shortened_urls)} detected",
        f"- Dangerous Attachments: {[a.get('filename') for a in dangerous_atts]}",
        f"- Deterministic Local Risk Score: {local_score} / 100",
        f"- Deterministic Final Verdict: {risk_verdict.get('verdict', 'Unknown')} (Score: {risk_verdict.get('risk_score', 0)}/100, Confidence: {risk_verdict.get('confidence_pct', 0)}%)",
        f"- Primary Risk Factors: {risk_verdict.get('primary_risk_factors', [])}",
        "",
        "[HISTORICAL THREAT MEMORY MATCHES]",
        f"- Correlated Incident: {threat_memory.get('has_correlation', False)}",
        f"- Historical IP Incidents: {threat_memory.get('ip_incident_count', 0)}",
        f"- Historical Domain Incidents: {threat_memory.get('domain_incident_count', 0)}",
        f"- Detected Historical Campaign: {threat_memory.get('detected_campaign', 'None')}",
        f"- Threat Memory Insights: {threat_memory.get('insights', [])}",
        "",
        "[EMAIL BODY SNIPPET (SANITIZED)]",
        sanitized_body,
        "",
        "Produce your complete forensic intelligence response in the exact JSON format specified."
    ]
    return "\n".join(prompt_lines)


# --- Investigation Assistant Chatbot Prompts ---

CHAT_SYSTEM_PROMPT = """You are the MailGuardian AI Senior Incident Responder & Threat Hunting Assistant.
You are assisting a security analyst or enterprise user investigating a specific analyzed email.

You have access to the complete forensic evidence and investigation findings for this email.
Rules for your answers:
1. Always ground your explanation in the actual facts, headers, IP addresses, domains, and authentication results of this specific analyzed email.
2. Be direct, authoritative, and helpful.
3. If asked technical questions (e.g. 'What is SPF failure?' or 'What is DMARC?'), explain what the technology is AND specifically why it failed or succeeded in this particular email.
4. If asked what to do, provide concise operational playbooks (e.g. sender blacklisting, password resets, perimeter firewall blocks, user alerts).
5. Language instructions: If the user asks in Hindi or Hinglish (e.g. using words like 'kyu', 'batao', 'samjh', 'kya', 'kaise', 'fraud'), reply in natural, fluent, professional cyber-analyst Hinglish!
6. At the end of your answer, supply 2 or 3 relevant suggested follow-up questions formatted as:
[SUGGESTED_QUESTIONS]
- Question 1?
- Question 2?
- Question 3?
"""


def build_chat_user_prompt(
    user_query: str,
    analysis_record: Dict[str, Any],
    chat_history: Optional[List[Dict[str, str]]] = None
) -> str:
    headers = analysis_record.get("headers", {})
    auth = analysis_record.get("auth", {})
    risk = analysis_record.get("risk", {})
    geo = analysis_record.get("geo", {})
    ai = analysis_record.get("ai_insights", {})

    lines = [
        "INVESTIGATION EVIDENCE CONTEXT:",
        f"- Case Report ID: {analysis_record.get('report_id', 'N/A')}",
        f"- Subject: {headers.get('subject', 'N/A')}",
        f"- From: {headers.get('from', {}).get('raw', 'N/A')}",
        f"- Origin IP: {analysis_record.get('origin_ip', {}).get('origin_ip', 'N/A')} ({geo.get('city', '')}, {geo.get('country', '')} - ISP: {geo.get('isp', '')})",
        f"- Auth: SPF={auth.get('spf', {}).get('status')}, DKIM={auth.get('dkim', {}).get('status')}, DMARC={auth.get('dmarc', {}).get('status')}",
        f"- Risk Verdict: {risk.get('verdict')} (Score: {risk.get('risk_score')}/100)",
        f"- AI Classification: {ai.get('classification', 'N/A')} ({ai.get('confidence_score', 'N/A')}%)",
        f"- Primary Risk Factors: {', '.join(risk.get('primary_risk_factors', []))}",
        f"- Executive Summary: {ai.get('executive_summary', 'N/A')}",
        ""
    ]

    if chat_history:
        lines.append("CONVERSATION HISTORY:")
        for msg in chat_history[-6:]:
            role = "Analyst" if msg.get("role") == "user" else "Assistant"
            lines.append(f"{role}: {msg.get('content', '')}")
        lines.append("")

    lines.append(f"ANALYST QUESTION: {user_query}")
    lines.append("")
    lines.append("Provide your detailed forensic answer:")

    return "\n".join(lines)
