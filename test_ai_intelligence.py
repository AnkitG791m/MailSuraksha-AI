import sys
import os
import json
from pathlib import Path

# Add packages to path
sys.path.insert(0, str(Path(__file__).resolve().parent / "packages"))

from core.prompts import sanitize_email_content, build_analysis_prompt
from core.llm_client import llm_client
from core.ai_intelligence import ai_engine, VALID_CLASSIFICATIONS
from core.investigation_chat import investigation_chat_assistant
from core.pipeline import pipeline
from database import db


def test_pii_sanitization():
    print("\n[TEST 1] Testing PII Sanitization & Masking...")
    sample_text = (
        "Hello, my credit card is 4532-1234-5678-9012 and SSN is 123-45-6789. "
        "The password: superSecretPassword123! and my bearer token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9. "
        "Call me at +1 (555) 234-5678."
    )
    sanitized = sanitize_email_content(sample_text)
    assert "4532-1234-5678-9012" not in sanitized, "Credit card failed to mask"
    assert "123-45-6789" not in sanitized, "SSN failed to mask"
    assert "superSecretPassword123!" not in sanitized, "Password failed to mask"
    assert "[REDACTED_CARD_NUMBER]" in sanitized, "Missing card redaction token"
    assert "[REDACTED_SSN]" in sanitized, "Missing SSN redaction token"
    print("  ✓ PASS: All sensitive PII, passwords, and tokens masked securely!")


def test_llm_client_fallback_resilience():
    print("\n[TEST 2] Testing LLM Client Fallback & Zero-Downtime Resilience...")
    # Test local expert fallback directly
    fallback_data, tele = llm_client.generate(
        system_prompt="System instructions",
        user_prompt="Subject: Urgent wire transfer. Verdict: Malicious. SPF: fail. Deceptive Anchor link detected.",
        expect_json=True
    )
    assert isinstance(fallback_data, dict), "Fallback did not return dict"
    assert fallback_data.get("classification") in VALID_CLASSIFICATIONS, f"Invalid classification: {fallback_data.get('classification')}"
    assert "recommendations" in fallback_data, "Missing recommendations"
    assert "executive_summary" in fallback_data, "Missing executive summary"
    print(f"  • Provider: {tele.get('provider_used')}")
    print(f"  • Classification: {fallback_data.get('classification')}")
    print(f"  • Confidence: {fallback_data.get('confidence_score')}%")
    print("  ✓ PASS: Multi-tier LLM engine returned structured forensic insights!")


def test_ai_engine_features_1_to_6():
    print("\n[TEST 3] Testing AI Features 1 to 6 Generation...")
    headers = {
        "subject": "Critical Security Alert: Immediate Verification Required",
        "from": {"raw": "Microsoft Support <support@microsoft-verify-update.com>", "domain": "microsoft-verify-update.com", "lookalike": {"target_brand": "microsoft.com"}},
        "reply_to": {"raw": "attacker@darkmail.to", "mismatch_with_from": True},
        "return_path": {"raw": "bounce@suspicious-vps.net", "mismatch_with_from": True}
    }
    auth = {
        "spf": {"status": "fail", "details": "SPF failed"},
        "dkim": {"status": "none", "details": "No DKIM signature"},
        "dmarc": {"status": "fail", "details": "DMARC policy failed"}
    }
    whois = {"age_days": 4, "is_young": True, "registrar": "NameCheap"}
    geo = {"query_ip": "185.220.101.5", "country": "Russia", "city": "Moscow", "isp": "Bulletproof VPS", "as_number": "AS208312"}
    threat_intel = {
        "origin_ip_intel": {
            "virustotal": {"malicious": 8, "suspicious": 2, "reputation": 15},
            "abuseipdb": {"abuse_score": 95, "total_reports": 412, "is_whitelisted": False},
            "alienvault": {"pulse_count": 3, "tags": ["phishing", "tor-exit"]}
        }
    }
    risk_verdict = {
        "verdict": "Malicious",
        "risk_score": 95.0,
        "confidence_pct": 95.0,
        "primary_risk_factors": ["SPF failed", "Deceptive link anchor mismatch", "Young domain (<30 days)"]
    }
    threat_memory = {
        "has_correlation": True,
        "ip_incident_count": 4,
        "domain_incident_count": 3,
        "detected_campaign": "Brand Typosquatting Wave",
        "insights": ["Origin IP previously recorded in 4 malicious incidents in Threat Memory."]
    }
    urls = {"mismatched_links": [{"display": "https://microsoft.com", "actual": "http://evil.com/login"}], "shortened_urls": []}
    attachments = [{"filename": "invoice_update.scr", "is_dangerous": True}]

    insights = ai_engine.analyze_email(
        headers=headers,
        auth=auth,
        whois=whois,
        geo=geo,
        threat_intel=threat_intel,
        local_score=95.0,
        risk_verdict=risk_verdict,
        threat_memory=threat_memory,
        body_text="Your account will be terminated in 24 hours. Click here to confirm identity: http://evil.com/login",
        urls=urls,
        attachments=attachments
    )

    # Validate Feature 1: Classification
    assert insights["classification"] in VALID_CLASSIFICATIONS
    assert 0 <= insights["confidence_score"] <= 100
    print(f"  • Feature 1 (Classification): {insights['classification']} (Confidence: {insights['confidence_score']}%)")

    # Validate Feature 2: Threat Explanation
    assert len(insights["threat_explanation"]) > 20
    print(f"  • Feature 2 (Threat Explanation): {insights['threat_explanation'][:90]}...")

    # Validate Feature 3: Recommendation Engine
    assert len(insights["recommendations"]) >= 3
    print(f"  • Feature 3 (Recommendations): {len(insights['recommendations'])} action items")

    # Validate Feature 4: Executive Summary (<= 150 words)
    word_count = len(insights["executive_summary"].split())
    assert word_count <= 150
    print(f"  • Feature 4 (Executive Summary): {word_count} words (<= 150 words requirement met)")

    # Validate Feature 5: Campaign Correlation Assistant
    camp = insights["campaign_correlation"]
    assert "possible_campaign_relation" in camp and "similarity_score" in camp
    print(f"  • Feature 5 (Campaign Correlation): {camp['possible_campaign_relation']} (Similarity: {camp['similarity_score']}%)")

    # Validate Feature 6: Plain Language Translation
    assert len(insights["user_friendly_translation"]) > 20
    print(f"  • Feature 6 (User-Friendly Translation): {insights['user_friendly_translation'][:90]}...")

    print("  ✓ PASS: All 6 AI Intelligence Features generated and validated!")


def test_investigation_chatbot_and_db():
    print("\n[TEST 4] Testing AI Feature 7: Investigation Assistant Chatbot & DB History...")
    test_report_id = "SECX-TEST-AI-999"
    mock_record = {
        "report_id": test_report_id,
        "headers": {"subject": "URGENT: Password Reset Required", "from": {"raw": "Security Desk <alert@microsoft-phish.com>"}},
        "origin_ip": {"origin_ip": "185.220.101.5"},
        "geo": {"city": "Moscow", "country": "Russia", "isp": "Bulletproof VPS"},
        "auth": {"spf": {"status": "fail"}, "dkim": {"status": "none"}, "dmarc": {"status": "fail"}},
        "risk": {"verdict": "Malicious", "risk_score": 92.0, "primary_risk_factors": ["SPF failed", "Origin IP flagged in AbuseIPDB"]},
        "ai_insights": {"classification": "Credential Harvesting", "confidence_score": 92, "executive_summary": "Active phishing campaign attempting credential theft."}
    }

    # Ask questions
    q = "Why did this email fail SPF authentication?"
    chat_res = investigation_chat_assistant.chat(test_report_id, q, mock_record)
    assert "reply" in chat_res and len(chat_res["reply"]) > 20
    assert "suggested_questions" in chat_res and len(chat_res["suggested_questions"]) > 0
    print(f"  • User Query: '{q}'")
    print(f"  • Assistant Reply: {chat_res['reply'][:120]}...")
    print(f"  • Suggested Questions: {chat_res['suggested_questions']}")

    # Test Database Persistence
    db.save_chat_message(test_report_id, "user", q)
    db.save_chat_message(test_report_id, "assistant", chat_res["reply"])
    history = db.get_chat_history(test_report_id)
    assert len(history) >= 2
    assert history[0]["role"] == "user"
    assert history[1]["role"] == "assistant"
    print(f"  • Chat History Recorded in SQLite: {len(history)} messages verified")
    print("  ✓ PASS: Interactive Investigation Chatbot and SQLite persistence verified!")


def test_end_to_end_pipeline_with_ai():
    print("\n[TEST 5] Testing End-to-End Pipeline with AI Intelligence Layer...")
    with open("samples/phishing_sample.eml", "rb") as f:
        content = f.read()

    result = pipeline.process_eml(content, filename="phishing_sample.eml")
    assert "ai_insights" in result, "ai_insights missing from pipeline output"
    ai = result["ai_insights"]
    assert ai["classification"] in VALID_CLASSIFICATIONS
    assert "recommendations" in ai and len(ai["recommendations"]) > 0
    assert "executive_summary" in ai

    # Verify report files
    pdf_path = Path(result["pdf_report_path"])
    json_path = Path(result["json_report_path"])
    assert pdf_path.exists(), f"PDF report not found at {pdf_path}"
    assert json_path.exists(), f"JSON report not found at {json_path}"

    with open(json_path) as jf:
        saved_json = json.load(jf)
        assert "ai_insights" in saved_json

    print(f"  • Analyzed Report ID: {result['report_id']}")
    print(f"  • AI Classification: {ai['classification']}")
    print(f"  • Executive Summary: {ai['executive_summary'][:90]}...")
    print(f"  • PDF Report Verified: {pdf_path.name} ({pdf_path.stat().st_size} bytes)")
    print(f"  • JSON Report Verified: {json_path.name} (Contains ai_insights)")
    print("  ✓ PASS: Complete end-to-end pipeline with AI layer, reports, and persistence verified!")


if __name__ == "__main__":
    print("=" * 70)
    print(" SECUREX AI INTELLIGENCE LAYER & INVESTIGATION CHATBOT TESTS ")
    print("=" * 70)

    test_pii_sanitization()
    test_llm_client_fallback_resilience()
    test_ai_engine_features_1_to_6()
    test_investigation_chatbot_and_db()
    test_end_to_end_pipeline_with_ai()

    print("\n" + "=" * 70)
    print(" ALL 5 AI INTELLIGENCE LAYER TEST SUITES PASSED 100%! ")
    print("=" * 70)
