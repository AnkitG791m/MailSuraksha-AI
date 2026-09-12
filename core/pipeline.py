import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from core.parser import EmailParser
from core.auth_check import AuthChecker
from core.origin_ip import OriginIPExtractor
from core.whois_lookup import WhoisLookup
from core.geo import GeoLocator
from core.local_analyzer import local_analyzer
from core.threat_intel import ThreatIntelAggregator
from core.threat_memory import threat_memory_engine
from core.classifier import RiskClassifier
from core.risk_scorer import RiskScorer
from core.quishing_scanner import QuishingScanner
from core.ai_intelligence import ai_engine
from core.report import ForensicReportGenerator
from database import db
from config import settings



class AnalysisPipeline:
    """
    Production-Ready SecureX Threat Intelligence Pipeline.
    1. Ingestion & Deep RFC Parsing
    2. Authentication & Live DNS Lookups
    3. Origin IP Extraction & Geolocation
    4. Layer 1: Local Analysis (Zero-Network Risk Scoring)
    5. Threat Memory & Campaign Correlation
    6. Layer 2: Selective Multi-Tier Threat Intel Enrichment:
       - Local Score < 50: Zero external APIs called (Low Risk)
       - Local Score 50-70: 7-Day SQLite Cache -> AbuseIPDB & OTX (Skip VT)
       - Local Score > 70: Full Enrichment (AbuseIPDB -> OTX -> VirusTotal Key Rotator)
    7. AI/ML Risk Classification
    8. Composite Risk Scoring & Threat Memory Recording
    9. Forensic PDF & JSON Reports
    """

    def __init__(self):
        self.classifier = RiskClassifier()
        self.risk_scorer = RiskScorer(
            clean_threshold=settings.CLEAN_THRESHOLD,
            suspicious_threshold=settings.SUSPICIOUS_THRESHOLD
        )

    def process_eml(self, raw_bytes: bytes, filename: str = "upload.eml") -> Dict[str, Any]:
        report_id = f"SECX-{uuid.uuid4().hex[:10].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Step 1 & 2: Ingestion & Forensic Parsing
        parser = EmailParser(raw_bytes)
        parsed_data = parser.parse_all()

        # Step 3: Authentication Checks (SPF, DKIM, DMARC + live DNS)
        auth_checker = AuthChecker(parsed_data["headers"])
        auth_results = auth_checker.check_all()

        # Step 4: Origin IP Extraction (walking Received chain bottom-to-top)
        ip_extractor = OriginIPExtractor(parsed_data["received_chain"])
        origin_ip_data = ip_extractor.extract()
        origin_ip = origin_ip_data.get("origin_ip")

        # Step 5: WHOIS & Domain Age (<30 day domain flagging)
        sender_domain = parsed_data["headers"].get("from", {}).get("domain", "")
        whois_lookup = WhoisLookup(sender_domain)
        whois_data = whois_lookup.lookup()

        # Step 6: GeoLocation (IPInfo token / ip-api.com, city, country, lat/long, ISP)
        geo_locator = GeoLocator(origin_ip)
        geo_data = geo_locator.locate()

        # --- LAYER 1: LOCAL THREAT ANALYSIS (Zero-Network Risk Scoring) ---
        local_analysis = local_analyzer.analyze(parsed_data, auth_results)
        local_score = local_analysis.get("local_risk_score", 0.0)

        # --- THREAT MEMORY ENGINE: CAMPAIGN & INFRASTRUCTURE CORRELATION ---
        subject = parsed_data["headers"].get("subject", "")
        extracted_domains = parsed_data.get("urls", {}).get("unique_domains", [])
        extracted_urls = parsed_data.get("urls", {}).get("all_urls", [])

        correlation_data = threat_memory_engine.correlate(
            origin_ip=origin_ip,
            sender_domain=sender_domain,
            subject=subject,
            urls=extracted_urls
        )

        # If recurring threat detected in memory, add local correlation signal
        if correlation_data.get("has_correlation"):
            local_analysis["triggered_rules"].extend(correlation_data.get("insights", []))

        # --- LAYER 2: SELECTIVE THREAT INTEL ENRICHMENT ---
        # Enforces:
        # Score < 50: Zero external APIs called
        # Score 50-70: 7-day cache check -> AbuseIPDB / OTX if miss (Skip VT)
        # Score > 70: Full enrichment with VT multi-key rotation
        threat_agg = ThreatIntelAggregator(
            origin_ip=origin_ip,
            domains=extracted_domains,
            urls=extracted_urls,
            local_risk_score=local_score
        )
        threat_data = threat_agg.check_all()

        # Step 8: AI/ML Risk Classifier (NLP TF-IDF + structural features)
        ml_results = self.classifier.classify(parsed_data, auth_results, whois_data, threat_data)

        # Step 9: Risk Scoring (weighted combination -> Final Verdict)
        risk_verdict = self.risk_scorer.calculate_verdict(
            parsed_data, auth_results, whois_data, geo_data, threat_data, ml_results
        )

        # Step 9.2: Quishing (QR Code Phishing) Analysis
        body_html = parsed_data.get("body", {}).get("html", "") if isinstance(parsed_data.get("body"), dict) else ""
        body_plain = parsed_data.get("body", {}).get("plain", "") if isinstance(parsed_data.get("body"), dict) else ""
        if not body_plain and isinstance(parsed_data.get("body"), dict):
            body_plain = parsed_data.get("body", {}).get("text", "")
        
        quishing_scanner = QuishingScanner(
            body_html=body_html,
            body_plain=body_plain,
            attachments=parsed_data.get("attachments", []),
            urls=extracted_urls
        )
        quishing_result = quishing_scanner.scan()
        if quishing_result.get("quishing_detected"):
            risk_verdict.setdefault("primary_risk_factors", []).append("QR Code Phishing (Quishing) Vector Identified")
            if risk_verdict.get("risk_score", 0) < 65:
                risk_verdict["risk_score"] = min(risk_verdict.get("risk_score", 0) + 30, 95)
                risk_verdict["verdict"] = "Malicious" if risk_verdict["risk_score"] >= 61 else "Suspicious"

        # Step 9.5: AI Intelligence Layer (OpenRouter / Gemini Multi-Tier LLM)
        # Generates: Threat Classification, Threat Explanation, Recommendations,
        # Executive Summary (<= 150 words), Campaign Correlation, Plain-language Translation
        ai_insights = ai_engine.analyze_email(
            headers=parsed_data["headers"],
            auth=auth_results,
            whois=whois_data,
            geo=geo_data,
            threat_intel=threat_data,
            local_score=local_score,
            risk_verdict=risk_verdict,
            threat_memory=correlation_data,
            body_text=parsed_data.get("body", {}).get("text", ""),
            urls=parsed_data.get("urls", {}),
            attachments=parsed_data.get("attachments", [])
        )

        # Build combined analysis payload
        analysis_result = {
            "report_id": report_id,
            "filename": filename,
            "analyzed_at": timestamp,
            "hashes": parsed_data["hashes"],
            "headers": parsed_data["headers"],
            "received_chain": parsed_data["received_chain"],
            "body": parsed_data["body"],
            "attachments": parsed_data["attachments"],
            "urls": parsed_data["urls"],
            "raw_headers": parsed_data["raw_headers"],
            "auth": auth_results,
            "origin_ip": origin_ip_data,
            "whois": whois_data,
            "geo": geo_data,
            "local_analysis": local_analysis,
            "threat_memory": correlation_data,
            "threat_intel": threat_data,
            "quishing": quishing_result,
            "ml": ml_results,
            "risk": risk_verdict,
            "ai_insights": ai_insights
        }

        # Step 10: Record into Threat Memory if suspicious/malicious
        threat_memory_engine.record(analysis_result)

        # Generate Forensic PDF and JSON reports
        pdf_path = settings.REPORTS_DIR / f"{report_id}.pdf"
        json_path = settings.REPORTS_DIR / f"{report_id}.json"
        
        try:
            report_gen = ForensicReportGenerator(analysis_result)
            report_gen.generate_pdf(pdf_path)
            report_gen.export_json(json_path)
            analysis_result["pdf_report_path"] = str(pdf_path)
            analysis_result["json_report_path"] = str(json_path)
        except Exception as r_err:
            logger.error(f"Report generation error for {report_id}: {r_err}", exc_info=True)
            analysis_result["pdf_report_path"] = None
            analysis_result["json_report_path"] = None

        # Persist to database
        db.save_analysis(report_id, filename, analysis_result)

        return analysis_result

pipeline = AnalysisPipeline()
