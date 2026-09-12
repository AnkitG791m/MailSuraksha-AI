import uuid
import hashlib
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

        # Step 0: Immutable Evidence Integrity Hashing (pre-parse baseline)
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        raw_md5 = hashlib.md5(raw_bytes).hexdigest()
        evidence_metadata = {
            "evidence_id": report_id,
            "sha256": raw_sha256,
            "md5": raw_md5,
            "byte_size": len(raw_bytes),
            "acquisition_utc": timestamp,
            "tool_name": "MailSuraksha AI Forensic Engine",
            "tool_version": "2.1.0",
            "parser_policy": "RFC 5322 Standards-Compliant",
            "time_sync_reference": "UTC System Clock"
        }

        # Step 1 & 2: Ingestion & Forensic Parsing
        parser = EmailParser(raw_bytes)
        parsed_data = parser.parse_all()

        # Step 3: Authentication Checks (SPF, DKIM, DMARC + live DNS)
        auth_checker = AuthChecker(parsed_data["headers"])
        auth_results = auth_checker.check_all()

        # Step 4: Origin IP & Relay Chain Anomaly Assessment
        ip_extractor = OriginIPExtractor(parsed_data["received_chain"], auth_context=auth_results)
        origin_ip_data = ip_extractor.extract()
        origin_ip = origin_ip_data.get("candidate_origin_ip") or origin_ip_data.get("origin_ip")

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

        # Step 9: Risk Scoring (calibrated combination -> Final Verdict)
        risk_verdict = self.risk_scorer.calculate_verdict(
            parsed_data, auth_results, whois_data, geo_data, threat_data, ml_results, origin_data=origin_ip_data
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

        # Build Graph-based Correlation Network with Non-Causal Semantics
        correlation_graph = self._build_correlation_graph(
            report_id=report_id,
            filename=filename,
            parsed_data=parsed_data,
            origin_ip_data=origin_ip_data,
            geo_data=geo_data,
            threat_data=threat_data,
            correlation_data=correlation_data,
            risk_verdict=risk_verdict
        )

        # Build combined analysis payload
        analysis_result = {
            "report_id": report_id,
            "filename": filename,
            "analyzed_at": timestamp,
            "evidence_metadata": evidence_metadata,
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
            "classifier": ml_results,
            "risk": risk_verdict,
            "risk_score": risk_verdict.get("risk_score"),
            "risk_band": risk_verdict.get("risk_band"),
            "analysis_confidence": risk_verdict.get("analysis_confidence"),
            "risk_factors": risk_verdict.get("factors", []),
            "playbooks": risk_verdict.get("playbook_items", []),
            "origin_assessment": origin_ip_data.get("origin_assessment", {}),
            "candidate_origin_ip": origin_ip_data.get("candidate_origin_ip"),
            "quishing": quishing_result,
            "ai_insights": ai_insights,
            "correlation_graph": correlation_graph,
            "graph_data": correlation_graph,
            "status": "complete"
        }

        # Step 10: Record into Threat Memory if suspicious/malicious
        threat_memory_engine.record(analysis_result)

        # Step 10: Persist to DB & Generate Reports
        db.save_analysis(report_id, filename, analysis_result)

        pdf_path = settings.REPORTS_DIR / f"{report_id}.pdf"
        json_path = settings.REPORTS_DIR / f"{report_id}.json"
        try:
            report_gen = ForensicReportGenerator(analysis_result)
            report_gen.generate_pdf(pdf_path)
            report_gen.export_json(json_path)
            analysis_result["pdf_report_path"] = str(pdf_path)
            analysis_result["json_report_path"] = str(json_path)
            analysis_result["reports"] = {
                "pdf_path": str(pdf_path),
                "json_path": str(json_path)
            }
        except Exception:
            analysis_result["pdf_report_path"] = None
            analysis_result["json_report_path"] = None
            analysis_result["reports"] = {
                "pdf_path": None,
                "json_path": None
            }

        return analysis_result

    def _build_correlation_graph(
        self,
        report_id: str,
        filename: str,
        parsed_data: Dict[str, Any],
        origin_ip_data: Dict[str, Any],
        geo_data: Dict[str, Any],
        threat_data: Dict[str, Any],
        correlation_data: Dict[str, Any],
        risk_verdict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Constructs an observational indicator correlation graph using non-causal relationship
        semantics (observed_in, candidate_origin_for, hosted_by, associated_with, etc.)
        pursuant to forensic rigor criteria.
        """
        nodes = []
        edges = []
        node_ids = set()

        def add_node(nid: str, label: str, ntype: str, category: str, color: str, details: str = ""):
            if nid and nid not in node_ids:
                node_ids.add(nid)
                nodes.append({
                    "id": nid,
                    "label": label[:30] + ("..." if len(label) > 30 else ""),
                    "type": ntype,
                    "category": category,  # 'observed_fact', 'derived_relationship', 'external_intelligence'
                    "color": color,
                    "details": details or label
                })

        def add_edge(src: str, dst: str, relation: str, confidence: float = 0.95, evidence_refs: list = None, weight: int = 1):
            if src in node_ids and dst in node_ids:
                edges.append({
                    "source": src,
                    "target": dst,
                    "label": relation,
                    "relation": relation,
                    "relationship_confidence": confidence,
                    "evidence_refs": evidence_refs or [],
                    "weight": weight
                })

        # Root Email Node (Observed Fact)
        v_color = "#ef4444" if risk_verdict.get("verdict") == "Malicious" else ("#f59e0b" if risk_verdict.get("verdict") == "Suspicious" else "#10b981")
        add_node(report_id, filename, "email", "observed_fact", v_color, f"Email Evidence: {filename} (Score: {risk_verdict.get('risk_score', 0)}/100)")

        # Sender Domain (Observed Fact)
        sender_domain = parsed_data.get("headers", {}).get("from", {}).get("domain", "")
        if sender_domain:
            d_id = f"domain:{sender_domain}"
            add_node(d_id, sender_domain, "domain", "observed_fact", "#8b5cf6", f"RFC 5322 From Domain: {sender_domain}")
            add_edge(d_id, report_id, "observed_in", confidence=1.0, evidence_refs=["header:from"])

        # Reply-To Domain (Observed Fact)
        reply_domain = parsed_data.get("headers", {}).get("reply_to", {}).get("domain", "")
        if reply_domain and reply_domain != sender_domain:
            r_id = f"reply:{reply_domain}"
            add_node(r_id, reply_domain, "reply_to", "observed_fact", "#ec4899", f"RFC 5322 Reply-To Domain: {reply_domain}")
            add_edge(r_id, report_id, "linked_from", confidence=1.0, evidence_refs=["header:reply_to"])

        # Candidate Origin IP (Derived Relationship)
        candidate_ip = origin_ip_data.get("candidate_origin_ip") or origin_ip_data.get("origin_ip")
        cand_conf = origin_ip_data.get("candidate_attribution_confidence", 0.70)
        if candidate_ip:
            ip_id = f"ip:{candidate_ip}"
            add_node(ip_id, candidate_ip, "ip", "derived_relationship", "#3b82f6", f"Candidate Origin IP: {candidate_ip} (Confidence: {int(cand_conf*100)}%)")
            add_edge(ip_id, report_id, "candidate_origin_for", confidence=cand_conf, evidence_refs=["header:received:earliest"])

            # ASN / Network Infrastructure (External Intelligence)
            isp = geo_data.get("isp") or geo_data.get("as_number", "")
            if isp and isp != "Unknown":
                asn_id = f"asn:{isp[:24]}"
                add_node(asn_id, isp[:20], "asn", "external_intelligence", "#6366f1", f"Network Routing Provider / ASN: {isp}")
                add_edge(ip_id, asn_id, "hosted_by", confidence=0.85, evidence_refs=["geo:bgp_asn"])

        # URLs / Hyperlinks (Observed Fact)
        extracted_urls = parsed_data.get("urls", {}).get("urls", [])
        for u in extracted_urls[:4]:
            u_str = u if isinstance(u, str) else u.get("url", "")
            if u_str:
                u_id = f"url:{u_str[:40]}"
                add_node(u_id, u_str[:25], "url", "observed_fact", "#06b6d4", f"Observed Hyperlink: {u_str}")
                add_edge(u_id, report_id, "observed_in", confidence=1.0, evidence_refs=["body:html_anchor"])

        # Attachments (Observed Fact)
        attachments = parsed_data.get("attachments", [])
        for att in attachments[:3]:
            att_name = att.get("filename", "attachment")
            att_id = f"att:{att_name}"
            is_dang = att.get("is_dangerous", False)
            add_node(att_id, att_name, "attachment", "observed_fact", "#f97316" if is_dang else "#64748b", f"Attachment: {att_name} ({att.get('size_bytes', 0)} B)")
            add_edge(att_id, report_id, "observed_in", confidence=1.0, evidence_refs=["mime:content_disposition"])

        # Campaign Correlation Node (External Intelligence / Hypothesis)
        campaign = correlation_data.get("detected_campaign")
        if campaign and campaign != "None":
            camp_id = f"camp:{campaign}"
            add_node(camp_id, campaign, "campaign", "external_intelligence", "#b91c1c", f"Correlated Attack Cluster: {campaign}")
            add_edge(camp_id, report_id, "associated_with", confidence=0.75, evidence_refs=["threat_memory:cluster"])

        return {
            "nodes": nodes,
            "edges": edges,
            "links": edges,  # Backward compatibility for frontend
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "density": round(len(edges) / max(1, len(nodes)), 2)
        }


pipeline = AnalysisPipeline()
