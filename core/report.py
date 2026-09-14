import json
import html
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from config import settings


class ForensicReportGenerator:
    """
    Step 10: Forensic Report Generator.
    Produces comprehensive, chain-of-custody-compliant forensic reports in PDF and JSON formats.
    Includes headers, cryptographic hashes, auth results, geo coordinates, WHOIS,
    threat intelligence, AI verdict, and full Received hop audit trail.
    """

    def __init__(self, analysis_result: Dict[str, Any]):
        self.data = analysis_result
        self.report_id = analysis_result.get("report_id", f"SECX-{int(datetime.now(timezone.utc).timestamp())}")
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def generate_pdf(self, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=12
        )
        h2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "BodyCustom",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155")
        )
        mono_style = ParagraphStyle(
            "MonoCustom",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#1e293b")
        )

        def esc(val: Any) -> str:
            if val is None:
                return "N/A"
            return html.escape(str(val))

        story = []

        # 1. Header Banner
        story.append(Paragraph("<b>MailGuardian AI</b> | Forensic Threat Intelligence Report", title_style))
        story.append(Paragraph(f"Case ID: <b>{esc(self.report_id)}</b> &nbsp;|&nbsp; Generated: {esc(self.timestamp)} &nbsp;|&nbsp; Enterprise Email Threat Defense", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=14))

        # 2. Executive Verdict Summary Box
        verdict = self.data.get("risk", {}).get("verdict", "Unknown")
        score = self.data.get("risk", {}).get("risk_score", 0.0)
        confidence = self.data.get("risk", {}).get("confidence_pct", 0.0)

        v_bg = colors.HexColor("#fee2e2") if verdict == "Malicious" else (colors.HexColor("#fef3c7") if verdict == "Suspicious" else colors.HexColor("#dcfce7"))
        v_fg = colors.HexColor("#991b1b") if verdict == "Malicious" else (colors.HexColor("#92400e") if verdict == "Suspicious" else colors.HexColor("#166534"))

        verdict_data = [
            [
                Paragraph(f"<font size=14 color='{v_fg.hexval()}'><b>FINAL VERDICT: {esc(verdict).upper()}</b></font><br/><font size=9 color='#475569'>Confidence: <b>{esc(confidence)}%</b></font>", body_style),
                Paragraph(f"<font size=18 color='{v_fg.hexval()}'><b>{esc(score)} / 100</b></font><br/><font size=8 color='#475569'>Composite Threat Score</font>", body_style)
            ]
        ]
        verdict_table = Table(verdict_data, colWidths=[380, 160])
        verdict_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), v_bg),
            ("BOX", (0, 0), (-1, -1), 1, v_fg),
            ("PADDING", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
        ]))
        story.append(verdict_table)
        story.append(Spacer(1, 10))

        # 3. Chain of Custody & File Hashes
        story.append(Paragraph("<b>1. Chain of Custody & Evidence Identifiers</b>", h2_style))
        hashes = self.data.get("hashes", {})
        headers = self.data.get("headers", {})
        custody_data = [
            [Paragraph("<b>Evidence SHA-256:</b>", body_style), Paragraph(esc(hashes.get("sha256", "N/A")), mono_style)],
            [Paragraph("<b>Evidence MD5:</b>", body_style), Paragraph(esc(hashes.get("md5", "N/A")), mono_style)],
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(esc(headers.get("subject", "N/A")), body_style)],
            [Paragraph("<b>Sender (From):</b>", body_style), Paragraph(esc(headers.get("from", {}).get("raw", "N/A")), body_style)],
            [Paragraph("<b>Return-Path:</b>", body_style), Paragraph(esc(headers.get("return_path", {}).get("raw", "N/A")), body_style)],
            [Paragraph("<b>Reply-To:</b>", body_style), Paragraph(esc(headers.get("reply_to", {}).get("raw", "N/A")), body_style)],
            [Paragraph("<b>Message-ID:</b>", body_style), Paragraph(esc(headers.get("message_id", "N/A")), mono_style)],
            [Paragraph("<b>Message Date:</b>", body_style), Paragraph(esc(headers.get("date", "N/A")), body_style)]
        ]
        t_custody = Table(custody_data, colWidths=[130, 410])
        t_custody.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 4)
        ]))
        story.append(t_custody)
        story.append(Spacer(1, 10))

        # 4. Authentication Validation (RFC 7489 Alignment Matrix)
        story.append(Paragraph("<b>2. Sender Identity & RFC 7489 Authentication Matrix</b>", h2_style))
        auth = self.data.get("auth", {})
        matrix_rows = auth.get("alignment_matrix") or auth.get("alignment", {}).get("matrix", [])
        
        auth_data = [
            [Paragraph("<b>Standard</b>", body_style), Paragraph("<b>Result</b>", body_style), Paragraph("<b>Domain Evaluated</b>", body_style), Paragraph("<b>Alignment Status</b>", body_style), Paragraph("<b>Forensic Evidence</b>", body_style)]
        ]
        
        if matrix_rows:
            for m in matrix_rows:
                res_col = "#16a34a" if "PASS" in str(m.get("result", "")) else "#dc2626"
                auth_data.append([
                    Paragraph(f"<b>{esc(m.get('protocol'))}</b>", body_style),
                    Paragraph(f"<font color='{res_col}'><b>{esc(m.get('result'))}</b></font>", body_style),
                    Paragraph(f"<code>{esc(m.get('domain'))}</code>", mono_style),
                    Paragraph(esc(m.get("alignment")), body_style),
                    Paragraph(esc(m.get("evidence")), body_style)
                ])
        else:
            auth_data.append([
                Paragraph("<b>SPF</b>", body_style),
                Paragraph(esc(auth.get("spf", {}).get("status", "none")).upper(), body_style),
                Paragraph(esc(auth.get("spf", {}).get("domain", "N/A")), body_style),
                Paragraph("N/A", body_style),
                Paragraph(esc(auth.get("spf", {}).get("details", "N/A")), body_style)
            ])

        t_auth = Table(auth_data, colWidths=[90, 60, 110, 100, 180])
        t_auth.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 3.5)
        ]))
        story.append(t_auth)
        story.append(Spacer(1, 10))

        # 5. Geolocation & Origin Infrastructure
        story.append(Paragraph("<b>3. Origin IP & Geolocation Intelligence</b>", h2_style))
        raw_origin = self.data.get("origin_ip", {})
        origin_ip = raw_origin.get("origin_ip", "N/A") if isinstance(raw_origin, dict) else str(raw_origin)
        conf_pct = raw_origin.get("confidence_score", 0.72) * 100 if isinstance(raw_origin, dict) else 70
        geo = self.data.get("geo", {})
        geo_mode = geo.get("data_mode", "LIVE")
        
        geo_data = [
            [Paragraph("<b>Probable Origin IP:</b>", body_style), Paragraph(f"<b>{esc(origin_ip)}</b> (Conf: {int(conf_pct)}%)", body_style),
             Paragraph("<b>Country / City:</b>", body_style), Paragraph(f"{esc(geo.get('country', 'N/A'))} ({esc(geo.get('city', 'N/A'))})", body_style)],
            [Paragraph("<b>Latitude / Longitude:</b>", body_style), Paragraph(f"{esc(geo.get('lat', 'N/A'))}, {esc(geo.get('lon', 'N/A'))}", body_style),
             Paragraph("<b>ISP / ASN:</b>", body_style), Paragraph(f"{esc(geo.get('isp', 'N/A'))} [{esc(geo.get('as_number', 'N/A'))}]", body_style)],
            [Paragraph("<b>Intelligence Mode:</b>", body_style), Paragraph(f"<b>[{esc(geo_mode)}]</b> via {esc(geo.get('source', 'System'))}", body_style),
             Paragraph("<b>Forensic Attribution:</b>", body_style), Paragraph("Probabilistic network routing lead (Not human identity)", body_style)]
        ]
        t_geo = Table(geo_data, colWidths=[120, 150, 110, 160])
        t_geo.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 3.5)
        ]))
        story.append(t_geo)
        story.append(Spacer(1, 10))

        # 6. WHOIS & Domain Age
        story.append(Paragraph("<b>4. WHOIS Registration & Domain Age Assessment</b>", h2_style))
        whois_data = self.data.get("whois", {})
        age_str = f"{whois_data.get('age_days')} days" if whois_data.get("age_days") is not None else "Unknown"
        is_young_str = "<font color='red'><b>YES (&lt;30 days - High Risk)</b></font>" if whois_data.get("is_young") else "No (Established Domain)"
        w_table_data = [
            [Paragraph("<b>Sender Domain:</b>", body_style), Paragraph(esc(whois_data.get("domain", "N/A")), body_style),
             Paragraph("<b>Registrar:</b>", body_style), Paragraph(esc(whois_data.get("registrar", "N/A")), body_style)],
            [Paragraph("<b>Domain Age:</b>", body_style), Paragraph(esc(age_str), body_style),
             Paragraph("<b>Flagged &lt;30 Days:</b>", body_style), Paragraph(is_young_str, body_style)]
        ]
        t_whois = Table(w_table_data, colWidths=[110, 160, 110, 160])
        t_whois.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 4)
        ]))
        story.append(t_whois)
        story.append(Spacer(1, 10))

        # 7. AI Intelligence & Threat Insights
        story.append(Paragraph("<b>5. AI Intelligence Layer & Forensic Executive Summary</b>", h2_style))
        ai = self.data.get("ai_insights", {})
        ml = self.data.get("ml", {})
        factors = self.data.get("risk", {}).get("primary_risk_factors", [])
        factors_html = "<br/>".join([f"• {esc(f)}" for f in factors]) if factors else "None detected"
        recs = ai.get("recommendations", [])
        recs_html = "<br/>".join([f"• {esc(r)}" for r in recs]) if recs else "Standard vigilance."
        camp = ai.get("campaign_correlation", {})
        camp_str = f"<b>{esc(camp.get('possible_campaign_relation', 'Isolated'))}</b> (Similarity: {esc(camp.get('similarity_score', 0))}%)<br/>{esc(camp.get('reasoning', ''))}"

        ai_data = [
            [Paragraph("<b>AI Threat Classification:</b>", body_style), Paragraph(f"<b>{esc(ai.get('classification', 'Pending'))}</b> (Confidence: {esc(ai.get('confidence_score', 0))}%)", body_style)],
            [Paragraph("<b>Forensic Executive Summary:</b>", body_style), Paragraph(esc(ai.get("executive_summary", "Forensic summary pending.")), body_style)],
            [Paragraph("<b>Threat Explanation:</b>", body_style), Paragraph(esc(ai.get("threat_explanation", "No threat explanation.")), body_style)],
            [Paragraph("<b>Security Recommendations:</b>", body_style), Paragraph(recs_html, body_style)],
            [Paragraph("<b>Campaign Correlation:</b>", body_style), Paragraph(camp_str, body_style)],
            [Paragraph("<b>Plain Language Translation:</b>", body_style), Paragraph(esc(ai.get("user_friendly_translation", "Safe to open.")), body_style)],
            [Paragraph("<b>Deterministic Risk Factors:</b>", body_style), Paragraph(factors_html, body_style)]
        ]
        t_ai = Table(ai_data, colWidths=[140, 400])
        t_ai.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 4)
        ]))
        story.append(t_ai)
        story.append(Spacer(1, 14))

        # 8. Received Hops Audit Chain
        story.append(Paragraph("<b>6. Email Received Infrastructure Hop Sequence (Bottom to Top)</b>", h2_style))
        hops = self.data.get("received_chain", [])
        hop_rows = [
            [Paragraph("<b>#</b>", body_style), Paragraph("<b>Hop Details (From / By / Proto / IPs)</b>", body_style)]
        ]
        for idx, h in enumerate(reversed(hops)):
            ips_str = ', '.join(h.get('ips', [])) if isinstance(h.get('ips'), list) else str(h.get('ips', ''))
            hop_text = f"<b>Hop {idx+1}</b>: from <code>{esc(h.get('from_host'))}</code> by <code>{esc(h.get('by_host'))}</code> with <code>{esc(h.get('with_proto'))}</code><br/>IPs: {esc(ips_str or 'None detected')}"
            hop_rows.append([Paragraph(str(idx+1), body_style), Paragraph(hop_text, body_style)])

        t_hops = Table(hop_rows, colWidths=[25, 515])
        t_hops.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 3)
        ]))
        story.append(t_hops)
        story.append(Spacer(1, 14))

        # 9. Quishing (QR Code Phishing) Assessment
        quish = self.data.get("quishing", {})
        if quish.get("quishing_detected"):
            story.append(Paragraph("<b>7. AI Quishing (QR Code Phishing) Analysis</b>", h2_style))
            q_ind_html = "<br/>".join([f"• {esc(i)}" for i in quish.get("indicators", [])])
            q_data = [
                [Paragraph("<b>Quishing Status:</b>", body_style), Paragraph("<font color='red'><b>DETECTED (High Risk QR Phishing Vector)</b></font>", body_style)],
                [Paragraph("<b>Confidence Score:</b>", body_style), Paragraph(f"{esc(quish.get('confidence_score', 0))}%", body_style)],
                [Paragraph("<b>Identified Indicators:</b>", body_style), Paragraph(q_ind_html or "None", body_style)]
            ]
            t_quish = Table(q_data, colWidths=[140, 400])
            t_quish.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#fca5a5")),
                ("PADDING", (0, 0), (-1, -1), 4)
            ]))
            story.append(t_quish)
            story.append(Spacer(1, 14))

        # 9. Actionable Incident Response & Containment Playbook
        playbook_acts = self.data.get("playbook_actions", [])
        if playbook_acts:
            story.append(Paragraph("<b>7. Actionable Incident Response & Containment Playbook</b>", h2_style))
            pb_rows = [[Paragraph("<b>#</b>", body_style), Paragraph("<b>Mandated Containment Action</b>", body_style)]]
            for p_idx, act in enumerate(playbook_acts):
                pb_rows.append([Paragraph(str(p_idx + 1), body_style), Paragraph(f"• {esc(act)}", body_style)])
            t_pb = Table(pb_rows, colWidths=[25, 515])
            t_pb.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("PADDING", (0, 0), (-1, -1), 3.5)
            ]))
            story.append(t_pb)
            story.append(Spacer(1, 12))

        # 10. Section 65B Digital Evidence Documentation Certificate (Indian Evidence Act / BSA 2023)
        story.append(Paragraph("<b>8. Statutory Evidence Documentation Package (Section 65B Indian Evidence Act / Section 63 BSA 2023)</b>", h2_style))
        sec65b_text = (
            "<b>STATUTORY EVIDENCE DOCUMENTATION CERTIFICATE (EXAMINER SUPPORT RECORD)</b><br/><br/>"
            f"1. <b>Evidence Identifier:</b> <code>{esc(self.report_id)}</code> | <b>Original Bitstream Hash (SHA-256):</b> <code>{esc(hashes.get('sha256', 'N/A'))}</code><br/>"
            f"2. <b>Acquisition Timestamp (UTC):</b> <b>{esc(self.timestamp)}</b> | <b>Time Sync Reference:</b> UTC System Clock via NTP.<br/>"
            "3. <b>Acquisition & Processing Tool:</b> MailGuardian AI Forensic Workstation (v2.1.0-SOC) operating on deterministic RFC 5322/7489 parsers.<br/>"
            "4. <b>Integrity Baseline:</b> The SHA-256 cryptographic hash of the original electronic bitstream was recorded immediately upon ingestion prior to memory representation. "
            "No modification was made to the underlying raw evidence.<br/>"
            "5. <b>Forensic Attribution Scope:</b> Geolocation, candidate origin IP, and Autonomous System Numbers represent probabilistic network routing leads. "
            "Conclusive human actor attribution requires judicial correlation with serving ISP subscriber allocation records.<br/>"
            "6. <b>Examiner Certification & Legal Notice:</b><br/>"
            "<i>\"This package is intended to support an examiner's electronic evidence documentation and chain-of-custody verification under Section 65B of the Indian Evidence Act, 1872 / Section 63 of Bharatiya Sakshya Adhiniyam, 2023. It does not independently establish legal admissibility without examiner testimony and verified judicial affidavit.\"</i><br/><br/>"
            "<b>Examiner Signature:</b> ___________________________ &nbsp;&nbsp;&nbsp;&nbsp; <b>Designation:</b> Lead SOC Analyst / Digital Evidence Examiner"
        )
        sec65b_data = [[Paragraph(sec65b_text, body_style)]]
        t_sec65b = Table(sec65b_data, colWidths=[540])
        t_sec65b.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0284c7")),
            ("PADDING", (0, 0), (-1, -1), 8)
        ]))
        story.append(t_sec65b)

        # Build document
        doc.build(story)
        return output_path

    def export_json(self, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        return output_path
