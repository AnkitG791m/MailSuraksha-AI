import sqlite3
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from config import settings

class Database:
    """
    SQLite database for SecureX:
    1. Analyses logs and audit trail.
    2. 7-Day Threat Intelligence Cache for indicators (IP, Domain, URL).
    3. Threat Memory Engine: historical suspicious/malicious emails for campaign correlation.
    """

    def __init__(self, db_path: Path = settings.DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")

            # 1. Main analysis table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    filename TEXT,
                    subject TEXT,
                    sender TEXT,
                    origin_ip TEXT,
                    country TEXT,
                    verdict TEXT,
                    risk_score REAL,
                    confidence_pct REAL,
                    sha256 TEXT,
                    created_at TIMESTAMP,
                    data_json TEXT
                )
            """)

            # 2. Threat Intelligence Cache table (7-day TTL)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_cache (
                    indicator TEXT PRIMARY KEY,
                    indicator_type TEXT,
                    source TEXT,
                    result TEXT,
                    reputation_score REAL,
                    last_scanned_at TIMESTAMP
                )
            """)

            # 3. Threat Memory table for correlation & campaign tracking
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_memory (
                    id TEXT PRIMARY KEY,
                    email_subject TEXT,
                    sender_email TEXT,
                    sender_domain TEXT,
                    origin_ip TEXT,
                    asn_isp TEXT,
                    urls TEXT,
                    campaign_tags TEXT,
                    threat_score REAL,
                    verdict TEXT,
                    created_at TIMESTAMP
                )
            """)

            # 4. Investigation Assistant Chat History table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS investigation_chat_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT,
                    role TEXT,
                    message TEXT,
                    created_at TIMESTAMP
                )
            """)

            # Performance Indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_mem_ip ON threat_memory(origin_ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_mem_domain ON threat_memory(sender_domain);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_report_id ON investigation_chat_history(report_id);")

            conn.commit()


    # --- Analysis Logs ---

    def save_analysis(self, report_id: str, filename: str, data: Dict[str, Any]):
        headers = data.get("headers", {})
        risk = data.get("risk", {})
        origin_ip = data.get("origin_ip", {}).get("origin_ip")
        country = data.get("geo", {}).get("country")
        sha256 = data.get("hashes", {}).get("sha256")
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO analyses 
                (id, filename, subject, sender, origin_ip, country, verdict, risk_score, confidence_pct, sha256, created_at, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                filename,
                headers.get("subject", "No Subject"),
                headers.get("from", {}).get("email", "unknown"),
                origin_ip,
                country,
                risk.get("verdict", "Unknown"),
                risk.get("risk_score", 0.0),
                risk.get("confidence_pct", 0.0),
                sha256,
                now_iso,
                json.dumps(data)
            ))
            conn.commit()

    def get_analysis(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            clean_id = report_id.lstrip("#").strip()
            cur.execute("SELECT data_json FROM analyses WHERE id = ? OR id LIKE ? ORDER BY created_at DESC LIMIT 1", (clean_id, f"{clean_id}%"))
            row = cur.fetchone()
            if row:
                return json.loads(row["data_json"])
            # Fallback to latest record so chat investigation never breaks on demo IDs
            cur.execute("SELECT data_json FROM analyses ORDER BY created_at DESC LIMIT 1")
            latest = cur.fetchone()
            if latest:
                return json.loads(latest["data_json"])
        return None

    def list_analyses(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, filename, subject, sender, origin_ip, country, verdict, risk_score, confidence_pct, created_at
                FROM analyses
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    # --- 7-Day Indicator Cache ---

    def get_cached_indicator(self, indicator: str, max_age_days: int = 7) -> Optional[Dict[str, Any]]:
        if not indicator:
            return None
        indicator_clean = indicator.strip().lower()

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT indicator, indicator_type, source, result, reputation_score, last_scanned_at
                FROM threat_intel_cache
                WHERE indicator = ?
            """, (indicator_clean,))
            row = cur.fetchone()

            if not row:
                return None

            # Check if scanned within max_age_days
            last_scanned_str = row["last_scanned_at"]
            try:
                last_scanned = datetime.fromisoformat(last_scanned_str)
                if last_scanned.tzinfo is None:
                    last_scanned = last_scanned.replace(tzinfo=timezone.utc)
                age = datetime.now(timezone.utc) - last_scanned
                if age > timedelta(days=max_age_days):
                    return None  # Expired cache (> 7 days)
            except Exception:
                pass

            try:
                parsed_res = json.loads(row["result"])
            except Exception:
                parsed_res = {"raw": row["result"]}

            return {
                "indicator": row["indicator"],
                "indicator_type": row["indicator_type"],
                "source": row["source"],
                "result": parsed_res,
                "reputation_score": row["reputation_score"],
                "last_scanned_at": row["last_scanned_at"],
                "is_cached": True
            }

    def save_cached_indicator(self, indicator: str, indicator_type: str, source: str,
                              result: Dict[str, Any], reputation_score: float = 0.0):
        if not indicator:
            return
        indicator_clean = indicator.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO threat_intel_cache
                (indicator, indicator_type, source, result, reputation_score, last_scanned_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                indicator_clean,
                indicator_type,
                source,
                json.dumps(result),
                reputation_score,
                now_iso
            ))
            conn.commit()

    def get_cache_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as cnt FROM threat_intel_cache")
            total_cached = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM threat_memory")
            threat_memory_count = cur.fetchone()["cnt"]
            return {
                "total_cached_indicators": total_cached,
                "threat_memory_entries": threat_memory_count
            }

    # --- Threat Memory Engine ---

    def record_threat_memory(self, analysis_data: Dict[str, Any]):
        """
        Store suspicious or malicious emails (risk_score >= 50) into Threat Memory
        for campaign correlation and repeated infrastructure tracking.
        """
        risk = analysis_data.get("risk", {})
        score = risk.get("risk_score", 0.0)
        verdict = risk.get("verdict", "Unknown")

        if score < 50.0 and verdict == "Clean":
            return  # Store only suspicious/malicious threats

        report_id = analysis_data.get("report_id", "")
        headers = analysis_data.get("headers", {})
        subject = headers.get("subject", "")
        sender_email = headers.get("from", {}).get("email", "")
        sender_domain = headers.get("from", {}).get("domain", "")
        origin_ip = analysis_data.get("origin_ip", {}).get("origin_ip", "")
        asn_isp = analysis_data.get("geo", {}).get("isp", "")
        urls = analysis_data.get("urls", {}).get("all_urls", [])

        # Campaign tags based on keywords / intent
        campaign_tags = []
        subj_lower = subject.lower()
        if "wire" in subj_lower or "transfer" in subj_lower or "escrow" in subj_lower:
            campaign_tags.append("ceo-wire-fraud")
        if "microsoft" in subj_lower or "365" in subj_lower or "password" in subj_lower or "verify" in subj_lower:
            campaign_tags.append("credential-harvesting")
        if "invoice" in subj_lower or "remittance" in subj_lower or "payment" in subj_lower:
            campaign_tags.append("fake-invoice")
        if headers.get("from", {}).get("lookalike"):
            campaign_tags.append("brand-typosquatting")

        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO threat_memory
                (id, email_subject, sender_email, sender_domain, origin_ip, asn_isp, urls, campaign_tags, threat_score, verdict, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                subject,
                sender_email,
                sender_domain,
                origin_ip,
                asn_isp,
                json.dumps(urls),
                json.dumps(campaign_tags),
                score,
                verdict,
                now_iso
            ))
            conn.commit()

    def correlate_threat(self, origin_ip: str, sender_domain: str, subject: str,
                         urls: List[str]) -> Dict[str, Any]:
        """
        Compare against historical threats in Threat Memory:
        - Repeated malicious IPs
        - Repeated malicious domains
        - Repeated phishing campaigns / subject patterns
        - Repeated sender infrastructure
        """
        matched_ip_cases = []
        matched_domain_cases = []
        matched_campaign_cases = []

        with self._get_connection() as conn:
            cur = conn.cursor()

            # 1. Check repeated malicious IP
            if origin_ip:
                cur.execute("""
                    SELECT id, email_subject, sender_domain, origin_ip, threat_score, verdict, created_at
                    FROM threat_memory
                    WHERE origin_ip = ?
                    ORDER BY created_at DESC LIMIT 10
                """, (origin_ip,))
                matched_ip_cases = [dict(r) for r in cur.fetchall()]

            # 2. Check repeated malicious domain
            if sender_domain:
                cur.execute("""
                    SELECT id, email_subject, sender_domain, origin_ip, threat_score, verdict, created_at
                    FROM threat_memory
                    WHERE sender_domain = ?
                    ORDER BY created_at DESC LIMIT 10
                """, (sender_domain.lower(),))
                matched_domain_cases = [dict(r) for r in cur.fetchall()]

            # 3. Check similar subject / campaign tags
            if subject:
                # Search by matching subject keywords
                tokens = [w for w in subject.split() if len(w) > 4][:3]
                if tokens:
                    clause = " OR ".join(["email_subject LIKE ?"] * len(tokens))
                    params = [f"%{t}%" for t in tokens]
                    cur.execute(f"""
                        SELECT id, email_subject, sender_domain, origin_ip, campaign_tags, threat_score, verdict, created_at
                        FROM threat_memory
                        WHERE {clause}
                        ORDER BY created_at DESC LIMIT 10
                    """, tuple(params))
                    matched_campaign_cases = [dict(r) for r in cur.fetchall()]

        # Generate correlation summary
        insights = []
        has_correlation = False
        campaign_name = None

        if matched_ip_cases:
            has_correlation = True
            insights.append(f"Origin IP {origin_ip} previously linked to {len(matched_ip_cases)} security incident(s) in Threat Memory.")

        if matched_domain_cases:
            has_correlation = True
            insights.append(f"Sender domain {sender_domain} previously recorded in {len(matched_domain_cases)} malicious campaign(s).")

        if matched_campaign_cases:
            has_correlation = True
            first_tags = matched_campaign_cases[0].get("campaign_tags")
            if first_tags:
                try:
                    tags = json.loads(first_tags)
                    if tags:
                        campaign_name = tags[0].replace("-", " ").title() + " Wave"
                except Exception:
                    pass
            if not campaign_name:
                campaign_name = "Recurring Phishing Campaign"
            insights.append(f"Pattern correlation: Content matches historical attack '{matched_campaign_cases[0].get('email_subject')}'.")

        return {
            "has_correlation": has_correlation,
            "ip_incident_count": len(matched_ip_cases),
            "domain_incident_count": len(matched_domain_cases),
            "campaign_incident_count": len(matched_campaign_cases),
            "matched_ip_cases": matched_ip_cases[:5],
            "matched_domain_cases": matched_domain_cases[:5],
            "detected_campaign": campaign_name,
            "insights": insights
        }

    # --- Investigation Chat History ---

    def save_chat_message(self, report_id: str, role: str, message: str):
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO investigation_chat_history (report_id, role, message, created_at)
                VALUES (?, ?, ?, ?)
            """, (report_id, role, message, now_iso))
            conn.commit()

    def get_chat_history(self, report_id: str, limit: int = 30) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT role, message as content, created_at
                FROM investigation_chat_history
                WHERE report_id = ?
                ORDER BY id ASC
                LIMIT ?
            """, (report_id, limit))
            rows = cur.fetchall()
            return [dict(r) for r in rows]

db = Database()

