from typing import Dict, Any, List
from database import db

class ThreatMemoryEngine:
    """
    Threat Memory Engine.
    Tracks historical suspicious & high-risk emails.
    Identifies:
    - Repeated attacker IPs
    - Repeated malicious sender domains
    - Linked phishing campaign waves
    - Repeated fraudulent infrastructure
    """

    def __init__(self):
        pass

    def correlate(self, origin_ip: str, sender_domain: str, subject: str,
                  urls: List[str]) -> Dict[str, Any]:
        return db.correlate_threat(
            origin_ip=origin_ip,
            sender_domain=sender_domain,
            subject=subject,
            urls=urls
        )

    def record(self, analysis_data: Dict[str, Any]):
        db.record_threat_memory(analysis_data)

threat_memory_engine = ThreatMemoryEngine()
