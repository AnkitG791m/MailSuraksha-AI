import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# In-memory WHOIS cache {domain: (timestamp, data)}
_WHOIS_CACHE: Dict[str, tuple] = {}
CACHE_TTL = 86400  # 24 hours


class WhoisLookup:
    """
    Step 5: WHOIS Lookup & Domain Age Analysis.
    Performs WHOIS queries on domains, calculates age in days,
    flags domains younger than 30 days (< 30 days is a primary phishing indicator).
    Includes caching and graceful error/timeout handling.
    """

    def __init__(self, domain: str):
        self.domain = domain.lower().strip() if domain else ""

    def lookup(self) -> Dict[str, Any]:
        if not self.domain:
            return {
                "domain": "",
                "status": "skipped",
                "error": "No domain provided",
                "is_young": False,
                "age_days": None
            }

        # Check cache
        now_ts = time.time()
        if self.domain in _WHOIS_CACHE:
            cached_ts, cached_res = _WHOIS_CACHE[self.domain]
            if now_ts - cached_ts < CACHE_TTL:
                return cached_res

        if not WHOIS_AVAILABLE:
            res = {
                "domain": self.domain,
                "status": "unavailable",
                "error": "python-whois library not installed",
                "is_young": False,
                "age_days": None,
                "registrar": None,
                "creation_date": None
            }
            _WHOIS_CACHE[self.domain] = (now_ts, res)
            return res

        try:
            w = whois.whois(self.domain)
            creation_date = self._extract_date(w.creation_date)
            expiration_date = self._extract_date(w.expiration_date)
            updated_date = self._extract_date(w.updated_date)

            age_days = None
            is_young = False

            if creation_date:
                now_utc = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    # Assume UTC if naive
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age_delta = now_utc - creation_date
                age_days = max(0, age_delta.days)
                is_young = age_days < 30

            registrar = w.registrar
            if isinstance(registrar, list):
                registrar = registrar[0] if registrar else None

            res = {
                "domain": self.domain,
                "status": "success",
                "registrar": registrar,
                "creation_date": creation_date.isoformat() if creation_date else None,
                "expiration_date": expiration_date.isoformat() if expiration_date else None,
                "updated_date": updated_date.isoformat() if updated_date else None,
                "age_days": age_days,
                "is_young": is_young,
                "name_servers": list(w.name_servers) if w.name_servers else [],
                "emails": w.emails if hasattr(w, "emails") else None,
                "org": w.org if hasattr(w, "org") else None,
                "error": None
            }
        except Exception as exc:
            # WHOIS can fail on unknown TLDs, rate limits, or connection refused
            res = {
                "domain": self.domain,
                "status": "error",
                "error": str(exc),
                "registrar": None,
                "creation_date": None,
                "age_days": None,
                "is_young": False
            }

        _WHOIS_CACHE[self.domain] = (now_ts, res)
        return res

    def _extract_date(self, date_val: Any) -> Optional[datetime]:
        if not date_val:
            return None
        if isinstance(date_val, list):
            date_val = date_val[0]
        if isinstance(date_val, datetime):
            return date_val
        if isinstance(date_val, str):
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
                try:
                    return datetime.strptime(date_val, fmt)
                except ValueError:
                    continue
        return None
