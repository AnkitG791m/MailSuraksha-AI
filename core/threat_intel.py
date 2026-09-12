import os
import time
import requests
import threading
from typing import Dict, Any, List, Optional
from config import settings
from database import db

# Thread-safe Key Rotator for VirusTotal API
class VTKeyRotator:
    """
    Manages a pool of VirusTotal API keys with:
    - Round-robin usage
    - Automatic failover upon HTTP 429 (Rate Limit Exceeded)
    - Request tracking and statistics
    - Cooldown and exhaust detection
    - Exponential backoff
    """
    def __init__(self, keys: List[str]):
        self.keys = [k.strip() for k in keys if k.strip()]
        self.current_idx = 0
        self.lock = threading.Lock()
        self.stats = {
            i: {
                "key_mask": f"{k[:6]}...{k[-4:]}" if len(k) >= 10 else "invalid",
                "requests_count": 0,
                "rate_limit_hits_429": 0,
                "last_used": None,
                "status": "active"
            }
            for i, k in enumerate(self.keys)
        }

    def get_active_key(self) -> Optional[str]:
        with self.lock:
            if not self.keys:
                return None
            return self.keys[self.current_idx]

    def rotate_on_429(self) -> Optional[str]:
        with self.lock:
            if not self.keys:
                return None
            old_idx = self.current_idx
            self.stats[old_idx]["rate_limit_hits_429"] += 1
            self.stats[old_idx]["status"] = "rate_limited_429"

            # Advance to next key
            self.current_idx = (self.current_idx + 1) % len(self.keys)
            new_idx = self.current_idx
            self.stats[new_idx]["status"] = "active"
            print(f"[VTKeyRotator] HTTP 429 on Key #{old_idx + 1} ({self.stats[old_idx]['key_mask']}). Rotated to Key #{new_idx + 1} ({self.stats[new_idx]['key_mask']}).")
            return self.keys[self.current_idx]

    def record_request(self, idx: int):
        with self.lock:
            if idx in self.stats:
                self.stats[idx]["requests_count"] += 1
                self.stats[idx]["last_used"] = time.strftime("%Y-%m-%d %H:%M:%S")

    def get_telemetry(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "total_keys": len(self.keys),
                "active_key_index": self.current_idx + 1 if self.keys else 0,
                "keys_stats": list(self.stats.values())
            }


# Initialize singleton rotator with keys from settings
vt_rotator = VTKeyRotator(settings.VIRUSTOTAL_API_KEYS)


class ThreatIntelAggregator:
    """
    Production-Ready Threat Intelligence Engine.
    Executes selective, multi-layer enrichment in priority order:
    1. Local Threat Database (Threat Memory)
    2. 7-Day SQLite Indicator Cache
    3. AbuseIPDB
    4. AlienVault OTX
    5. VirusTotal (Final enrichment, only when score > 70, with multi-key rotation)
    
    Trigger Rules:
    - Local Risk Score < 50: Zero external API calls!
    - Local Risk Score 50-70: Check 7-day cache; query AbuseIPDB/OTX if miss. Skip VirusTotal.
    - Local Risk Score > 70: Full enrichment including VirusTotal.
    """

    def __init__(self, origin_ip: Optional[str], domains: List[str], urls: List[str],
                 local_risk_score: float = 0.0):
        self.origin_ip = origin_ip.strip() if origin_ip else None
        self.domains = [d.lower().strip() for d in domains if d.strip()]
        self.urls = urls
        self.local_risk_score = local_risk_score

        # Execution telemetry
        self.telemetry = {
            "local_risk_score": local_risk_score,
            "trigger_level": "none",
            "external_apis_called": False,
            "cache_hits": [],
            "cache_misses": [],
            "abuseipdb_queried": False,
            "otx_queried": False,
            "virustotal_queried": False,
            "vt_key_used": None,
            "vt_rotation_active": len(settings.VIRUSTOTAL_API_KEYS) > 1
        }

    def check_all(self) -> Dict[str, Any]:
        # Rule 1: Local Score < 50 -> Skip all external APIs
        if self.local_risk_score < 50.0:
            self.telemetry["trigger_level"] = "low_risk_skipped"
            self.telemetry["reason"] = f"Local score ({self.local_risk_score}/100) < 50. External APIs completely skipped to preserve quotas."
            return {
                "origin_ip_intel": {
                    "target": self.origin_ip,
                    "virustotal": {"status": "skipped (low local risk)", "malicious": 0, "suspicious": 0, "harmless": 0},
                    "abuseipdb": {"status": "skipped (low local risk)", "abuse_score": 0, "total_reports": 0},
                    "alienvault": {"status": "skipped (low local risk)", "pulse_count": 0, "tags": []}
                },
                "domains_intel": {},
                "threat_risk_score": 0,
                "high_threat_detected": False,
                "telemetry": self.telemetry
            }

        # Rule 2: Local Score >= 50 -> External APIs permitted
        self.telemetry["external_apis_called"] = True
        allow_virustotal = (self.local_risk_score > 70.0)

        if allow_virustotal:
            self.telemetry["trigger_level"] = "high_risk_full_enrichment"
        else:
            self.telemetry["trigger_level"] = "medium_risk_selective_enrichment"

        # Check IP
        ip_intel = self._enrich_ip(self.origin_ip, allow_virustotal=allow_virustotal) if self.origin_ip else None

        # Check Top Domain
        domains_intel = {}
        for d in self.domains[:2]:  # Check top 2 domains to conserve API limits
            domains_intel[d] = self._enrich_domain(d, allow_virustotal=allow_virustotal)

        # Calculate composite reputation risk
        rep_score = self._calculate_reputation_score(ip_intel, domains_intel)

        return {
            "origin_ip_intel": ip_intel,
            "domains_intel": domains_intel,
            "threat_risk_score": rep_score,
            "high_threat_detected": rep_score >= 50,
            "telemetry": self.telemetry
        }

    def _enrich_ip(self, ip: str, allow_virustotal: bool) -> Dict[str, Any]:
        # 1. Check 7-Day Indicator Cache in SQLite
        cached = db.get_cached_indicator(ip, max_age_days=settings.CACHE_TTL_DAYS)
        if cached:
            self.telemetry["cache_hits"].append(ip)
            res = cached["result"]
            res["is_cached"] = True
            res["data_mode"] = "CACHED"
            res["last_scanned_at"] = cached.get("last_scanned_at")
            return res

        self.telemetry["cache_misses"].append(ip)

        # 2. Query AbuseIPDB
        abuse_res = self._query_abuseipdb(ip)
        self.telemetry["abuseipdb_queried"] = True

        # 3. Query AlienVault OTX
        otx_res = self._query_alienvault_otx(ip)
        self.telemetry["otx_queried"] = True

        # 4. Query VirusTotal only if High Risk (> 70)
        vt_res = None
        if allow_virustotal:
            vt_res = self._query_virustotal_ip_with_rotation(ip)
            self.telemetry["virustotal_queried"] = True
        else:
            vt_res = {
                "status": "skipped (quota conservation)",
                "data_mode": "SKIPPED",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "reputation": 0
            }

        result = {
            "target": ip,
            "data_mode": "LIVE" if (abuse_res.get("data_mode") == "LIVE" or (vt_res and vt_res.get("data_mode") == "LIVE")) else "FALLBACK",
            "virustotal": vt_res,
            "abuseipdb": abuse_res,
            "alienvault": otx_res,
            "is_cached": False,
            "attribution_disclaimer": "Threat intelligence scores represent observed network infrastructure history; not conclusive physical identity."
        }

        # Calculate score and save to 7-day SQLite cache
        rep = max(
            abuse_res.get("abuse_score", 0),
            (vt_res.get("malicious", 0) * 10) if vt_res else 0,
            (otx_res.get("pulse_count", 0) * 15)
        )
        db.save_cached_indicator(
            indicator=ip,
            indicator_type="ip",
            source="composite",
            result=result,
            reputation_score=rep
        )

        return result

    def _enrich_domain(self, domain: str, allow_virustotal: bool) -> Dict[str, Any]:
        # 1. Check 7-Day Indicator Cache
        cached = db.get_cached_indicator(domain, max_age_days=settings.CACHE_TTL_DAYS)
        if cached:
            self.telemetry["cache_hits"].append(domain)
            res = cached["result"]
            res["is_cached"] = True
            return res

        self.telemetry["cache_misses"].append(domain)

        # 2. Query AlienVault OTX for domain
        otx_res = self._query_alienvault_otx_domain(domain)

        # 3. Query VirusTotal if allowed
        vt_res = None
        if allow_virustotal:
            vt_res = self._query_virustotal_domain_with_rotation(domain)
        else:
            vt_res = {"status": "skipped (quota conservation)", "malicious": 0, "suspicious": 0}

        result = {
            "target": domain,
            "virustotal": vt_res,
            "alienvault": otx_res,
            "is_cached": False
        }

        rep = (vt_res.get("malicious", 0) * 10) if vt_res else 0
        db.save_cached_indicator(
            indicator=domain,
            indicator_type="domain",
            source="composite",
            result=result,
            reputation_score=rep
        )
        return result

    # --- AbuseIPDB ---

    def _query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        api_key = settings.ABUSEIPDB_API_KEY
        if not api_key:
            return {"status": "unconfigured", "abuse_score": 0, "total_reports": 0}

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
            headers = {"Key": api_key, "Accept": "application/json"}
            resp = requests.get(url, headers=headers, params=params, timeout=5.0)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "status": "success (live API)",
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "usage_type": data.get("usageType", "Unknown"),
                    "isp": data.get("isp", ""),
                    "country_code": data.get("countryCode", "")
                }
            elif resp.status_code == 429:
                return {"status": "rate_limited_429", "abuse_score": 0, "total_reports": 0}
        except Exception as e:
            pass

        return {"status": "error_fallback", "abuse_score": 0, "total_reports": 0}

    # --- AlienVault OTX ---

    def _query_alienvault_otx(self, ip: str) -> Dict[str, Any]:
        api_key = settings.ALIENVAULT_OTX_API_KEY
        if not api_key:
            return {"status": "unconfigured", "pulse_count": 0, "tags": []}

        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
            resp = requests.get(url, headers=headers, timeout=5.0)

            if resp.status_code == 200:
                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                tags = []
                for p in pulses[:5]:
                    tags.extend(p.get("tags", []))
                return {
                    "status": "success (live API)",
                    "pulse_count": pulse_info.get("count", 0),
                    "tags": list(set(tags))[:6]
                }
            elif resp.status_code == 429:
                return {"status": "rate_limited_429", "pulse_count": 0, "tags": []}
        except Exception:
            pass

        return {"status": "skipped", "pulse_count": 0, "tags": []}

    def _query_alienvault_otx_domain(self, domain: str) -> Dict[str, Any]:
        api_key = settings.ALIENVAULT_OTX_API_KEY
        if not api_key:
            return {"status": "unconfigured", "pulse_count": 0, "tags": []}

        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
            headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
            resp = requests.get(url, headers=headers, timeout=5.0)
            if resp.status_code == 200:
                pulse_info = resp.json().get("pulse_info", {})
                return {
                    "status": "success (live API)",
                    "pulse_count": pulse_info.get("count", 0)
                }
        except Exception:
            pass

        return {"status": "skipped", "pulse_count": 0}

    # --- VirusTotal Multi-Key Rotator & Backoff ---

    def _query_virustotal_ip_with_rotation(self, ip: str) -> Dict[str, Any]:
        retries = len(vt_rotator.keys)
        backoff = 1.0

        for attempt in range(retries):
            key = vt_rotator.get_active_key()
            if not key:
                return {"status": "unconfigured", "malicious": 0, "suspicious": 0, "harmless": 0}

            curr_idx = vt_rotator.current_idx
            self.telemetry["vt_key_used"] = f"Key #{curr_idx + 1}"

            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {"x-apikey": key, "Accept": "application/json"}
                vt_rotator.record_request(curr_idx)

                resp = requests.get(url, headers=headers, timeout=6.0)

                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attr = data.get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    rep = attr.get("reputation", 0)
                    return {
                        "status": "success (live API)",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "reputation": rep,
                        "key_used": f"Key #{curr_idx + 1}"
                    }
                elif resp.status_code == 429:
                    # Rate limit hit: rotate key and retry with backoff
                    vt_rotator.rotate_on_429()
                    time.sleep(backoff)
                    backoff = min(4.0, backoff * 2)
                    continue
                else:
                    return {"status": f"http_{resp.status_code}", "malicious": 0, "suspicious": 0, "harmless": 0}
            except Exception as exc:
                time.sleep(1.0)
                continue

        # If all keys exhausted, gracefully return without crashing
        return {
            "status": "keys_exhausted_fallback",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "reputation": 0
        }

    def _query_virustotal_domain_with_rotation(self, domain: str) -> Dict[str, Any]:
        retries = len(vt_rotator.keys)
        backoff = 1.0

        for attempt in range(retries):
            key = vt_rotator.get_active_key()
            if not key:
                return {"status": "unconfigured", "malicious": 0, "suspicious": 0, "harmless": 0}

            curr_idx = vt_rotator.current_idx

            try:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                headers = {"x-apikey": key, "Accept": "application/json"}
                vt_rotator.record_request(curr_idx)

                resp = requests.get(url, headers=headers, timeout=6.0)

                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attr = data.get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    rep = attr.get("reputation", 0)
                    return {
                        "status": "success (live API)",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "reputation": rep,
                        "key_used": f"Key #{curr_idx + 1}"
                    }
                elif resp.status_code == 429:
                    vt_rotator.rotate_on_429()
                    time.sleep(backoff)
                    backoff = min(4.0, backoff * 2)
                    continue
                else:
                    return {"status": f"http_{resp.status_code}", "malicious": 0, "suspicious": 0, "harmless": 0}
            except Exception:
                time.sleep(1.0)
                continue

        return {"status": "keys_exhausted_fallback", "malicious": 0, "suspicious": 0, "harmless": 0}

    def _calculate_reputation_score(self, ip_intel: Optional[Dict], domains_intel: Dict[str, Any]) -> int:
        score = 0
        if ip_intel:
            vt = ip_intel.get("virustotal", {})
            abuse = ip_intel.get("abuseipdb", {})
            otx = ip_intel.get("alienvault", {})

            # AbuseIPDB scoring
            abuse_score = abuse.get("abuse_score", 0)
            if abuse_score > 70:
                score += 50
            elif abuse_score > 25:
                score += 25

            # VirusTotal scoring
            vt_mal = vt.get("malicious", 0)
            if vt_mal >= 5:
                score += 45
            elif vt_mal >= 1:
                score += 25

            # OTX scoring
            if otx.get("pulse_count", 0) > 0:
                score += 20

        for d_name, d_data in domains_intel.items():
            vt = d_data.get("virustotal", {})
            if vt.get("malicious", 0) >= 3:
                score += 35

        return min(100, max(0, score))
