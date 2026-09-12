import re
import ipaddress
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any, Optional
from config import settings


class OriginIPExtractor:
    """
    Step 4: Relay Chain Anomaly Assessment & Candidate Origin IP Attribution.
    
    Forensic Principles:
    1. Received headers are inherently untrusted input. The engine does NOT claim to definitively
       prove forged hops from headers alone, but instead assesses header anomalies, syntax consistency,
       and chronological monotonicity.
    2. Inbound relay trustworthiness is evaluated against an explicit configurable trust model:
       configured organizational relays, known mail provider infrastructure, and TLS/auth context.
    3. Origin IPs are classified as 'candidate_origin_ip' representing probabilistic network routing leads,
       strictly separated from human physical identity.
    """

    def __init__(self, received_hops: List[Dict[str, Any]], auth_context: Optional[Dict[str, Any]] = None):
        self.received_hops = received_hops or []
        self.auth_context = auth_context or {}
        self.trusted_relays = [r.strip() for r in getattr(settings, "TRUSTED_RELAYS", [])]
        self.trusted_providers = [p.lower() for p in getattr(settings, "TRUSTED_PROVIDER_DOMAINS", [])]

    def extract(self) -> Dict[str, Any]:
        all_public_ips = []
        hop_evaluations = []
        internal_hops = 0

        header_anomalies = []
        forgery_indicators = []

        earliest_observed_ip = None
        first_trusted_relay_info = None
        candidate_origin_ip = None

        # Chronological order: Top hop (0) is recipient MTA (latest),
        # Bottom hop (N-1) is earliest recorded hop.
        chronological_hops = list(reversed(self.received_hops))
        total_hops = len(chronological_hops)

        previous_hop_dt = None

        for idx, hop in enumerate(chronological_hops):
            raw_text = hop.get("raw", "")
            from_host = hop.get("from_host", "")
            by_host = hop.get("by_host", "")
            date_raw = hop.get("timestamp", "") or hop.get("date_raw", "")
            ips = self._find_ips_in_text(raw_text)

            # Parse hop timestamp for monotonic consistency checking
            hop_dt = self._parse_hop_date(date_raw)
            if hop_dt and previous_hop_dt:
                # If current hop is older than previous hop by more than 300 seconds, flag clock inversion
                time_diff_sec = (hop_dt - previous_hop_dt).total_seconds()
                if time_diff_sec < -300:
                    anomaly_msg = f"Non-monotonic timestamp detected: Hop {idx+1} timestamp precedes previous hop by {abs(int(time_diff_sec))}s"
                    header_anomalies.append({
                        "hop_index": idx + 1,
                        "type": "timestamp_inversion",
                        "description": anomaly_msg
                    })
                    forgery_indicators.append("non_monotonic_timestamp")
            if hop_dt:
                previous_hop_dt = hop_dt

            hop_public_ips = []
            hop_private_ips = []
            for ip_str in ips:
                if self._is_routable_ip(ip_str):
                    hop_public_ips.append(ip_str)
                    if ip_str not in all_public_ips:
                        all_public_ips.append(ip_str)
                else:
                    hop_private_ips.append(ip_str)

            # Evaluate Relay Trust Basis under configurable trust model
            is_earliest = (idx == 0)
            is_latest = (idx == total_hops - 1)
            trust_basis = []
            trust_level = "untrusted"

            for pub_ip in hop_public_ips:
                # 1. Configured organizational relay check
                if self._matches_trusted_relays(pub_ip):
                    trust_basis.append("configured_org_relay")
                    trust_level = "high"
                    break

            # 2. Known provider infrastructure check (by_host / from_host)
            combined_hosts = f"{from_host} {by_host}".lower()
            for provider_domain in self.trusted_providers:
                if provider_domain in combined_hosts:
                    if "provider_metadata" not in trust_basis:
                        trust_basis.append("provider_metadata")
                    if trust_level != "high":
                        trust_level = "medium"
                    break

            # 3. Authentication context
            if "with esmtps" in raw_text.lower() or "tls" in raw_text.lower():
                if "authentication_context" not in trust_basis:
                    trust_basis.append("authentication_context")

            if is_latest:
                if "configured_org_relay" not in trust_basis:
                    trust_basis.append("recipient_boundary_mta")
                trust_level = "high"
            elif is_earliest and not trust_basis:
                trust_level = "untrusted"

            if not hop_public_ips:
                internal_hops += 1
                is_public = False
            else:
                is_public = True
                if earliest_observed_ip is None:
                    earliest_observed_ip = hop_public_ips[0]

                # Identify first relay meeting configured trust criteria
                if first_trusted_relay_info is None and trust_level in ("high", "medium") and not is_earliest:
                    first_trusted_relay_info = {
                        "ip": hop_public_ips[0],
                        "trust_basis": trust_basis,
                        "trust_level": trust_level,
                        "hop_index": idx + 1
                    }

            hop_evaluations.append({
                "hop_index": idx + 1,
                "chronological_order": "oldest_to_newest",
                "from_host": from_host or "unspecified",
                "by_host": by_host or "unspecified",
                "timestamp": date_raw or "unspecified",
                "is_public": is_public,
                "public_ips": hop_public_ips,
                "private_ips": hop_private_ips,
                "trust_basis": trust_basis,
                "trust_level": trust_level,
                "raw_snippet": (raw_text[:120] + "...") if len(raw_text) > 120 else raw_text
            })

        # Assess Header Forgery Indicators
        if not header_anomalies:
            forgery_assessment = "no_obvious_anomaly"
        elif len(header_anomalies) == 1:
            forgery_assessment = "anomalies_detected"
        else:
            forgery_assessment = "likely_untrusted"

        # Candidate Origin Infrastructure Attribution
        limitations = [
            "Network routing leads represent probabilistic candidate infrastructure, NOT proof of physical identity.",
            "Intermediate hops may reflect commercial VPN egress, cloud carrier relays, or multi-tenant hosting."
        ]

        if first_trusted_relay_info and earliest_observed_ip:
            candidate_origin_ip = earliest_observed_ip
            candidate_attribution_confidence = 0.70
            attribution_status = "candidate_investigative_lead"
        elif earliest_observed_ip:
            candidate_origin_ip = earliest_observed_ip
            candidate_attribution_confidence = 0.55
            attribution_status = "single_hop_unverified"
            limitations.append("Only a single public hop observed; high likelihood of direct-to-MX transmission or gateway injection.")
        elif all_public_ips:
            candidate_origin_ip = all_public_ips[0]
            candidate_attribution_confidence = 0.45
            attribution_status = "fallback_relay"
        else:
            candidate_origin_ip = None
            candidate_attribution_confidence = 0.0
            attribution_status = "internal_only"
            limitations.append("Message originated entirely on internal or RFC 1918 private network space.")

        first_relay_ip = first_trusted_relay_info["ip"] if first_trusted_relay_info else (candidate_origin_ip or "N/A")

        origin_assessment = {
            "status": attribution_status,
            "candidate_origin_ip": candidate_origin_ip,
            "probable_origin_ip": candidate_origin_ip,  # Backward compatibility
            "earliest_observed_ip": earliest_observed_ip,
            "first_trusted_relay_ip": first_relay_ip,
            "first_trusted_relay": first_trusted_relay_info or {
                "ip": first_relay_ip,
                "trust_basis": ["unspecified_boundary"],
                "trust_level": "low"
            },
            "header_anomalies": header_anomalies,
            "forgery_indicators": list(set(forgery_indicators)),
            "forgery_assessment": forgery_assessment,
            "candidate_attribution_confidence": candidate_attribution_confidence,
            "confidence_pct": int(candidate_attribution_confidence * 100),
            "limitations": limitations,
            "disclaimer": "Probabilistic network routing lead for examiner triage. Conclusive attribution requires judicial subpoena of ISP subscriber logs."
        }

        return {
            "origin_ip": candidate_origin_ip,
            "candidate_origin_ip": candidate_origin_ip,
            "earliest_observed_ip": earliest_observed_ip,
            "first_trusted_relay_ip": first_relay_ip,
            "first_trusted_relay": first_trusted_relay_info or {
                "ip": first_relay_ip,
                "trust_basis": ["unspecified_boundary"],
                "trust_level": "low"
            },
            "header_anomalies": header_anomalies,
            "forgery_indicators": list(set(forgery_indicators)),
            "forgery_assessment": forgery_assessment,
            "origin_assessment": origin_assessment,
            "hop_evaluations": hop_evaluations,
            "all_public_ips": all_public_ips,
            "total_hops": total_hops,
            "internal_hops_count": internal_hops,
            "candidate_attribution_confidence": candidate_attribution_confidence,
            "confidence": "high" if candidate_attribution_confidence >= 0.7 else ("medium" if candidate_attribution_confidence >= 0.5 else "low"),
            "confidence_score": candidate_attribution_confidence,
            "explanation": (
                f"Candidate origin infrastructure {candidate_origin_ip} derived from Received header traversal (Candidate Confidence: {int(candidate_attribution_confidence*100)}%)."
                if candidate_origin_ip else "No external public relay IP detected in message envelope."
            )
        }

    def _matches_trusted_relays(self, ip_str: str) -> bool:
        """Checks if an IP matches any configured CIDR or IP in TRUSTED_RELAYS."""
        if not ip_str:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for rule in self.trusted_relays:
                try:
                    if "/" in rule:
                        if ip_obj in ipaddress.ip_network(rule, strict=False):
                            return True
                    else:
                        if ip_obj == ipaddress.ip_address(rule):
                            return True
                except ValueError:
                    continue
        except ValueError:
            return False
        return False

    def _parse_hop_date(self, date_str: str) -> Optional[datetime]:
        """Extracts date object from Received header timestamp."""
        if not date_str:
            return None
        # Often after ';' in Received header
        if ";" in date_str:
            date_str = date_str.split(";")[-1].strip()
        try:
            return parsedate_to_datetime(date_str)
        except Exception:
            return None

    def _find_ips_in_text(self, text: str) -> List[str]:
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        return re.findall(ipv4_pattern, text)

    def _is_routable_ip(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified:
                return False
            if ip_str.startswith("0.") or ip_str.startswith("127."):
                return False
            # Check standard private / non-routable address space (RFC 1918, RFC 6598 CGNAT)
            rfc1918 = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
                ipaddress.ip_network("100.64.0.0/10"),
            ]
            if any(ip_obj in net for net in rfc1918):
                return False
            return True
        except ValueError:
            return False
