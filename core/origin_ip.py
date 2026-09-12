import re
import ipaddress
from typing import List, Dict, Any, Optional

class OriginIPExtractor:
    """
    Step 4: Origin IP Extractor.
    Walks the Received headers bottom-to-top (chronological order from original sender
    to final recipient MTA), ignores private, loopback, and internal IPs, and returns
    the most likely public Origin IP.
    """

    def __init__(self, received_hops: List[Dict[str, Any]]):
        self.received_hops = received_hops or []

    def extract(self) -> Dict[str, Any]:
        all_public_ips = []
        hop_evaluations = []
        internal_hops = 0

        earliest_observed_ip = None
        first_trusted_relay_ip = None
        probable_origin_ip = None

        # RFC 5322: Received headers are prepended by each MTA.
        # Top (index 0) = Last hop (Internal/Recipient gateway)
        # Bottom (index N-1) = Earliest hop (closest to original sender)
        chronological_hops = list(reversed(self.received_hops))
        total_hops = len(chronological_hops)

        limitations = [
            "Geolocation and network infrastructure attribution represent probabilistic investigative leads.",
            "Attacker may inject synthetic initial Received headers prior to handing message to first public MTA."
        ]

        for idx, hop in enumerate(chronological_hops):
            raw_text = hop.get("raw", "")
            from_host = hop.get("from_host", "")
            by_host = hop.get("by_host", "")
            timestamp = hop.get("timestamp", "")
            date_raw = hop.get("date_raw", "")
            ips = self._find_ips_in_text(raw_text)

            hop_public_ips = []
            hop_private_ips = []
            for ip_str in ips:
                if self._is_routable_ip(ip_str):
                    hop_public_ips.append(ip_str)
                    if ip_str not in all_public_ips:
                        all_public_ips.append(ip_str)
                else:
                    hop_private_ips.append(ip_str)

            # Determine trustworthiness of this hop
            # The earliest hop (idx 0) could be forged by attacker client unless authenticated
            is_earliest = (idx == 0)
            is_latest = (idx == total_hops - 1)
            
            if is_earliest:
                trust_status = "unverified_client"
                trust_reason = "Earliest hop in chain; can be client-generated or synthetic."
            elif is_latest:
                trust_status = "trusted_recipient_mta"
                trust_reason = "Final receiving gateway MTA under local recipient domain control."
            else:
                trust_status = "intermediate_relay"
                trust_reason = "Intermediate network relay; corroborated by receiving server handshake."

            if not hop_public_ips:
                internal_hops += 1
                is_public = False
            else:
                is_public = True
                if earliest_observed_ip is None:
                    earliest_observed_ip = hop_public_ips[0]

                # First trusted relay is the first public MTA that received the transmission
                if first_trusted_relay_ip is None and not is_earliest:
                    first_trusted_relay_ip = hop_public_ips[0]

            hop_evaluations.append({
                "hop_index": idx + 1,
                "chronological_order": "oldest_to_newest",
                "from_host": from_host or "unspecified",
                "by_host": by_host or "unspecified",
                "timestamp": timestamp or date_raw or "unspecified",
                "is_public": is_public,
                "public_ips": hop_public_ips,
                "private_ips": hop_private_ips,
                "trust_status": trust_status,
                "trust_reason": trust_reason,
                "raw_snippet": (raw_text[:120] + "...") if len(raw_text) > 120 else raw_text
            })

        # Forensic Origin Assessment
        # If earliest IP exists and has an intermediate public hop, evaluate confidence
        if first_trusted_relay_ip and earliest_observed_ip:
            probable_origin_ip = earliest_observed_ip
            confidence_score = 0.72
            attribution_status = "probable_investigative_lead"
        elif earliest_observed_ip:
            probable_origin_ip = earliest_observed_ip
            confidence_score = 0.60
            attribution_status = "single_hop_unverified"
            limitations.append("Only a single public hop observed; high possibility of direct-to-MX transmission.")
        elif all_public_ips:
            probable_origin_ip = all_public_ips[0]
            confidence_score = 0.50
            attribution_status = "fallback_relay"
        else:
            probable_origin_ip = None
            confidence_score = 0.0
            attribution_status = "internal_only"
            limitations.append("Message originated entirely on internal or RFC 1918 private network space.")

        origin_assessment = {
            "status": attribution_status,
            "probable_origin_ip": probable_origin_ip,
            "earliest_observed_ip": earliest_observed_ip,
            "first_trusted_relay_ip": first_trusted_relay_ip or probable_origin_ip,
            "confidence_score": confidence_score,
            "confidence_pct": int(confidence_score * 100),
            "limitations": limitations,
            "disclaimer": "Probabilistic attribution signal for investigative triage. Does not prove physical actor identity."
        }

        return {
            "origin_ip": probable_origin_ip,
            "earliest_observed_ip": earliest_observed_ip,
            "first_trusted_relay_ip": first_trusted_relay_ip,
            "origin_assessment": origin_assessment,
            "hop_evaluations": hop_evaluations,
            "all_public_ips": all_public_ips,
            "total_hops": total_hops,
            "internal_hops_count": internal_hops,
            "confidence": "high" if confidence_score >= 0.7 else ("medium" if confidence_score >= 0.5 else "low"),
            "confidence_score": confidence_score,
            "explanation": (
                f"Probable origin IP {probable_origin_ip} derived from chronological Received traversal (Confidence: {int(confidence_score*100)}%)."
                if probable_origin_ip else "No external public relay IP detected in message envelope."
            )
        }

    def _find_ips_in_text(self, text: str) -> List[str]:
        # Match IPv4 addresses
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        matches = re.findall(ipv4_pattern, text)
        return matches

    def _is_routable_ip(self, ip_str: str) -> bool:
        """
        Returns True if the IP is a routable external address.
        Filters out RFC 1918 (10.x, 172.16-31.x, 192.168.x), loopback (127.x),
        link-local (169.254.x), 0.0.0.0, and 255.255.255.255.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified:
                return False
            # Check 0.0.0.0 / broadcast
            if ip_str.startswith("0.") or ip_str.startswith("127."):
                return False
            return True
        except ValueError:
            return False
