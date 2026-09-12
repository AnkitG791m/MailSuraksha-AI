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
        self.received_hops = received_hops

    def extract(self) -> Dict[str, Any]:
        all_public_ips = []
        internal_hops = 0
        origin_ip = None
        origin_hop_info = None

        # RFC 5322 Received headers: top is newest, bottom is oldest.
        # Bottom-to-top means traversing in reverse order (oldest/sender first).
        chronological_hops = list(reversed(self.received_hops))

        for hop in chronological_hops:
            raw_text = hop.get("raw", "")
            ips = self._find_ips_in_text(raw_text)

            hop_public_ips = []
            for ip_str in ips:
                if self._is_routable_ip(ip_str):
                    hop_public_ips.append(ip_str)
                    if ip_str not in all_public_ips:
                        all_public_ips.append(ip_str)

            if not hop_public_ips:
                internal_hops += 1
            elif origin_ip is None:
                origin_ip = hop_public_ips[0]
                origin_hop_info = {
                    "hop_index": hop.get("hop_index"),
                    "raw_hop": raw_text,
                    "from_host": hop.get("from_host"),
                    "by_host": hop.get("by_host"),
                    "with_proto": hop.get("with_proto")
                }

        # Fallback: if no origin found in Received hops, look at any public IP found
        if not origin_ip and all_public_ips:
            origin_ip = all_public_ips[0]

        return {
            "origin_ip": origin_ip,
            "origin_hop": origin_hop_info,
            "all_public_ips": all_public_ips,
            "total_hops": len(self.received_hops),
            "internal_hops_count": internal_hops,
            "confidence": "high" if origin_ip else "none",
            "explanation": (
                f"Extracted public origin IP {origin_ip} from earliest external MTA hop."
                if origin_ip else "No external public IP could be detected in Received headers."
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
