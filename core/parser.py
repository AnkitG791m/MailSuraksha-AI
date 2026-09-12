import re
import hashlib
import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".jar", ".iso",
    ".img", ".dmg", ".pif", ".cpl", ".msc", ".docm", ".xlsm",
    ".pptm", ".dotm", ".xltm", ".potm"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "goo.gl", "rebrand.ly", "t.ly", "rotf.lol", "shorturl.at"
}

PROTECTED_BRANDS = [
    "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
    "netflix.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "dhl.com",
    "fedex.com", "dropbox.com", "linkedin.com", "facebook.com", "instagram.com",
    "github.com", "adobe.com", "yahoo.com", "outlook.com", "office.com"
]

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def detect_lookalike_domain(domain: str) -> Optional[Dict[str, Any]]:
    if not domain:
        return None
    d_clean = domain.lower().strip()
    for brand in PROTECTED_BRANDS:
        if d_clean == brand:
            return None
        dist = levenshtein_distance(d_clean, brand)
        b_name = brand.split(".")[0]
        d_name = d_clean.split(".")[0]
        name_dist = levenshtein_distance(d_name, b_name) if len(d_name) > 3 else 99
        
        if (dist <= 2 and len(d_clean) >= 5) or (name_dist <= 1 and len(d_name) >= 4 and d_name != b_name):
            return {
                "flagged_domain": domain,
                "target_brand": brand,
                "edit_distance": min(dist, name_dist),
                "is_spoofed_lookalike": True
            }
        if b_name in d_clean and d_clean != brand:
            return {
                "flagged_domain": domain,
                "target_brand": brand,
                "edit_distance": 0,
                "is_spoofed_lookalike": True,
                "brand_impersonation": True
            }
    return None

URL_REGEX = re.compile(
    r'(?:https?://|www\.)[a-zA-Z0-9_\.\-]+(?:\:[0-9]+)?(?:/[^\s<>"\'\)]*)?',
    re.IGNORECASE
)

class EmailParser:
    """
    Forensic Email Parser:
    Extracts headers, Received hops, plain/html body, attachments, embedded URLs,
    and checks for link spoofing (mismatched display anchor vs href).
    """

    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    def parse_all(self) -> Dict[str, Any]:
        headers = self.get_headers()
        received_hops = self.get_received_chain()
        body_data = self.get_body()
        attachments = self.get_attachments()
        urls_data = self.extract_urls(body_data["html"], body_data["text"])
        
        # Calculate SHA256 of raw email for chain of custody
        sha256_hash = hashlib.sha256(self.raw_bytes).hexdigest()
        md5_hash = hashlib.md5(self.raw_bytes).hexdigest()

        return {
            "hashes": {
                "sha256": sha256_hash,
                "md5": md5_hash,
                "size_bytes": len(self.raw_bytes)
            },
            "headers": headers,
            "received_chain": received_hops,
            "body": body_data,
            "attachments": attachments,
            "urls": urls_data,
            "raw_headers": self.get_raw_headers_str()
        }

    def get_headers(self) -> Dict[str, Any]:
        from_header = str(self.msg.get("From", ""))
        from_name, from_email = parseaddr(from_header)
        from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""

        reply_to_header = str(self.msg.get("Reply-To", ""))
        reply_to_name, reply_to_email = parseaddr(reply_to_header)
        reply_to_domain = reply_to_email.split("@")[-1].lower() if "@" in reply_to_email else ""

        to_header = str(self.msg.get("To", ""))
        to_list = [{"name": name, "email": addr} for name, addr in getaddresses([to_header])]

        cc_header = str(self.msg.get("Cc", ""))
        cc_list = [{"name": name, "email": addr} for name, addr in getaddresses([cc_header])]

        return_path = str(self.msg.get("Return-Path", "")).strip("<> ")
        return_path_domain = return_path.split("@")[-1].lower() if "@" in return_path else ""

        subject = str(self.msg.get("Subject", ""))
        date = str(self.msg.get("Date", ""))
        message_id = str(self.msg.get("Message-ID", "")).strip()

        # Flags for quick inspection
        mismatched_reply_to = bool(
            reply_to_email and from_email and (reply_to_email.lower() != from_email.lower())
        )
        mismatched_return_path = bool(
            return_path and from_domain and (return_path_domain != from_domain)
        )

        lookalike_info = detect_lookalike_domain(from_domain)

        return {
            "from": {
                "raw": from_header,
                "name": from_name,
                "email": from_email,
                "domain": from_domain,
                "lookalike": lookalike_info
            },
            "to": to_list,
            "cc": cc_list,
            "reply_to": {
                "raw": reply_to_header,
                "name": reply_to_name,
                "email": reply_to_email,
                "domain": reply_to_domain,
                "mismatch_with_from": mismatched_reply_to
            },
            "return_path": {
                "raw": return_path,
                "domain": return_path_domain,
                "mismatch_with_from": mismatched_return_path
            },
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "auth_results": str(self.msg.get("Authentication-Results", "")),
            "received_spf": str(self.msg.get("Received-SPF", "")),
            "dkim_signature": str(self.msg.get("DKIM-Signature", ""))
        }

    def get_received_chain(self) -> List[Dict[str, Any]]:
        """
        Extracts all Received headers. In RFC 5322, the top-most Received header
        is the latest hop, and the bottom-most is the earliest hop.
        """
        raw_received = self.msg.get_all("Received", [])
        hops = []
        
        # Order: 0 is topmost (latest), len-1 is bottommost (earliest/origin)
        for idx, hop_str in enumerate(raw_received):
            hop_str_clean = " ".join(str(hop_str).split())
            
            # Extract IPs found in this hop
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', hop_str_clean)
            
            # Attempt to parse 'from', 'by', 'with', 'id', 'for'
            from_match = re.search(r'from\s+([^\s;]+)', hop_str_clean, re.IGNORECASE)
            by_match = re.search(r'by\s+([^\s;]+)', hop_str_clean, re.IGNORECASE)
            with_match = re.search(r'with\s+([^\s;]+)', hop_str_clean, re.IGNORECASE)
            id_match = re.search(r'id\s+([^\s;]+)', hop_str_clean, re.IGNORECASE)

            hops.append({
                "hop_index": idx,
                "raw": hop_str_clean,
                "ips": ips,
                "from_host": from_match.group(1) if from_match else None,
                "by_host": by_match.group(1) if by_match else None,
                "with_proto": with_match.group(1) if with_match else None,
                "msg_id": id_match.group(1) if id_match else None
            })
            
        return hops

    def get_body(self) -> Dict[str, Any]:
        text_parts = []
        html_parts = []

        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    continue

                payload = part.get_payload(decode=True)
                if not payload:
                    continue

                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="replace")
                except Exception:
                    decoded = payload.decode("utf-8", errors="replace")

                if content_type == "text/plain":
                    text_parts.append(decoded)
                elif content_type == "text/html":
                    html_parts.append(decoded)
        else:
            payload = self.msg.get_payload(decode=True)
            if payload:
                charset = self.msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
                if self.msg.get_content_type() == "text/html":
                    html_parts.append(decoded)
                else:
                    text_parts.append(decoded)

        text_content = "\n".join(text_parts).strip()
        html_content = "\n".join(html_parts).strip()

        # If plain text is empty but HTML exists, strip HTML for NLP analysis
        if not text_content and html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            text_content = soup.get_text(separator=" ", strip=True)

        return {
            "text": text_content,
            "html": html_content,
            "has_html": bool(html_content),
            "has_text": bool(text_content)
        }

    def get_attachments(self) -> List[Dict[str, Any]]:
        attachments = []
        for part in self.msg.walk():
            filename = part.get_filename()
            content_disposition = str(part.get("Content-Disposition", ""))

            if filename or "attachment" in content_disposition:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue

                clean_filename = filename or "unnamed_attachment"
                size = len(payload)
                md5 = hashlib.md5(payload).hexdigest()
                sha256 = hashlib.sha256(payload).hexdigest()
                content_type = part.get_content_type()

                ext = ""
                if "." in clean_filename:
                    ext = "." + clean_filename.rsplit(".", 1)[-1].lower()

                is_dangerous = ext in DANGEROUS_EXTENSIONS

                attachments.append({
                    "filename": clean_filename,
                    "extension": ext,
                    "size_bytes": size,
                    "content_type": content_type,
                    "md5": md5,
                    "sha256": sha256,
                    "is_dangerous": is_dangerous
                })
        return attachments

    def extract_urls(self, html_content: str, text_content: str) -> Dict[str, Any]:
        urls = set()
        mismatched_links = []

        # 1. Parse HTML links and check anchor text vs href
        if html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                anchor_text = a.get_text(strip=True)

                if href.startswith(("http://", "https://")):
                    urls.add(href)
                    
                    # Check for deceptive links: anchor claims a domain, href is different
                    anchor_urls = URL_REGEX.findall(anchor_text)
                    for displayed in anchor_urls:
                        if not displayed.startswith(("http://", "https://")):
                            displayed_url = "http://" + displayed
                        else:
                            displayed_url = displayed

                        try:
                            disp_domain = urlparse(displayed_url).netloc.lower()
                            dest_domain = urlparse(href).netloc.lower()
                            if disp_domain and dest_domain and disp_domain != dest_domain:
                                mismatched_links.append({
                                    "display_text": anchor_text,
                                    "display_domain": disp_domain,
                                    "actual_destination": href,
                                    "destination_domain": dest_domain
                                })
                        except Exception:
                            pass

        # 2. Extract plain text URLs
        if text_content:
            found_urls = URL_REGEX.findall(text_content)
            for u in found_urls:
                if not u.startswith(("http://", "https://")):
                    u = "http://" + u
                urls.add(u)

        # Build unique domains and check for URL shorteners
        domains = set()
        shortened_urls = []
        url_list = list(urls)
        for u in url_list:
            try:
                parsed = urlparse(u)
                netloc = parsed.netloc.split(":")[0].lower()
                if netloc:
                    domains.add(netloc)
                    if netloc in SHORTENER_DOMAINS:
                        shortened_urls.append(u)
            except Exception:
                continue

        return {
            "all_urls": url_list,
            "unique_domains": list(domains),
            "mismatched_links": mismatched_links,
            "shortened_urls": shortened_urls,
            "url_count": len(url_list),
            "has_mismatches": len(mismatched_links) > 0,
            "has_shortened_urls": len(shortened_urls) > 0
        }

    def get_raw_headers_str(self) -> str:
        headers_list = []
        for key, value in self.msg.items():
            headers_list.append(f"{key}: {value}")
        return "\n".join(headers_list)
