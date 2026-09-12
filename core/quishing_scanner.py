import re
import base64
from typing import Dict, Any, List

class QuishingScanner:
    """
    Step 4b: AI Quishing (QR Code Phishing) Detector.
    Scans email body, inline base64 images, and attachments for QR code payloads,
    obfuscated image links, and deceptive redirects designed to bypass text-based spam filters.
    """

    def __init__(self, body_html: str, body_plain: str, attachments: List[Dict[str, Any]], urls: List[str]):
        self.body_html = body_html or ""
        self.body_plain = body_plain or ""
        self.attachments = attachments or []
        self.urls = urls or []

    def scan(self) -> Dict[str, Any]:
        detected_qr_indicators = []
        suspicious_qr_urls = []
        quishing_score = 0

        # 1. Check for QR code keywords & deceptive prompts in email text
        qr_prompt_patterns = [
            r"scan (this|the) qr code",
            r"scan with your (phone|authenticator|mobile)",
            r"qr code to (login|verify|authenticate|update|access)",
            r"microsoft authenticator qr",
            r"2fa qr code",
            r"qr code expires in",
            r"scan to review document"
        ]

        combined_text = (self.body_html + " " + self.body_plain).lower()
        for pat in qr_prompt_patterns:
            if re.search(pat, combined_text):
                detected_qr_indicators.append(f"Deceptive QR prompt detected: '{pat}'")
                quishing_score += 35

        # 2. Check for inline base64 images commonly used to embed QR codes
        base64_images = re.findall(r'src=["\']data:image/[^;]+;base64,([^"\']+)["\']', self.body_html)
        if base64_images:
            for idx, b64_str in enumerate(base64_images):
                # Check image size (QR codes typically 1KB - 200KB)
                approx_bytes = len(b64_str) * 3 // 4
                if 500 < approx_bytes < 300000 and detected_qr_indicators:
                    detected_qr_indicators.append(f"Inline base64 image (approx {approx_bytes // 1024} KB) matching QR payload profile")
                    quishing_score += 25
                    break

        # 3. Check attachment names for QR markers
        for att in self.attachments:
            fn = (att.get("filename") or "").lower()
            if any(q_term in fn for q_term in ["qr", "qrcode", "barcode", "auth_code", "scan_me", "2fa"]):
                detected_qr_indicators.append(f"Suspicious attachment filename: '{fn}'")
                quishing_score += 30

        # 4. Check for high-risk shortened or redirect URLs in body
        redirect_domains = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "qrco.de", "qr.link"]
        for u in self.urls:
            u_low = u.lower()
            if any(rd in u_low for rd in redirect_domains):
                suspicious_qr_urls.append(u)
                quishing_score += 20

        is_quishing = quishing_score >= 35 or len(detected_qr_indicators) >= 2
        risk_level = "High" if quishing_score >= 50 else ("Suspicious" if is_quishing else "Clean")

        return {
            "quishing_detected": is_quishing,
            "confidence_score": min(quishing_score, 100),
            "risk_level": risk_level,
            "indicators": detected_qr_indicators,
            "flagged_urls": suspicious_qr_urls,
            "summary": "QR code phishing (quishing) indicators detected." if is_quishing else "No quishing patterns detected."
        }

quishing_scanner = QuishingScanner("", "", [], [])
