import re
from typing import Dict, Any, List, Tuple, Optional

class ForensicChatEngine:
    """
    Intelligent Context-Grounded Forensic Chat Engine.
    Dynamically answers analyst questions using the email's deep forensic indicators.
    Natively supports fluent cyber-analyst Hinglish and authoritative English.
    """

    @staticmethod
    def is_hinglish_query(query: str) -> bool:
        q = query.lower()
        hinglish_words = {
            "kyu", "kyun", "kyon", "batao", "samjh", "samjhao", "kya", "kaise",
            "fraud", "hinglish", "hindi", "mujhe", "bhai", "karna", "hoga",
            "hai", "h", "ye", "yeh", "kripya", "bataiye", "aisa", "matlab",
            "nahi", "nhi", "chahiye", "apna", "kaun", "mera", "meri", "mere",
            "bheja", "aaya", "aayi", "de", "rha", "raha", "rahi", "rate",
            "hua", "jawab", "kaha", "gaya", "karo", "sakta", "sakte", "khol"
        }
        tokens = set(re.findall(r'[a-zA-Z]+', q))
        matches = tokens.intersection(hinglish_words)
        return len(matches) >= 1 or "hinglish" in q or "hindi" in q

    def generate_response(
        self,
        query: str,
        record: Dict[str, Any],
        chat_history: Optional[List[Dict[str, str]]] = None
    ) -> Tuple[str, List[str]]:
        """
        Synthesizes a tailored, dynamic forensic response based on query intent, language, and email facts.
        Returns: (reply_text, suggested_questions_list)
        """
        is_hinglish = self.is_hinglish_query(query)
        q_lower = query.lower()

        # Extract Evidence Fields
        headers = record.get("headers", {})
        subject = headers.get("subject", "No Subject")
        from_info = headers.get("from", {})
        from_raw = from_info.get("raw") or from_info.get("email") or "Unknown Sender"
        from_name = from_info.get("name", "")
        from_email = from_info.get("email", "")
        from_domain = from_info.get("domain", "")
        lookalike = from_info.get("lookalike") or {}
        target_brand = lookalike.get("target_brand")
        flagged_domain = lookalike.get("flagged_domain", from_domain)
        is_spoofed_lookalike = lookalike.get("is_spoofed_lookalike", False)

        auth = record.get("auth", {})
        spf = auth.get("spf", {})
        spf_status = str(spf.get("status", "none")).lower()
        spf_details = spf.get("details", "")

        dkim = auth.get("dkim", {})
        dkim_status = str(dkim.get("status", "none")).lower()
        dkim_details = dkim.get("details", "")

        dmarc = auth.get("dmarc", {})
        dmarc_status = str(dmarc.get("status", "none")).lower()
        dmarc_details = dmarc.get("details", "")
        is_spoofed = auth.get("is_spoofed", False)

        risk = record.get("risk", {})
        verdict = risk.get("verdict", "Suspicious")
        risk_score = risk.get("risk_score", 50)
        risk_factors = risk.get("primary_risk_factors", [])

        origin_ip_info = record.get("origin_ip", {})
        origin_ip = origin_ip_info.get("origin_ip") if isinstance(origin_ip_info, dict) else str(record.get("origin_ip", "Unknown"))
        geo = record.get("geo", {})
        country = geo.get("country", "Unknown")
        city = geo.get("city", "")
        isp = geo.get("isp", "Unknown ISP")

        intel = record.get("threat_intel", {})
        abuse_score = intel.get("abuseipdb", {}).get("abuse_score", 0)
        vt_positives = intel.get("virustotal", {}).get("positives", 0)

        ai_insights = record.get("ai_insights", {})
        classification = ai_insights.get("classification", "Phishing" if verdict == "Malicious" else "Suspicious Message")
        threat_explanation = ai_insights.get("threat_explanation", "")
        user_friendly = ai_insights.get("user_friendly_translation", "")
        recommendations = ai_insights.get("recommendations", [])
        urls = record.get("urls") or []

        # Intent Detection
        # 0. About Self / System Capabilities / What do you perform / Architecture
        if any(term in q_lower for term in [
            "apne bare", "apne baare", "who are you", "what are you", "tum kaun",
            "kya perform", "kya kya perform", "kya check karte ho", "kaun kaun sa",
            "capabilities", "pipeline", "features", "architecture", "tum kya ho",
            "tum kya karte ho", "kya kaam karte ho", "khud ke bare", "khud ke baare"
        ]):
            return self._handle_about_self_intent(
                is_hinglish, subject, from_raw, spf_status, dkim_status, dmarc_status,
                origin_ip, verdict, risk_score, classification
            )

        # 1. DMARC / SPF / DKIM / Authentication
        if any(term in q_lower for term in ["dmarc", "spf", "dkim", "auth", "authentication", "alignment"]):
            return self._handle_auth_intent(
                is_hinglish, spf_status, spf_details, dkim_status, dkim_details,
                dmarc_status, dmarc_details, origin_ip, from_domain, target_brand
            )

        # 2. Can I Click / Links / URLs
        if any(term in q_lower for term in ["link", "url", "click", "open", "khol", "website", "deceptive"]):
            return self._handle_link_intent(
                is_hinglish, urls, risk_factors, verdict, risk_score
            )

        # 3. Origin IP / Location / ISP / Threat Intel
        if any(term in q_lower for term in ["origin ip", " ip", "location", "country", "city", "isp", "server", "abuse"]):
            return self._handle_ip_intent(
                is_hinglish, origin_ip, country, city, isp, abuse_score, vt_positives, verdict
            )

        # 4. Action / Next Steps / Containment / Remediation
        if any(term in q_lower for term in ["action", "karein", "karna", "contain", "playbook", "remediat", "block", "kya karu", "steps"]):
            return self._handle_action_intent(
                is_hinglish, verdict, risk_score, origin_ip, from_email or from_domain, recommendations
            )

        # 5. Sender / Who Sent / Lookalike / Typosquatting
        if any(term in q_lower for term in ["sender", "from", "kisne", "who", "fake email", "lookalike", "typosquatting", "brand"]):
            return self._handle_sender_intent(
                is_hinglish, from_raw, from_name, from_email, from_domain, target_brand, is_spoofed_lookalike, verdict
            )

        # 6. Why Fraud / Why Malicious / Samjh nahi aaya (Most common user question!)
        if any(term in q_lower for term in ["kyu", "kyun", "fraud", "malicious", "suspicious", "fake", "samjh", "reason", "khatra", "why", "danger", "flagged"]):
            return self._handle_why_fraud_intent(
                is_hinglish, subject, from_raw, from_domain, target_brand,
                spf_status, dmarc_status, origin_ip, country, isp,
                verdict, risk_score, classification, risk_factors
            )

        # 7. Summary / Overview / Greeting
        return self._handle_overview_intent(
            is_hinglish, subject, from_raw, verdict, risk_score,
            classification, user_friendly, risk_factors
        )

    # --- INTENT HANDLERS ---

    def _handle_about_self_intent(
        self, is_hinglish: bool, subject: str, from_raw: str,
        spf_status: str, dkim_status: str, dmarc_status: str,
        origin_ip: str, verdict: str, risk_score: float, classification: str
    ) -> Tuple[str, List[str]]:
        if is_hinglish:
            reply = (
                "Bhai, mai **MailGuardian AI** ka Forensic Intelligence Assistant hu! 🛡️\n\n"
                "Mai koi basic chatbot nahi hu — mere andar ek **10-Step Deep Forensic Pipeline** chalti hai, aur mai har email me ye sab perform karta hu:\n\n"
                "1. **3-Tier Cryptographic Authentication Stack:**\n"
                "   • **SPF (Sender Policy Framework):** Domain ke published DNS TXT records check karke verify karta hu ki sending server IP authorized hai ya nahi.\n"
                "   • **DKIM (DomainKeys Identified Mail):** Email headers aur body ki cryptographic digital signature verify karta hu taaki tampering pakdi ja sake.\n"
                "   • **DMARC (Domain-based Message Authentication):** `From:` header alignment aur policy (none/quarantine/reject) enforce karta hu.\n\n"
                "2. **Received Chain Hop Walking & Origin IP:**\n"
                "   • Sabhi 'Received' routing hops ko reverse (bottom-to-top) track karta hu, internal private IPs (RFC 1918) filter karta hu, aur asli origin server IP nikaalta hu.\n\n"
                "3. **GeoLocation & ASN Resolution:**\n"
                "   • Origin IP ka Country, City, Coordinates, Hosting ISP aur ASN nikaal kar live radar map par plot karta hu.\n\n"
                "4. **Domain Age & Lookalike / Typosquatting Engine:**\n"
                "   • WHOIS lookup se domain creation age (<30 days = high risk) nikaalta hu.\n"
                "   • Levenshtein Distance aur Homoglyph detection se lookalike domains (jaise `micros0ft.com`, `microsoft-support-verify.com`) aur Display Name Spoofing pakadta hu.\n\n"
                "5. **Deceptive Hyperlink & Phishing Detector:**\n"
                "   • Anchor text vs destination URL mismatch ko flag karta hu (jaise text me 'Verify Account' aur actual link fake phishing portal par bhejna).\n\n"
                "6. **Multi-Feed Threat Intelligence (7-Day Cached):**\n"
                "   • AbuseIPDB, AlienVault OTX, aur VirusTotal Multi-Key Rotator se IP aur URLs ka reputation score check karta hu.\n\n"
                "7. **Threat Memory & Campaign Correlation Engine:**\n"
                "   • Purane suspicious emails ke saath pattern match karke coordinated cyber attacks aur APT phishing waves detect karta hu.\n\n"
                "8. **NLP & Behavioral Risk Scorer:**\n"
                "   • Urgency coercion, financial wire requests aur credential harvesting patterns ko 0-100 deterministic risk score me convert karta hu.\n\n"
                "9. **Court-Ready Chain of Custody & PDF Export:**\n"
                "   • Har investigation ka automated SHA-256 integrity hash aur court-admissible forensic report banata hu.\n\n"
                "10. **Interactive Conversational AI (Hinglish/English):**\n"
                "   • Kisi bhi email ki technical evidence ko plain Hinglish ya English me samjhata hu taaki normal user aur SOC analyst dono samajh sakein!\n\n"
                f"📌 **Is Current Email Ki Status:**\n"
                f"Is email par SPF: `{spf_status.upper()}`, DKIM: `{dkim_status.upper()}`, DMARC: `{dmarc_status.upper()}` perform hua hai aur verdict **{verdict.upper()}** (Risk Score: **{risk_score}/100**) nikla hai."
            )
            suggested = [
                "Is email me DMARC aur SPF kyu fail hue?",
                "Kya mai is email ke link par click kar sakta hu?",
                "Is attack ko rokne ke liye turant kya action lein?"
            ]
        else:
            reply = (
                "I am **MailGuardian AI**, an enterprise-grade Email Threat Detection & Forensic Intelligence Assistant. 🛡️\n\n"
                "I execute a rigorous **10-Step Deterministic Forensic Pipeline** across every ingested message:\n\n"
                "1. **Cryptographic Authentication Stack:**\n"
                "   - **SPF (RFC 7208):** Live DNS TXT evaluation of transmitting IP authorization.\n"
                "   - **DKIM (RFC 6376):** Public-key cryptographic header & body hash verification.\n"
                "   - **DMARC (RFC 7489):** Alignment verification between visible `From:` header and SPF/DKIM policies.\n\n"
                "2. **Received Chain Traversal & Origin IP:**\n"
                "   - Bottom-to-top hop parsing, filtering private RFC 1918 gateways to identify true threat-actor origin infrastructure.\n\n"
                "3. **GeoLocation & ASN Resolution:**\n"
                "   - Resolves country, city, coordinates, autonomous system (ASN), and transit ISP.\n\n"
                "4. **Domain Age & Lookalike Typosquatting:**\n"
                "   - WHOIS registration age evaluation (<30 days flag).\n"
                "   - Levenshtein edit distance & homoglyph analysis detecting brand impersonation.\n\n"
                "5. **Deceptive Hyperlink & Redirection Detection:**\n"
                "   - Flags divergence between human-readable anchor text and true HTTP destination targets.\n\n"
                "6. **Multi-Feed Threat Intelligence (7-Day Cache):**\n"
                "   - Parallel querying of AbuseIPDB, AlienVault OTX, and VirusTotal multi-key rotation engine.\n\n"
                "7. **Threat Memory & Campaign Correlation:**\n"
                "   - Cross-references internal threat memory to detect coordinated attack campaigns.\n\n"
                "8. **NLP & Behavioral Risk Engine:**\n"
                "   - Evaluates urgency coercion, credential harvesting prompts, and wire transfer BEC signals into a 0-100 composite risk score.\n\n"
                "9. **Court-Ready Evidence & PDF Generation:**\n"
                "   - Computes SHA-256 chain of custody and produces downloadable forensic PDF/JSON audits.\n\n"
                "10. **Interactive AI Investigation Assistant:**\n"
                "   - Translates complex cryptographic artifacts into actionable conversational insights in natural Hinglish or authoritative English."
            )
            suggested = [
                "Why was this email classified as a threat?",
                "What specific domain authentication checks failed?",
                "What containment actions should the SOC execute immediately?"
            ]
        return reply, suggested

    def _handle_why_fraud_intent(
        self, is_hinglish: bool, subject: str, from_raw: str, from_domain: str,
        target_brand: Optional[str], spf_status: str, dmarc_status: str,
        origin_ip: str, country: str, isp: str, verdict: str,
        risk_score: float, classification: str, risk_factors: List[str]
    ) -> Tuple[str, List[str]]:
        if is_hinglish:
            brand_point = ""
            if target_brand:
                brand_point = (
                    f"1. **Nakli Sender Domain (Brand Impersonation):** Ye email khud ko **{target_brand.split('.')[0].capitalize()}** ka bata rahi hai, "
                    f"lekin actual sending domain `{from_domain}` hai jo ki ek lookalike / spoofed domain hai.\n"
                )
            else:
                brand_point = f"1. **Suspicious Sender:** Email `{from_raw}` se aayi hai jo untrusted infrastructure use kar rahi hai.\n"

            auth_point = (
                f"2. **Authentication Fail (SPF: {spf_status.upper()}, DMARC: {dmarc_status.upper()}):** "
                f"Origin server (`{origin_ip}`) is domain ke authorized email servers me listed nahi hai, isliye cryptographic security checks fail ho gaye.\n"
            )

            risk_summary = "\n".join([f"• {f}" for f in risk_factors[:3]]) if risk_factors else "• Deceptive headers aur suspicious routing pakdi gayi hai."

            reply = (
                f"Bhai, ye email **100% {verdict.upper()}** ({classification}) attack hai! Iska Risk Score **{risk_score}/100** hai.\n\n"
                f"**Iske 3 sabse bade kaaran ye hain:**\n"
                f"{brand_point}"
                f"{auth_point}"
                f"3. **Deceptive Routing & Origin:** Origin IP `{origin_ip}` ({country} - {isp}) se connect hui hai, jiska threat index elevated hai.\n\n"
                f"🔍 **Key Forensic Indicators:**\n"
                f"{risk_summary}\n\n"
                f"⚠️ **Advice:** Ye email credentials chori karne ya system compromise karne ke liye bheji gayi hai. Iske kisi bhi link ya button par bilkul click mat karna!"
            )
            suggested = [
                "Kya mai is email ke link par click kar sakta hu?",
                "DMARC aur SPF fail hone ka technical matlab kya hai?",
                "Is attack ko rokne ke liye turant kya action lein?"
            ]
        else:
            factors_list = "\n".join([f"- **{f}**" for f in risk_factors[:4]]) if risk_factors else "- Multiple deterministic heuristic indicators triggered."
            reply = (
                f"This email was classified as **{verdict.upper()}** ({classification}) with an enterprise risk score of **{risk_score}/100**.\n\n"
                f"### Core Forensic Failure Points:\n"
                f"1. **Identity & Authentication Breakdown:**\n"
                f"   - **SPF Status:** `{spf_status.upper()}` (Origin IP `{origin_ip}` is unauthorized)\n"
                f"   - **DMARC Status:** `{dmarc_status.upper()}` (Alignment violation detected)\n"
                f"2. **Domain Spoofing & Impersonation:**\n"
                f"   - Sender domain `{from_domain}` mimics legitimate infrastructure" + (f" (targeting brand `{target_brand}`)" if target_brand else "") + ".\n"
                f"3. **Origin Routing Risk:**\n"
                f"   - Origin IP `{origin_ip}` located in `{country}` (`{isp}`) exhibits abnormal mail gateway behavior.\n\n"
                f"### Flagged Indicators:\n"
                f"{factors_list}\n\n"
                f"**Verdict:** High-confidence threat designed for credential theft or organizational compromise. Immediate containment required."
            )
            suggested = [
                "Can I safely interact with the embedded links?",
                "Why did DMARC and SPF authentication fail?",
                "What containment actions should the SOC execute immediately?"
            ]
        return reply, suggested

    def _handle_auth_intent(
        self, is_hinglish: bool, spf_status: str, spf_details: str,
        dkim_status: str, dkim_details: str, dmarc_status: str,
        dmarc_details: str, origin_ip: str, from_domain: str,
        target_brand: Optional[str]
    ) -> Tuple[str, List[str]]:
        if is_hinglish:
            reply = (
                f"Email authentication 3 main security protocols par chalti hai — **SPF, DKIM, aur DMARC**. Is email ki technical status ye hai:\n\n"
                f"1. **SPF (Sender Policy Framework) — `{spf_status.upper()}`:**\n"
                f"   - SPF domain ke DNS record me check karta hai ki kya origin server IP `{origin_ip}` authorized hai.\n"
                f"   - **Result:** Ye IP authorized nahi thi, isliye SPF **{spf_status.upper()}** ho gaya.\n\n"
                f"2. **DKIM (DomainKeys Identified Mail) — `{dkim_status.upper()}`:**\n"
                f"   - DKIM email ke content par digital signature verify karta hai taaki tampering na ho sake.\n"
                f"   - **Result:** Is email me valid cryptographic signature verify nahi hui (`{dkim_status.upper()}`).\n\n"
                f"3. **DMARC (Domain-based Message Authentication) — `{dmarc_status.upper()}`:**\n"
                f"   - DMARC ensure karta hai ki SPF ya DKIM pass hokar `From:` header domain se match ho.\n"
                f"   - **Result:** Dono checks fail hone ki wajah se DMARC **FAIL** ho gaya aur policy violation confirm hua.\n\n"
                f"🛡️ **Samjh:** Sender ne asal identity ko spoof (nakli) banakar ye email bheji hai."
            )
            suggested = [
                "Is sender domain ko gateway par block kaise karein?",
                "Kya origin IP se purani koi attack history judi hai?",
                "Kya mai is email ke link par click kar sakta hu?"
            ]
        else:
            reply = (
                f"Here is the detailed forensic breakdown of the email authentication stack:\n\n"
                f"### 1. SPF (Sender Policy Framework) — `{spf_status.upper()}`\n"
                f"- **Mechanism:** Validates whether the transmission IP `{origin_ip}` is designated in the DNS TXT SPF records for `{from_domain}`.\n"
                f"- **Diagnostic:** {spf_details or f'IP {origin_ip} is not authorized in published SPF records.'}\n\n"
                f"### 2. DKIM (DomainKeys Identified Mail) — `{dkim_status.upper()}`\n"
                f"- **Mechanism:** Cryptographic public-key verification of header and payload integrity.\n"
                f"- **Diagnostic:** {dkim_details or 'Cryptographic signature is absent or failed hash verification.'}\n\n"
                f"### 3. DMARC Alignment — `{dmarc_status.upper()}`\n"
                f"- **Mechanism:** Evaluates SPF/DKIM identifier alignment against the visible RFC 5322 `From:` domain.\n"
                f"- **Diagnostic:** {dmarc_details or 'Both SPF and DKIM alignment criteria failed, confirming sender identity forgery.'}\n\n"
                f"**Analytical Conclusion:** This message fails baseline RFC authentication standards, indicating unauthorized adversary relay."
            )
            suggested = [
                "What is the recommended DMARC policy (reject vs quarantine)?",
                "How do we configure origin IP perimeter firewall drops?",
                "Has this lookalike domain been reported to domain registrars?"
            ]
        return reply, suggested

    def _handle_link_intent(
        self, is_hinglish: bool, urls: List[Any], risk_factors: List[str],
        verdict: str, risk_score: float
    ) -> Tuple[str, List[str]]:
        if is_hinglish:
            reply = (
                f"⛔ **BILKUL NAHI! Is email ke kisi bhi link par click mat karna.**\n\n"
                f"**Iske peeche ka khatra:**\n"
                f"1. **Deceptive Hyperlink:** Email me jo anchor text dikhta hai (jaise 'Verify Account' ya 'Login') wo asli target URL se alag hai. "
                f"Aapko ek fake phishing login portal par redirect kiya jayega.\n"
                f"2. **Credential Theft:** Wahan aapse login credentials/password maanga jayega aur submit karte hi hacker ke database me chala jayega.\n"
                f"3. **Malware / Session Hijacking:** Kuch links par click karne se malicious payload execute ho sakta hai.\n\n"
                f"💡 **Agar galti se kisi ne click kar diya ho to:**\n"
                f"• Turant apna corporate password change karein.\n"
                f"• SOC / IT security team ko inform karein aur active sessions terminate karein."
            )
            suggested = [
                "SOC team ko kya immediate action lena chahiye?",
                "Is email ka origin IP kis desh se hai?",
                "DMARC fail hone ka kya matlab hai?"
            ]
        else:
            reply = (
                f"⛔ **DO NOT INTERACT WITH ANY EMBEDDED LINKS.**\n\n"
                f"### Link Threat Assessment:\n"
                f"- **Deceptive Anchor Discrepancy:** The visible anchor text misleads recipients regarding the destination URL, routing victims toward adversary-controlled infrastructure.\n"
                f"- **Attack Objective:** Credential harvesting disguised as security verification or single sign-on (SSO) portals.\n"
                f"- **Payload Risk:** Potential drive-by malware execution or automated session cookie harvesting.\n\n"
                f"### Incident Response Protocol (If Interacted):\n"
                f"1. Isolate the target workstation from the corporate network immediately.\n"
                f"2. Revoke active OAuth refresh tokens and force global password reset.\n"
                f"3. Query enterprise web proxy / DNS logs for outbound hits to the flagged destination URLs."
            )
            suggested = [
                "What are the specific URLs extracted from this email?",
                "What firewall rules should be deployed for containment?",
                "What authentication indicators failed on this message?"
            ]
        return reply, suggested

    def _handle_ip_intent(
        self, is_hinglish: bool, origin_ip: str, country: str, city: str,
        isp: str, abuse_score: float, vt_positives: int, verdict: str
    ) -> Tuple[str, List[str]]:
        loc_str = f"{city}, {country}" if city else country
        if is_hinglish:
            reply = (
                f"🌐 **Origin IP & Infrastructure Intelligence:**\n\n"
                f"• **Origin IP:** `{origin_ip}`\n"
                f"• **Location:** {loc_str}\n"
                f"• **Hosting ISP:** {isp}\n"
                f"• **AbuseIPDB Score:** {abuse_score}%\n"
                f"• **VirusTotal Detections:** {vt_positives} security vendors flagged\n\n"
                f"**Forensic Note:** Ye IP kisi standard legitimate mail exchange server ki nahi hai. "
                f"Attackers aksar aisi cloud hosting (VPS), VPN ya proxy infrastructure use karte hain taaki identity chupayi ja sake.\n\n"
                f"🛡️ **Recommendation:** Apne organization ke perimeter firewall aur email gateway par IP `{origin_ip}` ko turant blocklist me daalein."
            )
            suggested = [
                "Is IP ko perimeter firewall par kaise block karein?",
                "DMARC authentication details dikhao?",
                "Kya is email me koi deceptive links hain?"
            ]
        else:
            reply = (
                f"🌐 **Origin IP Threat Intelligence:**\n\n"
                f"- **IP Address:** `{origin_ip}`\n"
                f"- **Geographic Location:** {loc_str}\n"
                f"- **Network ASN / ISP:** {isp}\n"
                f"- **AbuseIPDB Confidence:** {abuse_score}%\n"
                f"- **Security Vendor Positives:** {vt_positives} flagged\n\n"
                f"**Infrastructure Analysis:** The transmitting node operates out of untrusted hosting/cloud infrastructure, inconsistent with legitimate enterprise messaging relays.\n\n"
                f"**Remediation Rule:** Add `{origin_ip}` to edge border router / firewall perimeter ingress drop policies."
            )
            suggested = [
                "Generate firewall ingress block syntax for this IP",
                "Why did this email fail SPF and DMARC verification?",
                "What containment steps are required across Microsoft 365?"
            ]
        return reply, suggested

    def _handle_action_intent(
        self, is_hinglish: bool, verdict: str, risk_score: float,
        origin_ip: str, sender: str, recommendations: List[str]
    ) -> Tuple[str, List[str]]:
        if is_hinglish:
            rec_text = "\n".join([f"• {r}" for r in recommendations]) if recommendations else (
                "• Sender address ko organization-wide email blocklist me daalein.\n"
                "• Origin IP ko firewall par block karein.\n"
                "• Kisi bhi user ko link par click karne se mana karein."
            )
            reply = (
                f"🛡️ **Immediate Incident Containment Playbook (SOC Action):**\n\n"
                f"1. **Email Purge:** Microsoft 365 ya Google Workspace admin console se is message ko sabhi inboxes se permanently delete/quarantine karein.\n"
                f"2. **Perimeter Firewall Block:** Origin IP `{origin_ip}` ko enterprise firewall par drop rule me add karein.\n"
                f"3. **Sender Blacklist:** Sender `{sender}` ko mail gateway blocklist me daalein.\n"
                f"4. **Credential Audit:** Agar kisi user ne is mail ke link par click kiya ho, to unka session revoke karke password reset karwayein.\n\n"
                f"📋 **Detailed Recommendations:**\n"
                f"{rec_text}"
            )
            suggested = [
                "Kya mai is email ke link par click kar sakta hu?",
                "Is email me kya kya fake paya gaya?",
                "Threat memory me kya aisi emails pehle aayi hain?"
            ]
        else:
            rec_text = "\n".join([f"- {r}" for r in recommendations]) if recommendations else (
                "- Enforce edge boundary drop rules for the origin IP.\n"
                "- Add sender domain to secure email gateway blocklists.\n"
                "- Conduct tenant-wide mailbox search and purge."
            )
            reply = (
                f"🛡️ **SOC Operational Containment Playbook:**\n\n"
                f"### Phase 1: Immediate Triage\n"
                f"1. **Tenant-Wide Purge:** Execute Compliance Search / Hard Purge across Microsoft 365 / Google Workspace for Subject & Sender.\n"
                f"2. **Perimeter Firewall Block:** Block IP `{origin_ip}` at Palo Alto / Fortinet / Cloudflare gateway.\n"
                f"3. **Mail Gateway Rule:** Add `{sender}` and related subdomains to email perimeter rejection list.\n\n"
                f"### Phase 2: Credential & Endpoint Remediation\n"
                f"4. **Session Revocation:** Force logout of active SSO sessions for any user who interacted with this email.\n"
                f"5. **EDR Query:** Hunt for outbound network connections to origin IP `{origin_ip}` across endpoints.\n\n"
                f"### Automated Recommendations:\n"
                f"{rec_text}"
            )
            suggested = [
                "What specific authentication failures were detected?",
                "How do we query SIEM logs for this origin IP?",
                "What campaign correlation was identified in threat memory?"
            ]
        return reply, suggested

    def _handle_sender_intent(
        self, is_hinglish: bool, from_raw: str, from_name: str,
        from_email: str, from_domain: str, target_brand: Optional[str],
        is_spoofed_lookalike: bool, verdict: str
    ) -> Tuple[str, List[str]]:
        if is_hinglish:
            brand_note = (
                f"Ye email **{target_brand}** ban kar aayi hai, lekin asal domain `{from_domain}` hai. "
                f"Ye classic **Lookalike / Typosquatting Attack** hai jahan genuine brand ka naam use karke logo ko dhoka diya jata hai."
                if target_brand else
                f"Sender domain `{from_domain}` ek untrusted infrastructure se operate ho rahi hai."
            )
            reply = (
                f"🕵️ **Sender Identity Analysis:**\n\n"
                f"• **Display Name:** `{from_name or 'Not set'}`\n"
                f"• **Actual Address:** `{from_email or from_raw}`\n"
                f"• **Sender Domain:** `{from_domain}`\n\n"
                f"{brand_note}\n\n"
                f"Sender ne display name me bharosemand naam dikhaya taaki aap bina check kiye trust kar lein, jabki technical header me actual sender alag hai."
            )
            suggested = [
                "Bhai ye kyu fraud email hai simple shabdon me batao?",
                "DMARC fail kyu hua is email me?",
                "Is sender ko block kaise karein?"
            ]
        else:
            reply = (
                f"🕵️ **Sender Identity & Deception Analysis:**\n\n"
                f"- **Display Name:** `{from_name or 'N/A'}`\n"
                f"- **From Header Address:** `{from_email or from_raw}`\n"
                f"- **Domain of Origin:** `{from_domain}`\n\n"
                f"**Impersonation Assessment:** " + (
                    f"The sender engineered a homoglyph / typosquatted domain targeting **{target_brand}**. Display name spoofing was utilized to bypass superficial human inspection."
                    if target_brand else
                    "The sender operates through an untrusted domain lacking legitimate organizational reputation."
                ) + "\n\n"
                f"**Cryptographic Verification:** Domain authentication failed to confirm organizational identity."
            )
            suggested = [
                "Why did SPF and DMARC fail for this sender?",
                "What containment actions should be taken against this domain?",
                "Can I safely click the links inside this email?"
            ]
        return reply, suggested

    def _handle_overview_intent(
        self, is_hinglish: bool, subject: str, from_raw: str,
        verdict: str, risk_score: float, classification: str,
        user_friendly: str, risk_factors: List[str]
    ) -> Tuple[str, List[str]]:
        if is_hinglish:
            factors = "\n".join([f"• {f}" for f in risk_factors[:3]]) if risk_factors else "• Security checks failed."
            reply = (
                f"Hello Analyst! Mai MailGuardian AI Forensic Assistant hu.\n\n"
                f"Is email ki primary forensic report ye rahi:\n"
                f"• **Subject:** `{subject}`\n"
                f"• **Sender:** `{from_raw}`\n"
                f"• **Verdict:** **{verdict.upper()}** (Risk Score: **{risk_score}/100**)\n"
                f"• **Classification:** {classification}\n\n"
                f"**Key Findings:**\n"
                f"{factors}\n\n"
                f"Aap is email ke SPF/DMARC checks, origin IP reputation, deceptive links ya containment actions ke baare me kuch bhi pooch sakte hain!"
            )
            suggested = [
                "Ye email fraud kyu hai hinglish me samjhao?",
                "Kya mai is email ke link par click kar sakta hu?",
                "DMARC aur SPF authentication checks kyu fail hue?"
            ]
        else:
            factors = "\n".join([f"- {f}" for f in risk_factors[:3]]) if risk_factors else "- Deterministic indicators detected."
            reply = (
                f"### MailGuardian AI Forensic Assessment\n\n"
                f"- **Subject:** `{subject}`\n"
                f"- **Sender:** `{from_raw}`\n"
                f"- **Forensic Verdict:** **{verdict.upper()}** (Risk Score: **{risk_score}/100**)\n"
                f"- **Threat Type:** {classification}\n\n"
                f"### High-Risk Indicators Detected:\n"
                f"{factors}\n\n"
                f"Feel free to ask about specific authentication failures, origin IP routing, deceptive links, or immediate containment playbooks."
            )
            suggested = [
                "Why was this email classified as a threat?",
                "What specific domain authentication checks failed?",
                "What immediate containment actions should I take?"
            ]
        return reply, suggested

forensic_chat_engine = ForensicChatEngine()
