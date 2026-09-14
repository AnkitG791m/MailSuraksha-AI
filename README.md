# MailGuardian AI (Enterprise Cyber Defense & Forensic Intelligence)
> **AI-Powered Autonomous Email Threat Intelligence, Forensic Investigation & Geolocation Defense Platform**  
> **Tech Stack:** Python 3.11/3.12, FastAPI, Scikit-Learn, ReportLab Platypus, Leaflet.js, SQLite, Docker

MailGuardian AI is an enterprise-grade digital forensics and automated SOC triage platform. It ingests raw RFC 822/5322 `.eml` email files, executes an automated 10-step forensic pipeline, and generates interactive origin radar maps, non-causal threat correlation graphs, calibrated risk scores, and court-admissible Section 65B (Indian Evidence Act / BSA) forensic dossiers.

---

## 1. High-Level Backend Architecture & Workflow

The backend processes every incoming email through a strict 10-stage forensic pipeline managed by [`AnalysisPipeline`](file:///home/ankitg791/dEMO/core/pipeline.py). The pipeline enforces zero-trust verification, cryptographic chain of custody, and multi-tier threat enrichment:

```mermaid
flowchart TD
    A[Raw .eml Email File Ingestion] --> B[Stage 1: Pre-Parse Cryptographic Ingestion & Hashing\nSHA-256 + MD5]
    B --> C[Stage 2: Deep RFC 5322 Parsing & URL Analysis\nHeaders, Body, Attachments, Deceptive Links]
    C --> D[Stage 3: RFC Authentication Verification\nPSL-aware SPF, Multi-DKIM, DMARC Alignment]
    D --> E[Stage 4: Relay Trust Model & Header Anomaly Assessment\nReverse Hop Traversal, Monotonicity Checks, Candidate Origin IP]
    E --> F[Stage 5: WHOIS & Domain Age Intelligence\nRegistration Audit, &lt;30d Disposable Domain Flag]
    E --> G[Stage 6: Geolocation & Network Autonomous System\nCountry, City, Coordinates, ISP, ASN]
    E --> H[Stage 7: Multi-Tier Selective Threat Intelligence\nTier 1: Local &lt;50 (0 APIs) | Tier 2: 50-70 Cache/AbuseIPDB | Tier 3: &gt;70 VT 5-Key Pool]
    C --> I[Stage 8: ML Risk Classification & NLP Vectorization\nTF-IDF + Urgency NLP + Structural Security Signals]
    D & F & G & H & I --> J[Stage 9: Calibrated Risk Engine v2026.1 & Threat Memory\nDecoupled Confidence, Collinearity Capping, Playbooks]
    J --> K[Stage 10: Non-Causal Correlation Graph & Forensic Reports\nReportLab PDF with Section 65B Certificate & JSON]
    K --> L[SOC Web Dashboard & REST APIs\nLeaflet.js Radar, Forensic Drawers, Chatbot Copilot]
```

---

## 2. Deep Dive: Stage-by-Stage Forensic Engineering

Every stage in MailGuardian AI is built according to RFC standards, forensic best practices, and enterprise fault tolerance. Below is the comprehensive matrix explaining:
1. **What check/authentication is performed?**
2. **Why is it performed (Forensic & Threat Rationale)?**
3. **Can something else be used instead or alongside (Alternatives & Modern Standards)?**
4. **What happens if that check fails or times out (Failure Modes & Graceful Degradation)?**

---

### Stage 1: Pre-Parse Cryptographic Evidence Ingestion
- **Implementation File:** [`core/pipeline.py`](file:///home/ankitg791/dEMO/core/pipeline.py)
- **What is performed:**
  - The raw uploaded byte buffer is hashed **immediately before any parser or string manipulation** occurs.
  - Generates cryptographic SHA-256 (`hashlib.sha256`) and MD5 (`hashlib.md5`) checksums stored in `evidence_metadata`.
- **Why it is performed:**
  - **Legal Admissibility (Chain of Custody):** Under digital forensic standards (ISO/IEC 27037) and Indian Evidence Act Section 65B (and Bharatiya Sakshya Adhiniyam - BSA), evidence must be proven unaltered. If an email is re-serialized or normalized after parsing, whitespace or newline conversions alter the hash, destroying legal integrity. Pre-parse hashing guarantees bit-level tamper evidence.
- **Alternatives & Modern Standards:**
  - **SHA-512 / BLAKE3:** Could be used for higher cryptographic collision resistance. SHA-256 remains the global gold standard for law enforcement and judicial filings.
  - **Hardware Security Module (HSM) / RFC 3161 Trusted Timestamps:** Cryptographically timestamping evidence via a Qualified Trust Service Provider (QTSP).
- **What happens if this stage fails?**
  - If the byte buffer is empty or corrupted (0 bytes): Pipeline raises a `ValueError("Empty or unreadable email byte stream")` and terminates before consuming resources.
  - If encoding is malformed: The raw byte slice is preserved verbatim, ensuring hash stability regardless of text encoding anomalies.

---

### Stage 2: Deep RFC 5322 Parsing & Deceptive URL Deconstruction
- **Implementation File:** [`core/parser.py`](file:///home/ankitg791/dEMO/core/parser.py)
- **What is performed:**
  - Extracts RFC 5322 header fields: `From`, `To`, `Subject`, `Date`, `Message-ID`, `Return-Path`, `Reply-To`.
  - Analyzes MIME structures, multipart boundaries, plaintext vs. HTML bodies.
  - Extracts all URLs and compares **Anchor Display Text** against destination `href`.
  - Evaluates brand typosquatting via Levenshtein edit distance against protected enterprise domains (`paypal`, `microsoft`, `google`, `sbi`, `icici`, etc.).
  - Flags URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`) and suspicious attachment extensions (`.exe`, `.scr`, `.vbs`, `.iso`, double extensions like `.pdf.exe`).
- **Why it is performed:**
  - **Hyperlink Deception is Attack Vector #1:** Phishing emails regularly display `https://login.microsoftonline.com` as text, while the underlying HTML hyperlink redirects the victim to a credential harvester (`http://login-security-update-993.top`).
  - **Mismatched Reply-To / Return-Path:** Identifies Business Email Compromise (BEC) and executive wire fraud where the attacker spoofs the CEO in `From:` but routes replies to a burner inbox.
- **Alternatives & Modern Standards:**
  - **Computer Vision OCR & DOM Rendering:** Headless browser (Playwright/Puppeteer) screenshot rendering to detect visual spoofing and zero-font trickery.
  - **QR Code (Quishing) Scanner:** Integrated in [`core/quishing_scanner.py`](file:///home/ankitg791/dEMO/core/quishing_scanner.py) using PyZbar/OpenCV to decode obfuscated QR payloads.
- **What happens if this stage fails?**
  - Malformed MIME / Obfuscated boundary: Parser catches decoding exceptions and attempts fallback decodings (`utf-8`, `latin-1`, `windows-1252`, raw bytes with `errors='replace'`).
  - Missing headers: If `Message-ID` or `Date` is absent, the parser records a syntax anomaly factor, generates an internal synthetic tracking ID, and continues execution without crashing.

---

### Stage 3: RFC Authentication Verification (PSL-Aware SPF, Multi-DKIM, DMARC Alignment)
- **Implementation File:** [`core/auth_check.py`](file:///home/ankitg791/dEMO/core/auth_check.py)
- **What is performed:**
  1. **Public Suffix List (PSL) Extraction (`get_organizational_domain`):** Strips subdomains to extract the true organizational domain, correctly handling multi-part country codes (e.g., `mail.sbi.co.in` -> `sbi.co.in`, `corp.gov.in` -> `gov.in`, `co.uk`, `com.au`).
  2. **SPF Verification (RFC 7208):** Differentiates RFC 5321 `MAIL FROM` (Return-Path) from RFC 5322 `From`. Checks whether the candidate origin IP is authorized in the sender domain's DNS TXT SPF record (`+ip4`, `include:`, `~all`, `-all`). Evaluates strict (`mail.example.com == mail.example.com`) vs. relaxed (`sub.example.com` shares `example.com` org domain) alignment.
  3. **Multi-Signature DKIM Evaluation (RFC 6376):** Inspects *every* `DKIM-Signature` present in the message independently. A message may carry multiple signatures (e.g., third-party relay signature `d=sendgrid.net` alongside author domain signature `d=targetcorp.com`).
  4. **Untrusted `Authentication-Results` Filtering:** Rejects injected or spoofed `Authentication-Results` headers by comparing `authserv-id` against [`TRUSTED_AUTHSERV_IDS`](file:///home/ankitg791/dEMO/config.py).
  5. **DMARC Policy & Alignment (RFC 7489):** Evaluates overall DMARC outcome by checking if *either* SPF or DKIM is aligned with the RFC 5322 `From` domain. Separates `result` (`pass`, `fail`, `none`), `policy` (`none`, `quarantine`, `reject`), and `disposition`.
- **Why it is performed:**
  - **Identity Spoofing Prevention:** Email SMTP protocol (RFC 821) natively allows any sender to forge `From: ceo@company.com`. SPF, DKIM, and DMARC are the only standardized cryptographic and DNS protocols that verify domain authorization.
  - **Why SPF alone is not enough:** SPF only validates the envelope bounce path (RFC 5321 `MAIL FROM`). An attacker can send from `attacker@burner.com` (valid SPF) while displaying `From: support@bank.com`.
  - **Why DKIM alone is not enough:** An attacker can legally sign a phishing email using their own domain `d=malicious.org`. Unless DKIM aligns with the header `From` domain, it provides zero identity security.
- **Alternatives & Modern Standards:**
  - **ARC (Authenticated Received Chain - RFC 8617):** Critical for forwarded emails or mailing lists that legitimately break SPF (IP changes) and DKIM (mail list footer modifications).
  - **BIMI (Brand Indicators for Message Identification - RFC 9637):** Validates verified brand logos via VMC (Verified Mark Certificates) requiring strict DMARC enforcement.
  - **MTA-STS (RFC 8461) & DANE/TLSA (RFC 7672):** Enforces opportunistic or mandatory TLS encryption on SMTP transit.
- **What happens if this stage fails?**
  - **DNS Server Timeout / ServFail:** When authoritative DNS servers are unresponsive, `dnspython` times out gracefully after 3.0s (`DNS_TIMEOUT`). The check returns `status: "temperror"`, assigns neutral/mild risk impact, lowers `analysis_confidence` (e.g., -0.15), and falls back to trusted internal `Authentication-Results` headers if available.
  - **Domain has no SPF/DMARC (`NXDOMAIN`):** Returns `status: "none"`, records missing authentication policies, and applies calibrated penalty points without aborting.

---

### Stage 4: Relay Trust Model & Header Anomaly Assessment
- **Implementation File:** [`core/origin_ip.py`](file:///home/ankitg791/dEMO/core/origin_ip.py)
- **What is performed:**
  - **Reverse Hop Traversal:** Reverses `Received` headers so index 0 represents the earliest recorded client/relay hop and index $N-1$ represents the recipient boundary MTA.
  - **Header Anomaly & Consistency Assessment:** Replaces naive "forged hop claims" with rigorous consistency checks:
    - **Timestamp Monotonicity:** Flags `timestamp_inversion` if a hop timestamp is chronologically earlier than a preceding hop by $> 300$ seconds.
    - **Syntax Anomalies:** Flags malformed `from`/`by`/`with` clauses and missing TCP tokens.
    - **forgery_assessment:** Outputs `no_obvious_anomaly`, `anomalies_detected`, or `likely_untrusted`.
  - **Relay Trust Evaluation:** Evaluates relays against configured organizational relays (`TRUSTED_RELAYS`), known mail provider infrastructure (`TRUSTED_PROVIDER_DOMAINS` like Google, Microsoft, AWS SES), and TLS/ESMTP authentication context.
  - **Candidate Origin IP Isolation:** Filters RFC 1918 private IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC 6598 CGNAT (`100.64.0.0/10`), loopback (`127.0.0.0/8`), and link-local (`169.254.0.0/16`) to isolate the `candidate_origin_ip` with separate `candidate_attribution_confidence`.
- **Why it is performed:**
  - **MTA Spoofing Reality:** `Received` headers are untrusted input because any SMTP sender can inject fake `Received: from legitimate.com...` headers at the bottom of the email.
  - Therefore, the system **cannot definitively prove forged hops from headers alone**, but can reliably identify anomalies, clock inversions, and evaluate the first trusted organizational boundary.
  - **Attribution Discipline:** An IP address represents candidate network infrastructure (a VPN exit, compromised proxy, or cloud carrier), not proof of human identity.
- **Alternatives & Modern Standards:**
  - **BGP Routing & RPKI Origin Validation:** Validating Route Origin Authorizations (ROAs) to detect BGP route hijacking.
  - **DNSBL / RBL (Spamhaus ZEN, Barracuda):** Real-time IP blacklist lookups during MTA ingestion.
- **What happens if this stage fails?**
  - All hops are internal RFC 1918 IPs: `candidate_origin_ip` is set to `None`, attribution status set to `"internal_only"`, and confidence is calibrated accordingly.
  - Unparseable date format: Date parsing exceptions are caught silently (`_parse_hop_date`), skipping monotonicity checks for that hop without crashing the pipeline.

---

### Stage 5: WHOIS & Domain Age Intelligence
- **Implementation File:** [`core/whois_lookup.py`](file:///home/ankitg791/dEMO/core/whois_lookup.py)
- **What is performed:**
  - Queries authoritative TLD registrars for the sender domain using `python-whois`.
  - Calculates domain age in days from creation date (`creation_date`).
  - Computes time to expiration (`expiration_date`) and flags domains created $< 30$ days ago (`is_new_domain`).
- **Why it is performed:**
  - **Disposable Phishing Infrastructure:** Over 85% of malicious phishing and spear-phishing domains are registered within 48 to 72 hours of launching an attack. Legitimate enterprise banking domains are typically years or decades old.
- **Alternatives & Modern Standards:**
  - **RDAP (Registration Data Access Protocol - RFC 7480 / RFC 9082):** RESTful JSON-based successor to port-43 WHOIS with structured error codes and authentication support.
  - **Passive DNS (pDNS):** Historical domain-to-IP resolution tracking to identify fast-flux domains and bulletproof hosting.
- **What happens if this stage fails?**
  - WHOIS Port 43 rate limits / Connection Refused / Privacy Guard: The query is wrapped in a 5.0s timeout. On failure, `domain_age_days` is marked as `null`, `whois_status: "lookup_failed"`, and the scoring engine skips the domain age penalty without interrupting analysis.

---

### Stage 6: IP Geolocation & Autonomous System Intelligence
- **Implementation File:** [`core/geo.py`](file:///home/ankitg791/dEMO/core/geo.py)
- **What is performed:**
  - Resolves `candidate_origin_ip` to Country, City, Region, Latitude, Longitude, ISP, and Autonomous System Number (ASN).
  - Supplies geographic coordinates to the Leaflet.js radar sweep dashboard map.
- **Why it is performed:**
  - **Geopolitical & Anomaly Triage:** A local branch bank email originating from a bulletproof host in a non-extradition jurisdiction is an immediate critical threat indicator.
- **Alternatives & Modern Standards:**
  - **MaxMind GeoIP2 / GeoLite2 Local Database (MMDB):** Zero-latency offline lookup avoiding third-party API dependencies.
  - **IP2Location / DB-IP:** Commercial-grade threat geolocation databases.
- **What happens if this stage fails?**
  - Network disconnection / API rate limit: Falls back to an offline default schema (`{"country": "Unknown", "city": "Unknown", "latitude": 0.0, "longitude": 0.0}`). The interactive map disables the pin and notes offline status gracefully.

---

### Stage 7: Multi-Tier Selective Threat Intelligence Enrichment
- **Implementation File:** [`core/threat_intel.py`](file:///home/ankitg791/dEMO/core/threat_intel.py)
- **What is performed:**
  - Enforces a **3-Tier Selective Enrichment Architecture** engineered for zero quota waste:
    1. **Tier 1 (Local Risk Score < 50):** **Zero External APIs Called**. Clean and low-risk emails skip VirusTotal, AbuseIPDB, and AlienVault OTX entirely.
    2. **Tier 2 (Local Risk Score 50–70):** Queries the 7-day local SQLite indicator cache (`threat_intel_cache`). On cache miss, queries AbuseIPDB v2 and AlienVault OTX (skipping VirusTotal).
    3. **Tier 3 (Local Risk Score > 70):** Full priority enrichment: queries Threat Memory -> 7-day Cache -> AbuseIPDB -> AlienVault OTX -> **VirusTotal Multi-Key Pool**.
  - **VT Multi-Key Rotator (`VTKeyRotator`):** Implements a thread-safe pool of 5 API keys with automatic failover upon HTTP 429 (rate-limit) responses.
- **Why it is performed:**
  - Public SOCs and security teams are constrained by strict API quotas (e.g. VirusTotal free tier allows 4 requests/min, 500/day).
  - Unconditional enrichment exhausts API limits on harmless spam. Tiered enrichment preserves quotas for genuine threats.
- **Alternatives & Modern Standards:**
  - **MISP (Malware Information Sharing Platform) & OpenCTI:** Open-source STIX/TAXII threat sharing standards for government and national CERTs.
  - **Commercial Feeds:** CrowdStrike Falcon Intel, Mandiant Advantage, Recorded Future.
- **What happens if this stage fails?**
  - **HTTP 429 (Rate Limit):** The key rotator immediately switches to the next available API key in the pool.
  - **Total API Blackout:** If all external APIs are unreachable or offline, the engine falls back to the 7-day SQLite cache, and if still unavailable, relies on Layer 1 local heuristic scoring with zero crash.

---

### Stage 8: AI/ML Risk Classification & NLP Vectorization
- **Implementation File:** [`core/classifier.py`](file:///home/ankitg791/dEMO/core/classifier.py), [`ml/train.py`](file:///home/ankitg791/dEMO/ml/train.py)
- **What is performed:**
  - Combines NLP text vectorization (`TfidfVectorizer` on subject + body) with tabular structural features (SPF pass/fail, DKIM validity, domain age, deceptive link counts, urgency keyword density).
  - Evaluates probability of maliciousness using a trained `RandomForestClassifier`.
  - Outputs predicted class and classification probability with explainable feature importance.
- **Why it is performed:**
  - Rule-based heuristics cannot easily detect semantic subtleties, social engineering, or emerging phrasing patterns. Machine learning bridges structural signals with linguistic context.
- **Alternatives & Modern Standards:**
  - **Fine-Tuned Small Language Models (SLMs):** DeBERTa-v3 or RoBERTa fine-tuned specifically on phishing corpora (e.g., IWSPA, Enron).
  - **Large Language Models (LLM zero-shot reasoning):** Incorporated in [`core/ai_intelligence.py`](file:///home/ankitg791/dEMO/core/ai_intelligence.py) via OpenRouter / Gemini for multilingual translation and executive threat summaries.
- **What happens if this stage fails?**
  - Corrupt pickle model / Missing file: If `model.pkl` is unreadable, the classifier catches `Exception`, logs a warning, and returns a baseline heuristic probability based on deceptive links and urgency counts.

---

### Stage 9: Calibrated Risk Scorer v2026.1 & Threat Memory
- **Implementation File:** [`core/risk_scorer.py`](file:///home/ankitg791/dEMO/core/risk_scorer.py), [`core/threat_memory.py`](file:///home/ankitg791/dEMO/core/threat_memory.py)
- **What is performed:**
  - Synthesizes all evidence pillars into a single calibrated score (0–100) under `scoring_version: "2026.1"`:
    - **Clean:** 0 – 20
    - **Low Risk:** 21 – 40
    - **Medium Risk:** 41 – 70
    - **High Risk:** 71 – 85
    - **Critical Risk:** 86 – 100
  - **Decoupled Confidence (`analysis_confidence`):** Evaluated independently on a 0.0–1.0 scale based on header completeness, DNS availability, and threat intel coverage.
  - **Collinear Signal De-Duplication:** Caps overlapping deductions so an email with failing SPF, failing DKIM, and failing DMARC is not penalized three times independently (capped at 35 points).
  - **Structured Actionable Playbooks:** Emits concrete incident response actions (`scope`, `impact_level`, `requires_approval`, `reversibility`, `false_positive_warning`).
  - **Threat Memory:** Records malicious indicators into local SQLite to cluster recurring campaign fingerprints and repeat offender IPs/domains.
- **Why it is performed:**
  - Uncalibrated scoring engines produce runaway false alarms where a simple marketing email with relaxed SPF is flagged as "95% Malicious".
  - Decoupling risk from confidence ensures an analyst knows whether an email is *confidently safe* vs. *inconclusively rated due to missing DNS records*.
- **What happens if this stage fails?**
  - Internal mathematical safeguards ensure risk score is clamped strictly to $[0.0, 100.0]$ and confidence is clamped to $[0.1, 1.0]$. The engine is 100% deterministic and self-contained with no network dependencies.

---

### Stage 10: Non-Causal Correlation Graph & Forensic Reporting
- **Implementation File:** [`core/pipeline.py`](file:///home/ankitg791/dEMO/core/pipeline.py), [`core/report.py`](file:///home/ankitg791/dEMO/core/report.py)
- **What is performed:**
  - **Non-Causal Relationship Semantics:** Assembles a correlation network where edges represent observed relationships (`observed_in`, `candidate_origin_for`, `hosted_by`, `signed_by`, `linked_from`, `associated_with`), each with `relationship_confidence` and `evidence_refs`.
  - **Section 65B Digital Certificate:** Emits an examiner-support PDF dossier using ReportLab Platypus containing:
    - Evidence identifiers, SHA-256 and MD5 pre-parse hashes.
    - Full reverse hop audit table with timestamps.
    - Explicit legal disclaimer that electronic admissibility is determined by the judiciary under Indian Evidence Act / BSA.
  - **Exportable Structured JSON:** Full forensic telemetry dump for SIEM/SOAR ingestion.
- **Why it is performed:**
  - **Forensic defensibility in court:** Technical evidence must be accompanied by examiner certification, tool versioning, and non-causal descriptions to withstand cross-examination.
- **What happens if this stage fails?**
  - ReportLab PDF generation exception: Caught in `try...except`, outputs `pdf_report_path: null`, and still outputs the complete JSON evidence payload, ensuring data is never lost.

---

## 3. Comprehensive Summary: Failure Modes & Recovery Matrix

| Failure Scenario | Affected Stage | System Fallback & Recovery Mechanism | Impact on Output |
|---|---|---|---|
| **Authoritative DNS Timeout / Down** | Stage 3 (Auth) | 3.0s timeout triggered; falls back to internal `Authentication-Results` if trusted; otherwise evaluates without live DNS. | `analysis_confidence` lowered by 0.15; score calculated from structural signals. |
| **Untrusted / Injected Auth Header** | Stage 3 (Auth) | Evaluates `authserv-id` against `TRUSTED_AUTHSERV_IDS`. Untrusted headers are ignored. | Prevents attacker bypass via fake `Authentication-Results: spf=pass`. |
| **All Hops Private (RFC 1918 / CGNAT)** | Stage 4 (Origin IP) | Identifies internal routing; sets `candidate_origin_ip: null` and attribution to `"internal_only"`. | Geolocation skipped; email flagged as internal enterprise message. |
| **Non-Monotonic / Scrambled Timestamps** | Stage 4 (Origin IP) | Flags `timestamp_inversion` anomaly and records `forgery_indicators`. | Increases anomaly factor; changes assessment to `anomalies_detected`. |
| **WHOIS Port 43 Blocked / Rate-Limited** | Stage 5 (WHOIS) | 5.0s graceful timeout; records `whois_status: "lookup_failed"`. | Domain age skipped; no false-positive age penalty applied. |
| **IP Geolocation API Down / Offline** | Stage 6 (Geo) | Returns default coordinates `[0.0, 0.0]` with `"country": "Unknown"`. | Radar map renders in offline fallback mode without crashing. |
| **VirusTotal HTTP 429 (Quota Exceeded)** | Stage 7 (Threat Intel) | Key rotator rotates immediately to Key #2/3/4/5 in thread-safe pool. | Continuous operation with zero downtime for SOC analysts. |
| **Complete External Network Blackout** | Stage 7 (Threat Intel) | Hits 7-day SQLite cache; if not cached, skips external calls and relies on Layer 1 local analysis. | Analysis completes 100% locally with zero external network requirement. |
| **ML Model File Missing / Corrupt** | Stage 8 (ML) | Fallback heuristic classifier computes probability from deceptive link count and urgency density. | Pipeline produces valid risk score and explainable feature list. |
| **LLM / OpenRouter API Rate-Limited** | AI Insights | Deterministic fallback generates rule-based executive summaries and plain-language translations. | Dashboard displays complete explanations without waiting for LLM. |

---

## 4. Directory Structure

```
MailGuardian-AI/
├── app.py                      # FastAPI application, route privacy guard, and REST endpoints
├── config.py                   # Central settings, RFC parameters, and threshold constants
├── database.py                 # SQLite database, 7-day threat cache, audit trail, threat memory
├── Dockerfile                  # Containerized deployment manifest
├── docker-compose.yml          # Production orchestration with health checks
├── requirements.txt            # Production Python dependencies
├── core/
│   ├── pipeline.py             # 10-stage forensic pipeline orchestrator
│   ├── parser.py               # RFC 5322 MIME parser & deceptive URL detector
│   ├── auth.py                 # PSL-aware SPF, Multi-DKIM, and DMARC alignment (RFC 7489)
│   ├── relay.py                # Relay trust model, hop traversal, and anomaly detection
│   ├── threat_intel.py         # Multi-tier selective threat enrichment & 5-key VT pool
│   ├── local_analyzer.py       # Zero-network heuristics & lexical analysis engine
│   ├── risk_engine.py          # Calibrated risk engine v2026.1 with decoupled confidence
│   ├── ml_classifier.py        # Scikit-learn TF-IDF & heuristic feature classifier
│   ├── report.py               # ReportLab Platypus PDF generator (Section 65B certified)
│   ├── ai_intelligence.py      # LLM reasoning integration & plain-language translation
│   ├── llm_client.py           # Multi-provider resilient LLM client (OpenRouter, Gemini, Local)
│   └── prompts.py              # PII-sanitized forensic reasoning system prompts
├── static/
│   ├── css/style.css           # UI styling & animations
│   └── js/dashboard.js         # Leaflet.js radar, dynamic modals, and analyst filters
├── templates/
│   ├── landing.html            # Public landing page (zero sensitive data exposure)
│   ├── login.html              # Analyst authentication portal
│   ├── dashboard.html          # Protected SOC forensic command center
│   └── index.html              # Standalone landing template
├── samples/
│   ├── clean_sample.eml        # Benign test message (DMARC pass, legitimate hops)
│   ├── phishing_sample.eml     # Credential phishing attack (deceptive anchor, threat IP)
│   └── spoofed_sample.eml      # Display name spoofing (DMARC alignment failure)
├── runbooks/                   # Production incident response and recovery runbooks
└── tests/
    └── test_forensic_pipeline.py # Comprehensive 8-test unit verification suite
```

---

## 5. Quick Start & Installation

### 1. Prerequisites
- Python 3.10, 3.11, or 3.12
- Git

### 2. Clone and Setup
```bash
git clone git@github.com:AnkitG791m/MailSuraksha-AI.git
cd MailSuraksha-AI

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Automated Test Harness
Verify all RFC alignment, relay trust, and evidence integrity tests:
```bash
PYTHONPATH=packages:. python3 -m unittest discover -s tests -v
```

Expected output:
```text
test_calibrated_scoring_schema_and_decoupling ... ok
test_pre_parse_hash_stability ... ok
test_clock_inversion_anomaly_detection ... ok
test_relay_trust_model_and_candidate_attribution ... ok
test_multi_dkim_signatures_evaluation ... ok
test_public_suffix_organizational_domain ... ok
test_spf_strict_vs_relaxed_alignment ... ok
test_untrusted_auth_results_filtering ... ok

Ran 8 tests in 14.730s
OK
```

### 4. Launch the Application
```bash
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```
Open **http://localhost:8000** in your browser.

---

## 6. API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Public landing page & platform capabilities |
| `GET` | `/login` | Analyst authentication portal |
| `GET` | `/dashboard` | Protected SOC forensic command center |
| `POST` | `/api/analyze` | Multipart `.eml` upload for instant 10-step forensic analysis |
| `GET` | `/api/sample/{type}` | 1-click test with `clean`, `phishing`, or `spoofed` sample |
| `GET` | `/api/reports/{id}/pdf` | Download official Section 65B forensic PDF dossier |
| `GET` | `/api/reports/{id}/json`| Export structured machine-readable JSON evidence |
| `POST`| `/api/investigate/chat`| Context-grounded AI forensic chatbot assistant |

---

## 7. License & Disclaimers

- **License:** MIT License. Enterprise Cyber Defense Solution.
- **Forensic Disclaimer:** MailGuardian AI generates candidate technical intelligence and forensic documentation support. Conclusive human attribution requires lawful ISP subscriber subpoenas and judicial warrants. Electronic admissibility of Section 65B certificates is subject to court appraisal under the Indian Evidence Act / Bharatiya Sakshya Adhiniyam (BSA).
