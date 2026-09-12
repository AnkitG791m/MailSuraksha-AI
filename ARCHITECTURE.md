# MailSuraksha AI — System Architecture & Forensic Pipeline Specification

**Version:** 2.1.0  
**Compliance Standards:** RFC 5322, RFC 7208, RFC 6376, RFC 7489, Section 65B (Indian Evidence Act / BSA 2023)  
**Classification:** Evidence-Preserving Enterprise SOC Architecture

---

## 1. High-Level Architecture Overview

MailSuraksha AI implements an automated 10-layer forensic pipeline designed to ingest raw email messages (`.eml`), verify cryptographic provenance, trace hop-by-hop relay paths, query live threat intelligence providers, evaluate ML risk classifiers, and generate tamper-evident Section 65B forensic audit packages.

```
+-------------------------------------------------------------------------------+
|                       INGESTION & PARSING (Layers 1 - 3)                      |
|  Raw .eml Ingestion -> Cryptographic Hashing (SHA-256) -> RFC 5322 Parsing    |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                  STANDARDS-AWARE AUTHENTICATION (Layer 4)                     |
|  SPF (RFC 7208)  |  DKIM (RFC 6376)  |  RFC 7489 Alignment Matrix (DMARC)     |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                 RELAY TRAVERSAL & MULTI-TIER ATTRIBUTION (Layer 5)            |
|  Earliest Observed IP | First Trusted Relay IP | Probable Origin IP (Lead)    |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                ENRICHMENT & THREAT INTELLIGENCE (Layers 6 - 7)                |
|  IP Geolocation Radar | AbuseIPDB | VirusTotal Multi-Key Rotator | AlienVault |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|              COMPOSITE SCORING & GRAPH CORRELATION (Layers 8 - 9)             |
|  Gradient Ensemble ML | Weighted Heuristics | Entity Graph (SVG Mapping)      |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|             EVIDENTIARY REPORTING & INVESTIGATION ASSISTANT (Layer 10)        |
|  Section 65B PDF Evidence Certificate | JSON Dossier | Forensic SOC Assistant |
+-------------------------------------------------------------------------------+
```

---

## 2. 10-Layer Forensic Pipeline Details

### Layer 1: Ingestion & Integrity Hashing
- **Input:** Raw binary `.eml` or RFC 822 stream.
- **Integrity Baseline:** Generates immediate SHA-256 and MD5 cryptographic hashes before any internal memory transformation.
- **Evidence Storage:** Preserves raw message byte streams in compliant, immutable storage for chain-of-custody verification.

### Layer 2: RFC 5322 Structural Header Parsing
- Extracts envelope senders (`Return-Path`), display addresses (`From`), response targets (`Reply-To`), routing instructions (`Received`, `X-Originating-IP`), and diagnostic fields (`Authentication-Results`, `DKIM-Signature`, `Message-ID`).
- Identifies missing, malformed, or injected duplicate headers.

### Layer 3: Lexical & Homoglyph Anomaly Analysis
- Evaluates domain character entropy and Unicode punycode encodings.
- Computes Levenshtein edit distance against top corporate and institutional domain names.
- Analyzes Reply-To divergence against Header From to flag executive impersonation.

### Layer 4: RFC 7489 Standards-Aware Authentication Matrix
- **SPF Verification (RFC 7208):** Evaluates envelope sender against DNS TXT records (`pass`, `neutral`, `softfail`, `fail`, `none`).
- **DKIM Verification (RFC 6376):** Validates cryptographic RSA/Ed25519 signature headers (`a=`, `d=`, `s=`, `b=`, `bh=`).
- **RFC 7489 DMARC Alignment Matrix:**
  - Evaluates **Strict Alignment** (`aspf=s`, `adkim=s` requiring exact domain match).
  - Evaluates **Relaxed Alignment** (`aspf=r`, `adkim=r` allowing organizational domain match).
  - Computes effective DMARC policy action (`none`, `quarantine`, `reject`).

### Layer 5: Hop-by-Hop Received Chain Traversal & 3-Tier IP Attribution
Instead of making single-IP attribution claims, the traversal engine classifies network leads into three forensic categories:
1. `earliest_observed_ip`: The earliest IP address recorded in the deepest non-private `Received` header.
2. `first_trusted_relay_ip`: The edge border relay connecting the sender's network to enterprise MX infrastructure.
3. `probable_origin_ip`: The highest-probability sender lead after excluding bogons, private subnets (RFC 1918), loopbacks, and known cloud carrier pools.
- Attaches an explicit attribution confidence percentage and forensic limitations disclosure.

### Layer 6: Origin Geolocation Radar & ASN Resolution
- Resolves autonomous system number (ASN), ISP name, country, and geographic coordinates.
- Tagged with operational provenance: `LIVE`, `CACHED`, `FALLBACK`, or `UNAVAILABLE`.

### Layer 7: Multi-Source Threat Intelligence Orchestration
- **AbuseIPDB:** Real-time IP abuse confidence score and historical malicious report count.
- **VirusTotal Multi-Key Rotator:** High-availability API key pool rotator with telemetry tracking to inspect IP reputation, domain threat flags, and file attachment hashes.
- **AlienVault OTX:** Open Threat Exchange pulse associations and adversary campaign linkages.

### Layer 8: Explainable Composite Risk Scoring Engine
- Combines Gradient Ensemble ML classification with deterministic forensic weighting:
  - Base Score = `0.40 * ML_Probability + 0.60 * Heuristic_Deductions`
- Emits transparent **Scoring Explanations** with numerical impact points (`+30 pts`, `+25 pts`).
- Emits **Actionable Incident Containment Playbooks** for Tier-1 SOC analysts.

### Layer 9: Threat Indicator Correlation Graph
- Dynamically constructs an interconnected relational graph of entities:
  - Email Nodes, From Domains, Reply-To Domains, Origin IPs, Edge ASNs, Embedded URLs, and Attachments.
  - Generates interactive SVG visualization with node clustering.

### Layer 10: Section 65B Statutory Evidence Reporting & SOC Assistant
- Compiles tamper-evident forensic PDF and machine-readable JSON dossiers.
- Generates a **Statutory Certificate of Electronic Evidence** compliant with Section 65B of the Indian Evidence Act / Section 63 of Bharatiya Sakshya Adhiniyam (BSA) 2023.
- Embeds SHA-256 hash digests, chain-of-custody signatures, and explicit probabilistic attribution disclaimers.
- Provides interactive context-aware natural language SOC assistant for real-time investigation queries.

---

## 3. Privacy & Security Architecture

- **Strict Route Separation:**
  - Public marketing overview: `/` (zero sensitive email records exposed).
  - Private analyst portal: `/login`.
  - Protected SOC workspace: `/dashboard`.
- **Session Authentication:** Cryptographically signed session tokens (`HMAC-SHA256`) delivered via HttpOnly, SameSite cookies.
- **Endpoint Protection:** API endpoints (`/api/history`, `/api/analyze`, `/api/analysis/{id}`) enforce active session authentication, returning `401 Unauthorized` on unauthenticated requests.
