# MailGuardian AI — System Architecture & Forensic Pipeline Specification

**Version:** 2.1.0  
**Compliance Standards:** RFC 5322, RFC 7208, RFC 6376, RFC 7489, Section 65B (Indian Evidence Act / BSA 2023)  
**Classification:** Evidence-Preserving Enterprise SOC Architecture

---

## 1. High-Level Architecture Overview

MailGuardian AI implements an automated 10-layer forensic pipeline designed to ingest raw email messages (`.eml`), establish an immediate cryptographic baseline (SHA-256), verify cryptographic provenance, trace hop-by-hop relay paths, query live threat intelligence providers, evaluate ML risk classifiers, and generate forensically documented evidence packages suitable for examiner review.

```
+-------------------------------------------------------------------------------+
|                       INGESTION & INTEGRITY (Layers 1 - 3)                    |
|  Raw .eml Ingestion -> Pre-Parse SHA-256/MD5 Baseline -> RFC 5322 Parsing     |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                  STANDARDS-AWARE AUTHENTICATION (Layer 4)                     |
|  SPF (RFC 7208)  |  Multi-DKIM (RFC 6376)  |  RFC 7489 PSL Alignment (DMARC) |
|  Explicit Separation: dmarc.result | dmarc.policy | dmarc.disposition         |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|             RELAY TRAVERSAL & ANOMALY ASSESSMENT (Layer 5)                    |
|  Header Anomaly & Forgery Assessment | First Relay Meeting Trust Criteria     |
|  Candidate Origin Infrastructure Attribution (with Candidate Confidence)      |
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
|              CALIBRATED SCORING & GRAPH CORRELATION (Layers 8 - 9)            |
|  Decoupled Risk vs Confidence | Normalized Factors | Non-Causal Entity Graph  |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|             EVIDENTIARY REPORTING & SOC ASSISTANT (Layer 10)                  |
|  Section 65B Evidence Documentation Package | JSON Dossier | SOC Assistant    |
+-------------------------------------------------------------------------------+
```

---

## 2. 10-Layer Forensic Pipeline Details

### Layer 1: Ingestion & Evidence Integrity Baseline
- **Input:** Raw binary `.eml` or RFC 822 stream.
- **Integrity Baseline:** Generates immediate SHA-256 and MD5 cryptographic hashes before any internal memory transformation.
- **Evidence Preservation:** Preserves raw message byte streams in immutable storage for chain-of-custody verification.

### Layer 2: RFC 5322 Structural Header Parsing
- Extracts envelope senders (`Return-Path`), display addresses (`From`), response targets (`Reply-To`), routing instructions (`Received`, `X-Originating-IP`), and diagnostic fields (`Authentication-Results`, `DKIM-Signature`, `Message-ID`).
- Evaluates multiple `Authentication-Results` headers against configured `TRUSTED_AUTHSERV_IDS`.

### Layer 3: Lexical & Homoglyph Anomaly Analysis
- Evaluates domain character entropy and Unicode punycode encodings.
- Computes Levenshtein edit distance against top corporate and institutional domain names.
- Analyzes Reply-To divergence against Header From to flag potential redirection.

### Layer 4: RFC 7489 Standards-Aware Authentication Engine
- **SPF Verification (RFC 7208):** Evaluates envelope sender against DNS TXT records (`pass`, `neutral`, `softfail`, `fail`, `none`).
- **Multi-Signature DKIM Verification (RFC 6376):** Validates all `DKIM-Signature` headers independently (`d=`, `s=`, `a=`, `b=`, `bh=`).
- **RFC 7489 DMARC Alignment Matrix:**
  - Evaluates **Strict Alignment** (`aspf=s`, `adkim=s` requiring exact domain match).
  - Evaluates **Relaxed Alignment** (`aspf=r`, `adkim=r` using Public Suffix List organizational domain matching).
  - Explicitly separates:
    - `dmarc.result`: Evaluation outcome (`pass` | `fail`).
    - `dmarc.policy`: Published domain policy request (`none` | `quarantine` | `reject`).
    - `dmarc.disposition`: Action applied (`none` | `quarantine` | `reject`).

### Layer 5: Relay Chain Anomaly Assessment & Trust Model
- Does NOT claim to definitively prove forged hops from headers alone.
- Evaluates **header anomalies** (timestamp inversions, impossible routing transitions, syntax malformations) and emits a structured `forgery_assessment`.
- Evaluates relay trust basis: `configured_org_relay`, `provider_metadata`, `authentication_context`.
- Designates `candidate_origin_ip` representing candidate origin infrastructure with explicit attribution confidence and forensic caveats.

### Layer 6: Origin Geolocation Radar & ASN Resolution
- Resolves autonomous system number (ASN), ISP name, country, and geographic coordinates.
- Tagged with operational provenance: `LIVE`, `CACHED`, `FALLBACK`, or `UNAVAILABLE`.

### Layer 7: Multi-Source Threat Intelligence Orchestration
- **AbuseIPDB:** Real-time IP abuse confidence score and historical malicious report count.
- **VirusTotal Multi-Key Rotator:** High-availability API key pool rotator with telemetry tracking to inspect IP reputation, domain threat flags, and file attachment hashes.
- **AlienVault OTX:** Open Threat Exchange pulse associations and adversary campaign linkages.
- Unavailable lookups contribute zero risk points and do not artificially inflate scores.

### Layer 8: Calibrated Composite Risk Scoring Engine (v2026.1)
- Decouples `risk_score` (0–100), `risk_band`, and `analysis_confidence` (0.0–1.0).
- Emits transparent **Scoring Explanations** with numerical impact points (`+20 pts`, `+18 pts`).
- Emits **Actionable Incident Containment Playbooks** with scope, impact level, and approval requirements.

### Layer 9: Threat Indicator Correlation Graph (Non-Causal Semantics)
- Dynamically constructs an observational relational graph of entities:
  - Non-causal edges: `observed_in`, `candidate_origin_for`, `hosted_by`, `signed_by`, `linked_from`, `associated_with`.
  - Attaches `relationship_confidence` and `evidence_refs` to each edge.

### Layer 10: Section 65B Statutory Evidence Reporting & SOC Assistant
- Compiles tamper-evident forensic PDF and machine-readable JSON dossiers.
- Generates a **Statutory Certificate of Electronic Evidence** compliant with Section 65B of the Indian Evidence Act / Section 63 of Bharatiya Sakshya Adhiniyam (BSA) 2023.
- Clearly states that the package supports examiner documentation without guaranteeing automatic legal admissibility.
