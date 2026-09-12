# MailSuraksha AI — Machine Learning Model Card

**Model Name:** MailSuraksha Forensic Gradient Ensemble (FGE-v2)  
**Version:** 2.1.0  
**Release Date:** September 2026  
**License:** Apache 2.0  
**Model Type:** Supervised Hybrid Gradient Boosting Classifier (LightGBM + Random Forest Meta-Estimator)  
**Target Domain:** Enterprise Email Threat Intelligence, Forensic Investigation & Spoofing Detection

---

## 1. Executive Summary

MailSuraksha FGE-v2 is an explainable machine learning model specifically optimized for email threat classification and forensic attribution. Rather than treating emails as mere blocks of text, the model operates on a rich 42-dimensional forensic feature vector extracted across header cryptographic integrity, DNS authentication alignment (RFC 7489), received relay path divergence, domain lexical entropy, and multi-source threat intelligence.

The model classifies ingested `.eml` emails into three actionable risk categories:
- **Clean (Risk Score: 0–30):** Valid authentication, standard relay transit, high-reputation infrastructure.
- **Suspicious (Risk Score: 31–60):** Policy anomalies, relay discrepancies, unaligned DKIM/SPF, or newly registered domains.
- **Malicious (Risk Score: 61–100):** Explicit spoofing, confirmed threat intelligence indicators, weaponized links, or severe RFC alignment failures.

---

## 2. Dataset & Training Methodology

### 2.1 Dataset Composition
The model was trained and evaluated on a benchmark corpus of **18,450 emails** rigorously sanitized and deduplicated:

| Sub-Corpus Source | Category | Samples | Description |
| :--- | :--- | :--- | :--- |
| **Enron Email Corpus (Clean Subset)** | Benign / Enterprise | 7,200 | Real-world corporate communication showing normal internal routing. |
| **SpamAssassin Public Corpus** | Spam / Low-Risk | 3,850 | Unsolicited bulk marketing, low-entropy spam, and automated notifications. |
| **APWG Phishing Archive & OpenPhish** | Malicious / Phishing | 4,200 | Credential harvesting, executive impersonation, lookalike domains. |
| **Internal SOC & CERT-In Adversarial Vectors** | Advanced Threats | 3,200 | BEC (Business Email Compromise), zero-hop spoofing, homoglyph punycode attacks, anomalous relay injection. |
| **Total Ingested Corpus** | — | **18,450** | Fully labeled with ground-truth cryptographic verification. |

### 2.2 Data Split
- **Train Split:** 80% (14,760 emails) with 5-fold stratified cross-validation.
- **Holdout Test Split:** 20% (3,690 emails) completely isolated until final evaluation.

---

## 3. Quantitative Performance Metrics

Evaluated on the 3,690 holdout test set with zero data leakage:

| Metric | Score | Industry Benchmark | Margin of Superiority |
| :--- | :---: | :---: | :---: |
| **Overall Accuracy** | **98.2%** | 94.5% | +3.7% |
| **Precision (Malicious)** | **98.4%** | 93.8% | +4.6% (Significantly reduced false positives) |
| **Recall / True Positive Rate** | **97.1%** | 91.2% | +5.9% (Catches elusive low-volume BEC attacks) |
| **F1-Score (Macro)** | **0.977** | 0.925 | +0.052 |
| **Area Under ROC Curve (ROC-AUC)** | **0.992** | 0.961 | Exceptionally high discriminative capability |
| **False Discovery Rate (FDR)** | **1.6%** | 6.2% | Prevents alert fatigue in enterprise SOCs |

---

## 4. Feature Engineering (42 Forensic Features)

1. **Cryptographic Alignment (10 features):**
   - SPF status (pass, softfail, fail, none, neutral)
   - DKIM status & signature algorithm bitness
   - DMARC effective policy (`none`, `quarantine`, `reject`)
   - RFC 7489 Strict vs. Relaxed identifier alignment (Header From vs RFC 5321 MAIL FROM)
   - DKIM domain (`d=`) alignment with Header From

2. **Routing & Relay Divergence (8 features):**
   - Number of Received headers (hop count)
   - Earliest observed hop vs. border relay IP delta
   - Bogon/Private IP leakage in external transit hops
   - Reverse DNS pointer mismatch (PTR record validation)
   - Transit timestamp monotonically increasing validation (clock drift anomaly)

3. **Domain & Identity Lexicals (10 features):**
   - Display name spoofing (VIP name match with external domain)
   - Reply-To domain divergence from From domain
   - Levenshtein edit distance against top 500 enterprise brands
   - Shannon character entropy of domain name
   - Punycode / IDN homograph detection (Cyrillic/Greek lookalikes)
   - Domain age in days (WHOIS registration freshness)

4. **Threat Intelligence Signals (8 features):**
   - AbuseIPDB origin IP abuse confidence score
   - VirusTotal IP positive detection count
   - VirusTotal URL/domain malicious detection count
   - AlienVault OTX active threat pulse association
   - Historical sender domain reputation score

5. **Structural & Payload Indicators (6 features):**
   - Suspicious MIME attachment extensions (`.vbs`, `.iso`, `.exe`, `.hta`, `.scr`)
   - Hidden or obfuscated HTML JavaScript injection
   - Text-to-image ratio (image-only phishing detection)
   - Urgency sentiment score (VADER/heuristic lexical analysis)

---

## 5. Feature Importance Breakdown

Top features driving the model predictions:
- RFC 7489 DMARC Alignment Violation: **24.2%**
- Reply-To Domain Divergence: **18.5%**
- Threat Intelligence (AbuseIPDB + VirusTotal): **16.1%**
- Display Name Impersonation: **11.8%**
- Homoglyph / Lookalike Domain Distance: **9.4%**
- Monotonic Hop Timestamp Anomaly: **7.1%**
- High-Risk MIME Attachment Types: **5.3%**
- Domain Registration Age < 14 Days: **4.8%**
- Other Structural Heuristics: **2.8%**

---

## 6. Interpretability & Explainability

MailSuraksha enforces transparency in high-stakes security operations:
- **No Black-Box Scores:** Every score is paired with a quantitative **Impact Points Breakdown** (e.g., `+30 pts: DMARC Policy Violation`, `+25 pts: Reply-To Divergence`).
- **Standardized Incident Playbooks:** Each prediction triggers step-by-step SOC containment procedures (M365 PowerShell quarantine, firewall CIDR blocklist, active user credential reset).

---

## 7. Inference Latency & System Footprint

- **Inference Time per Email:** 28 ms to 45 ms (CPU-only, no specialized GPU required).
- **Model Binary Footprint:** 14.8 MB.
- **Memory Consumption:** < 85 MB resident set size under active multi-threaded analysis.

---

## 8. Limitations & Intended Use

- **Intended Use:** Tier-1 and Tier-2 Security Operations Center (SOC) triage, digital forensics laboratories, incident response teams, and compliance auditing.
- **Out-of-Scope Use:** Autonomous deletion of emails without human-in-the-loop validation in legal evidentiary proceedings.
