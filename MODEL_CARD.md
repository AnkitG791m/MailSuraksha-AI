# MailGuardian AI — Machine Learning Model Card

**Model Name:** MailGuardian Forensic Gradient Ensemble (FGE-v2)  
**Version:** 2.1.0  
**Status:** Target benchmark specification — provisional and subject to independent validation against the reproducible test harness.  
**Release Date:** September 2026  
**License:** Apache 2.0  
**Model Type:** Supervised Hybrid Gradient Boosting Classifier (LightGBM + Random Forest Meta-Estimator)  
**Target Domain:** Enterprise Email Threat Intelligence, Forensic Investigation & Spoofing Detection

---

## 1. Executive Summary & Verification Notice

> [!IMPORTANT]
> **Provisional Evaluation Notice:**  
> The quantitative metrics presented in this document represent **target benchmark specifications** established during prototyping. They are provisional and not yet independently verified across multi-institution evaluation sets. In strict adherence to forensic rigor, production deployment requires executing the reproducible evaluation harness described in Section 4.

MailGuardian FGE-v2 is an explainable machine learning model engineered for email threat classification and forensic attribution. The model operates on a 42-dimensional forensic feature vector extracted across header cryptographic integrity, DNS authentication alignment (RFC 7489), received relay path divergence, domain lexical entropy, and multi-source threat intelligence.

The model classifies ingested `.eml` emails into three actionable risk categories:
- **Clean (Risk Score: 0–30):** Valid authentication, standard relay transit, high-reputation infrastructure.
- **Suspicious (Risk Score: 31–60):** Policy anomalies, relay discrepancies, unaligned DKIM/SPF, or newly registered domains.
- **Malicious (Risk Score: 61–100):** Explicit spoofing, confirmed threat intelligence indicators, weaponized links, or severe RFC alignment failures.

---

## 2. Target Dataset Specifications

### 2.1 Proposed Training Corpus
Target training and evaluation corpus composition:

| Sub-Corpus Source | Proposed Category | Samples | Description |
| :--- | :--- | :--- | :--- |
| **Enron Email Corpus (Clean Subset)** | Benign / Enterprise | 7,200 | Corporate communication showing normal internal routing. |
| **SpamAssassin Public Corpus** | Spam / Low-Risk | 3,850 | Unsolicited bulk marketing, low-entropy spam, and automated notifications. |
| **APWG Phishing Archive & OpenPhish** | Malicious / Phishing | 4,200 | Credential harvesting, executive impersonation, lookalike domains. |
| **CERT-In / Synthetic Adversarial Vectors** | Advanced Threats | 3,200 | BEC, zero-hop spoofing, homoglyph punycode attacks, anomalous relay injection. |
| **Total Ingested Corpus** | — | **18,450** | Target labeled corpus with cryptographic verification. |

### 2.2 Proposed Split Protocol
- **Train Split:** 80% (14,760 emails) with 5-fold stratified cross-validation (random seed: 42).
- **Holdout Test Split:** 20% (3,690 emails) held back for evaluation.

---

## 3. Target Performance Metrics (Provisional Specifications)

Target operational metrics established for model tuning:

| Metric | Target Specification | Note |
| :--- | :---: | :--- |
| **Overall Accuracy** | **98.2%** | Target benchmark on holdout test set |
| **Precision (Malicious)** | **98.4%** | Target specification to minimize false positive quarantines |
| **Recall / True Positive Rate** | **97.1%** | Target specification to detect stealthy low-volume BEC attacks |
| **F1-Score (Macro)** | **0.977** | Harmonic balance between precision and recall |
| **Area Under ROC Curve (ROC-AUC)** | **0.992** | Target discriminative capability |
| **False Positive Rate (FPR)** | **< 1.0%** | Designed to prevent alert fatigue in enterprise SOCs |

*Disclaimer: These figures are target engineering specifications and should not be cited as certified production metrics until verified by an independent third-party audit.*

---

## 4. Reproducible Evaluation Harness Protocol

To independently verify these metrics, evaluators must run:
1. `python3 -m unittest discover -s tests -v` (core engine tests).
2. Execute the evaluation script with a fixed seed (`seed=42`).
3. Verify that the confusion matrix does not exhibit data leakage between train and test splits.

---

## 5. Feature Engineering (42 Forensic Features)

1. **Cryptographic Alignment (10 features):**
   - SPF authentication result (pass, softfail, fail, none, neutral)
   - DKIM multi-signature authentication statuses
   - DMARC published policy (`none`, `quarantine`, `reject`)
   - RFC 7489 Strict vs. Relaxed identifier alignment (Header From vs RFC 5321 MAIL FROM)
   - DKIM domain (`d=`) alignment with Header From

2. **Routing & Relay Divergence (8 features):**
   - Monotonic Received header timestamp verification
   - Hop count and public/private IP boundary transitions
   - Bogon/Private IP leakage in external transit hops
   - Reverse DNS pointer mismatch (PTR record validation)

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

5. **Structural & Payload Indicators (6 features):**
   - High-risk MIME attachment extensions (`.vbs`, `.iso`, `.exe`, `.hta`, `.scr`)
   - Hidden or obfuscated HTML JavaScript injection
   - Text-to-image ratio (image-only phishing detection)
   - Urgency sentiment score (lexical heuristic analysis)

---

## 6. Interpretability & Explainability

- **Decoupled Confidence:** Analysis confidence (completeness of data inputs) is tracked separately from risk score and candidate origin IP attribution.
- **Calibrated Scoring Factors:** Structured signals with explicit impact points and severity levels under `scoring_version: "2026.1"`.
- **Standardized Playbooks:** Actionable containment playbooks with scope, impact level, and analyst approval requirements.
