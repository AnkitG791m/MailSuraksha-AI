# Operations Runbooks — MailGuardian AI

This directory contains verified, production-ready operational runbooks for on-call engineers, system administrators, and SOC operators maintaining the **MailGuardian AI** digital forensics and threat intelligence platform.

---

## Quick Incident Triage Matrix

| Incident | Severity | Affected Component | Runbook |
|---|---|---|---|
| **Application Down / Crashing** | **P0** | FastAPI / Uvicorn Server | [`application-down.md`](application-down.md) |
| **Database Lockup or Corruption** | **P0** | SQLite (`data/securex.db`) | [`database-corruption-and-lockup.md`](database-corruption-and-lockup.md) |
| **Storage / Disk Exhaustion** | **P1** | Local disk (`reports/`, `data/`) | [`disk-exhaustion-and-storage.md`](disk-exhaustion-and-storage.md) |
| **Threat Intel / LLM API Exhaustion** | **P1** | External APIs & Key Rotator | [`threat-intel-and-api-exhaustion.md`](threat-intel-and-api-exhaustion.md) |
| **ML Model Artifact Failure** | **P1** | Scikit-learn model (`ml/model.pkl`) | [`ml-model-failure.md`](ml-model-failure.md) |
| **Authentication & Session Failures** | **P1** | Cookie / HMAC Session Engine | [`auth-and-session-issues.md`](auth-and-session-issues.md) |

---

## Severity Definitions

- **P0 (Critical Outage / Data Integrity Risk):** Complete platform unavailability, database inaccessible or corrupted, or inability to ingest any evidence. Immediate operator response required.
- **P1 (Major Service Degradation):** Core pipeline operational, but major subsystems (external threat enrichment, report generation, or analyst authentication) failing. Requires mitigation within 1 hour.
- **P2 (Operational Impairment):** Non-blocking failure where fallback mechanisms (e.g. offline heuristic AI summaries, cached threat data) mask impact from end-users. Triage within business hours.
- **P3 (Low-Risk Maintenance):** Telemetry skew, minor cache misses, or non-critical formatting issues.

---

## Production Architecture Reference

- **Process Supervisor:** Direct Uvicorn (`uvicorn app:app --host 0.0.0.0 --port 8000`) or Docker Compose (`docker-compose.yml` service: `mailguardian`).
- **Database Engine:** SQLite 3 in WAL mode located at `data/securex.db`.
- **Evidence Storage:** Cryptographic raw hashes stored in database; generated PDF and JSON dossiers written to `reports/`.
- **Machine Learning Runtime:** Serialized Scikit-Learn bundle at `ml/model.pkl` loaded into memory by `RiskClassifier`.
- **External Dependencies:** Authoritative DNS (UDP port 53), WHOIS (TCP port 43), VirusTotal v3, AbuseIPDB v2, AlienVault OTX, OpenRouter, Google Gemini.
- **CI/CD & Rollback:** Automated deployment pipeline is **NOT VERIFIED** in this repository. Deployment is container-based or git-based manual execution.

---

## On-Call Incident Checklist

1. Identify the symptom from the triage matrix above.
2. Open the corresponding runbook.
3. Follow the **Immediate Actions** to stabilize the service without executing destructive commands.
4. Execute the step-by-step **Diagnosis** to isolate root cause.
5. Apply the safe **Recovery** steps. Any action marked `REQUIRES HUMAN APPROVAL` must not be automated without operator confirmation.
6. Verify operational recovery using the **Validation** commands.
