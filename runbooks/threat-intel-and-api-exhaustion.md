# Incident: External Threat Intel & LLM API Exhaustion or Network Outage

## Purpose

Operational procedure when external threat intelligence providers (VirusTotal, AbuseIPDB, AlienVault OTX) or AI language model providers (OpenRouter, Google Gemini) exceed rate limits (HTTP 429), encounter authentication failures (HTTP 401/403), or suffer upstream network outages.

## Impact

- High-risk emails (>70 local score) cannot fetch fresh live reputation scores from VirusTotal or AbuseIPDB.
- AI Copilot chat (`/api/investigate/chat`) and automated executive summaries degrade to deterministic local heuristic fallbacks.
- Analysis pipeline execution times may increase by 4.0s (default `THREAT_INTEL_TIMEOUT_SECONDS`) per unreachable provider.

## Symptoms

- Telemetry endpoint `GET /api/threat-intel/stats` shows:
  - `rate_limit_hits_429 > 0` for all configured VirusTotal keys.
  - Providers failing with status `rate_limited_429`, `api_error`, or `timeout`.
- Logs display:
  - `[VTKeyRotator] HTTP 429 on Key #...`
  - `[LLMClient] OpenRouter error HTTP 429/401`
  - `[LLMClient] Gemini Key ... quota exceeded`
  - `[LLMClient] Falling back to Tier 5 Local Heuristic Engine`
- Analyses continue to finish because Layer 1 local scoring and SQLite caching protect against total crashes, but enriched external intelligence is missing or cached.

## Severity

**P1 — Serious Production Degradation (Subsystem Fallback Active)**

## Immediate Actions

1. Query live threat intel and cache telemetry:
   ```bash
   curl -s http://127.0.0.1:8000/api/threat-intel/stats | python3 -m json.tool
   ```
2. Verify outbound DNS and external API connectivity from the host or container:
   ```bash
   # Test VirusTotal reachability:
   curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 https://www.virustotal.com/api/v3/
   # Test OpenRouter reachability:
   curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 https://openrouter.ai/api/v1/models
   ```
3. Check `.env` configuration to verify which provider keys are populated:
   ```bash
   grep -E "^(VIRUSTOTAL|ABUSEIPDB|ALIENVAULT|OPENROUTER|GEMINI)" .env | sed 's/=.*/=<CONFIGURED>/'
   ```

## Diagnosis

### Step 1: Check VirusTotal Multi-Key Pool
MailGuardian AI uses `VTKeyRotator` to pool up to 5 keys configured in `VIRUSTOTAL_API_KEYS`. Check if all keys have exhausted their per-minute (4 req/min) or daily (500 req/day) free quota:
```bash
python3 -c "
from config import settings
from core.threat_intel import vt_rotator
print('Configured keys count:', len(settings.VIRUSTOTAL_API_KEYS))
print('Telemetry:', vt_rotator.get_telemetry())
"
```

### Step 2: Check Threat Intel Cache Health
The platform caches threat indicators for 7 days (`CACHE_TTL_DAYS=7`). Verify that the cache is being read:
```bash
sqlite3 data/securex.db "SELECT count(*), max(last_scanned_at) FROM threat_intel_cache;"
```

### Step 3: Check LLM Client Tier Status
Inspect which LLM tier is handling executive summaries:
- **Tier 1:** OpenRouter (`OPENROUTER_API_KEY`)
- **Tier 2-4:** Google Gemini failover keys (`GEMINI_API_KEY_1`, `2`, `3`)
- **Tier 5:** Local deterministic heuristics (No external API needed)

Run an LLM dry-run to identify the failing tier:
```bash
python3 -c "
from core.llm_client import LLMClient
client = LLMClient()
res, tele = client.generate('You are an expert.', 'Ping test', expect_json=False)
print('Provider used:', tele.get('provider_used'))
print('Fallback triggered:', tele.get('fallback_triggered'))
print('Latency ms:', tele.get('latency_ms'))
"
```

## Recovery

### Scenario A: Rotating In Fresh API Keys (REQUIRES HUMAN APPROVAL)
If all VirusTotal or Gemini keys are exhausted:
1. Obtain fresh or upgraded API keys from provider consoles.
2. Update `.env` with the new keys (comma-separated for VirusTotal):
   ```bash
   # Example format (replace with valid keys):
   # VIRUSTOTAL_API_KEYS=key1,key2,key3
   # GEMINI_API_KEY_1=new_key_here
   ```
3. Restart the application service to load updated configuration:
   ```bash
   # Docker:
   docker compose restart mailguardian
   # Host:
   pkill -f "uvicorn.*app:app" && python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 &
   ```

### Scenario B: Upstream Outage / Air-Gapped Network Operation (SAFE AUTOMATION)
If the host has lost outbound internet connectivity or external APIs are suffering global outages:
1. Verify that Layer 1 zero-network scoring is active:
   - MailGuardian AI is designed to function 100% offline. The pipeline uses `local_analyzer.py` (SPF/DKIM header checks, URL anchor mismatches, domain age, typosquatting heuristics, and Random Forest ML).
2. The platform automatically suppresses external calls for low-risk emails (`local_score < 50`).
3. To temporarily disable slow network retries during prolonged outages, set the timeout to 1.0s in `.env`:
   ```bash
   THREAT_INTEL_TIMEOUT_SECONDS=1.0
   ```
   and restart the service.

## Validation

1. Verify telemetry endpoint reports active status:
   ```bash
   curl -s http://127.0.0.1:8000/api/threat-intel/stats | grep -E "(total_keys|active_key_index)"
   ```
2. Test an end-to-end sample scan:
   ```bash
   curl -s http://127.0.0.1:8000/api/sample/phishing | python3 -c "
   import sys, json
   d = json.load(sys.stdin)
   print('Risk Score:', d.get('risk_score'))
   print('Threat Intel Origin Status:', d.get('threat_intel', {}).get('origin_ip_intel', {}).get('abuseipdb', {}).get('status'))
   "
   ```
   Expected: Valid risk score returned without error.

## Rollback

- If updated API keys in `.env` cause syntax errors or invalid authentication:
  - Revert `.env` changes from backup copy or version control template:
    ```bash
    git checkout .env 2>/dev/null || cp .env.bak .env
    docker compose restart mailguardian
    ```

## Escalation

- Escalate to SecOps Lead if:
  - Corporate egress firewall is blocking outbound HTTPS to threat intelligence services.
  - Enterprise API contracts need billing renewal or increased rate-limit quotas.

## Do Not

- **DO NOT** commit real API keys to git repositories or public tickets.
- **DO NOT** disable the `local_analyzer` or `risk_scorer` fallbacks in Python code.
- **DO NOT** set `THREAT_INTEL_TIMEOUT_SECONDS` to a large value (e.g. >15s), which causes HTTP requests to hang and exhausts server worker threads.

## Root Cause Follow-Up

1. Monitor daily threat intel consumption via `/api/threat-intel/stats`.
2. Ensure the 7-day SQLite indicator cache is operational to avoid duplicate queries for known bad actors.
3. Review whether adding additional rotating free-tier keys or upgrading to paid tier is required for your analysis volume.
