# Incident: Analyst Authentication and Session Verification Failure

## Purpose

Operational recovery procedure when SOC analysts cannot log in, are repeatedly redirected back to `/login` when navigating to `/dashboard`, or when API requests return HTTP 401 Unauthorized errors.

## Impact

- Analysts cannot access the protected SOC command dashboard (`/dashboard`), Scanner section (`/scan`), or Copilot Assistant (`/assistant`).
- Automated API integrations and scripts calling `POST /api/analyze` or `GET /api/history` fail with HTTP 401 Unauthorized.
- Public landing page (`/`) continues to function normally.

## Symptoms

- Navigating to `http://<host>:8000/dashboard` immediately redirects to `http://<host>:8000/login`.
- Logging in via `/login` appears to succeed or reload, but dashboard remains inaccessible.
- API requests return:
  ```json
  {"detail": "Unauthorized. Active SOC analyst session required. Please log in at /login"}
  ```
- Browser developer tools show cookie `mailguardian_session` missing, rejected, or failing signature verification.

## Severity

**P1 — Major Feature Failure (Analyst Access Blocked)**

## Immediate Actions

1. Check if the authentication endpoint is responding:
   ```bash
   curl -s -X POST http://127.0.0.1:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "test@mailguardian.ai", "name": "Test Analyst", "role": "Lead SOC Analyst"}'
   ```
   Expected response: `{"status":"authenticated","user":{"email":"test@mailguardian.ai",...}}`
   along with `Set-Cookie: mailguardian_session=...` in response headers.
2. Check if the session verification works with the returned cookie:
   ```bash
   COOKIE=$(curl -s -i -X POST http://127.0.0.1:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "test@mailguardian.ai"}' | grep -i "set-cookie" | awk '{print $2}' | tr -d '\r;')
   
   curl -s http://127.0.0.1:8000/api/auth/me --cookie "$COOKIE"
   ```
   Expected response: `{"authenticated":true,"user":{"email":"test@mailguardian.ai",...}}`

## Diagnosis

### Step 1: Check for `SECRET_KEY` Mismatch Across Replicas or Restarts
MailGuardian AI signs cookies using HMAC-SHA256:
```python
AUTH_SECRET = getattr(settings, "SECRET_KEY", "mailguardian-secure-soc-eval-2026")
```
- If running multiple Uvicorn workers or containers behind a load balancer without a shared `SECRET_KEY` in `.env`, a session issued by Container A will fail verification on Container B.
- If the application was restarted after changing `SECRET_KEY` in `.env`, all pre-existing cookies are invalidated.

Check `.env` for `SECRET_KEY`:
```bash
grep "^SECRET_KEY=" .env 2>/dev/null || echo "SECRET_KEY not set in .env (using default fallback)"
```

### Step 2: Check Reverse Proxy / SSL Termination Issues
If MailGuardian AI is deployed behind Nginx, Caddy, or an ALB/ingress:
- If HTTPS is terminated at the proxy but proxy forwards traffic as HTTP without `X-Forwarded-Proto: https`, browsers may reject cookies configured with secure policies.
- Check if proxy is stripping the `Cookie` or `Authorization` header.

### Step 3: Check Browser Cookie Expiry and Domain Policy
- Cookie name: `mailguardian_session`
- Cookie parameters in `app.py`: `httponly=True`, `samesite="lax"`, `max_age=604800` (7 days), `path="/"`.
- If accessing via IP address vs domain name across cross-origin iframes, `samesite="lax"` may block cookie delivery.

## Recovery

### Scenario A: Standardize `SECRET_KEY` in Environment (SAFE AUTOMATION)
If running multiple instances or to prevent cookie invalidation across deployments:
1. Define a persistent `SECRET_KEY` in `.env`:
   ```bash
   # Ensure a consistent random secret exists in .env
   if ! grep -q "^SECRET_KEY=" .env; then
     echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env
   fi
   ```
2. Restart the application service:
   ```bash
   docker compose restart mailguardian
   # or
   pkill -f "uvicorn.*app:app" && python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 &
   ```

### Scenario B: API Client Using Bearer Token (SAFE AUTOMATION)
For automated scripts, CLI tools, or CI/CD pipelines calling the API directly without browser cookies:
1. Generate an authentication token:
   ```bash
   AUTH_PAYLOAD=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "service-account@mailguardian.ai", "name": "Service Account", "role": "Automation Engine"}')
   
   TOKEN=$(curl -s -i -X POST http://127.0.0.1:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "service-account@mailguardian.ai"}' | grep -i "set-cookie" | sed 's/.*mailguardian_session=\([^;]*\).*/\1/' | tr -d '\r\n')
   ```
2. Pass the token in the `Authorization` header:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/history
   ```

### Scenario C: Browser Cookie Cleansing (REQUIRES HUMAN APPROVAL)
If a user's browser holds a corrupted or stale HMAC cookie from an older version:
1. Instruct the analyst to clear cookies for the host origin or open an Incognito / Private browsing window.
2. Navigate to `/login` and submit the login form.

## Validation

1. Verify `/api/auth/login` issues valid cookies:
   ```bash
   curl -s -i -X POST http://127.0.0.1:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "analyst@test.local", "name": "Test", "role": "Analyst"}' | grep -E "(HTTP/|set-cookie)"
   ```
   Expected output: `HTTP/1.1 200 OK` and `set-cookie: mailguardian_session=...`
2. Test protected API access:
   ```bash
   TOKEN=$(curl -s -i -X POST http://127.0.0.1:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email": "analyst@test.local"}' | grep -i "set-cookie" | sed 's/.*mailguardian_session=\([^;]*\).*/\1/' | tr -d '\r\n')
   
   curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/history
   ```
   Expected output: `200`

## Rollback

- If rotating `SECRET_KEY` unexpectedly logged out all active operators during an ongoing critical incident:
  - Temporarily revert `SECRET_KEY` in `.env` to the previous value and restart the service.

## Escalation

- Escalate to Lead Application Engineer if:
  - HMAC comparison (`hmac.compare_digest`) fails despite matching secrets.
  - Custom reverse proxy is rewriting URL encoding of session cookies.

## Do Not

- **DO NOT** hardcode secrets into public client-side JavaScript.
- **DO NOT** disable the `require_auth` guard in `app.py` as a workaround (this exposes confidential evidence, email contents, and forensic reports).
- **DO NOT** share session tokens in unencrypted chat channels or ticket comments.

## Root Cause Follow-Up

1. Verify that all production container instances share the identical `SECRET_KEY` environment variable.
2. If running behind a reverse proxy (e.g., Nginx), confirm proper header forwarding:
   ```nginx
   proxy_set_header Host $host;
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   proxy_set_header X-Forwarded-Proto $scheme;
   ```
