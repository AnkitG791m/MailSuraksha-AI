# Incident: Complete Application / API Outage

## Purpose

Operational recovery procedure when the MailGuardian AI web application or REST API process is unreachable, crashing in a loop, or failing to start.

## Impact

- Analysts cannot access the SOC dashboard (`/dashboard`), authentication page (`/login`), or public landing page (`/`).
- Automated forensic pipeline (`POST /api/analyze`) cannot ingest or process `.eml` evidence files.
- Report downloads (`/api/reports/{id}/pdf`) and Copilot investigation API (`/api/investigate/chat`) return HTTP 502/503 or connection refused.

## Symptoms

- `curl -I http://127.0.0.1:8000/` returns `Connection refused` or `502 Bad Gateway`.
- Docker container `mailguardian_platform` status is `Exited`, `Restarting`, or `Dead`.
- Terminal / process logs show traceback during startup:
  - `Address already in use` (port conflict).
  - `ModuleNotFoundError` or `ImportError`.
  - `PermissionError` on `data/` or `reports/`.
  - Python traceback in `config.py`, `app.py`, or `database.py`.

## Severity

**P0 — Complete Production Outage**

## Immediate Actions

1. Check if the process or container is currently running:
   ```bash
   # Docker deployment:
   docker compose ps
   # Direct host deployment:
   pgrep -a -f "uvicorn.*app:app"
   ```
2. Verify port binding and host reachability:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/
   ```
3. If running via Docker Compose and container has crashed, inspect recent fatal logs without restarting:
   ```bash
   docker compose logs --tail=100 mailguardian
   ```

## Diagnosis

### Step 1: Check Process Logs
- **Docker Compose:**
  ```bash
  docker compose logs --tail=150 mailguardian
  ```
- **Direct Uvicorn Process:**
  Inspect the stdout/stderr stream or the active terminal / systemd service unit:
  ```bash
  journalctl -u mailguardian -n 100 --no-pager
  ```

### Step 2: Check for Port Conflicts (Port 8000)
If logs report `[Errno 98] Address already in use`:
```bash
ss -tulpn | grep :8000
# or
lsof -i :8000
```
Determine what foreign process is binding to port 8000 before terminating anything.

### Step 3: Check Filesystem Permissions
The application requires write access to `data/`, `reports/`, and `ml/`:
```bash
ls -ld data reports ml
```
If directory ownership belongs to another user or `root` inside Docker:
```bash
# Verify permissions:
test -w data && test -w reports && test -w ml && echo "Writable: OK" || echo "Permissions: FAIL"
```

### Step 4: Verify Python Dependencies and Import Integrity
Run an import dry-run inside the active environment:
```bash
# Inside virtual environment or container:
python3 -c "import app; print('App import successful')"
```
If this fails, identify missing system packages (`whois`, `dnsutils`) or Python modules (`fastapi`, `reportlab`, `scikit-learn`, `dnspython`).

## Recovery

### Scenario A: Process Terminated / Crashed Cleanly (SAFE AUTOMATION)
If the process exited due to temporary system reboot or process kill:
- **Docker Deployment:**
  ```bash
  docker compose up -d
  ```
- **Direct Host Deployment:**
  ```bash
  source venv/bin/activate
  python3 -m uvicorn app:app --host 0.0.0.0 --port 8000
  ```

### Scenario B: Port 8000 Occupied by Orphaned Process (REQUIRES HUMAN APPROVAL)
If an old, hung Uvicorn worker is blocking port 8000:
1. Identify the PID holding port 8000:
   ```bash
   lsof -t -i :8000
   ```
2. Confirm the process identity before killing:
   ```bash
   ps -fp $(lsof -t -i :8000)
   ```
3. Terminate the hung process:
   ```bash
   kill -15 <PID>
   # If unresponsive after 10s:
   kill -9 <PID>
   ```
4. Restart the application:
   ```bash
   docker compose up -d
   ```

### Scenario C: Missing System or Python Dependencies (SAFE AUTOMATION)
If running on host and dependencies are missing:
```bash
# System packages:
sudo apt-get update && sudo apt-get install -y whois dnsutils build-essential

# Python requirements:
pip install -r requirements.txt
python3 ml/train.py
```

### Scenario D: Permission Errors on Mounted Volumes (REQUIRES HUMAN APPROVAL)
If Docker volume mounts have misaligned UID/GID:
```bash
mkdir -p data reports ml
chmod 755 data reports ml
```

## Validation

1. Verify HTTP root route responds:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/
   ```
   Expected output: `200`
2. Verify authentication status endpoint:
   ```bash
   curl -s http://127.0.0.1:8000/api/auth/me
   ```
   Expected response contains: `{"authenticated":false}`
3. Verify test suite execution:
   ```bash
   PYTHONPATH=packages:. python3 -m unittest discover -s tests -v
   ```
   Expected output: `Ran 8 tests ... OK`

## Rollback

- If the crash occurred following a code or container image update:
  - **Docker Compose:** Revert to previous image tag or rebuild from known-good git commit:
    ```bash
    git checkout HEAD~1
    docker compose build --no-cache
    docker compose up -d
    ```
  - **Host Deployment:**
    ```bash
    git checkout HEAD~1
    python3 -m uvicorn app:app --host 0.0.0.0 --port 8000
    ```
- If rollback mechanism does not exist in your environment:
  "No verified automated rollback pipeline found; manual git checkout required."

## Escalation

- Escalate to Lead Developer / Infrastructure Lead if:
  - Application exits immediately with unhandled C-level crash (e.g. Scipy/Scikit-learn segmentation fault).
  - Out-of-Memory (OOM) killer terminates the process repeatedly during ML inference or report generation.
  - Port 8000 is occupied by an unidentifiable critical system service.

## Do Not

- **DO NOT** delete the `data/` directory or `data/securex.db` to fix application startup failures.
- **DO NOT** disable authentication or modify `app.py` directly on production without version control.
- **DO NOT** bypass container volume mounts, which could cause immediate loss of historical analyses and reports.

## Root Cause Follow-Up

1. Review system resource telemetry (`dmesg -T | grep -i oom`) to confirm whether the process was killed by kernel OOM.
2. Ensure process supervisor (systemd or Docker `restart: unless-stopped`) is configured to recover from transient restarts.
3. Review `config.py` environment variable overrides to ensure no malformed integer or boolean strings caused startup crashes.
