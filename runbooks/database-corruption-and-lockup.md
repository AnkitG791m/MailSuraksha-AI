# Incident: SQLite Database Lockup, Corruption, or Permission Failure

## Purpose

Operational recovery procedure when the platform's primary SQLite datastore (`data/securex.db`) becomes locked by concurrent transactions, reports filesystem corruption, or fails due to permissions.

## Impact

- All forensic scan persistance (`POST /api/analyze`) fails with HTTP 500 (`Pipeline error: database is locked` or `malformed disk image`).
- Threat memory correlations and 7-day indicator caching stop working.
- Historical analysis lists (`GET /api/history`) and past report retrieval (`GET /api/analysis/{id}`) fail.
- Investigation Copilot chat (`/api/investigate/chat`) cannot record or read chat history.

## Symptoms

- Application logs contain:
  - `sqlite3.OperationalError: database is locked`
  - `sqlite3.DatabaseError: database disk image is malformed`
  - `sqlite3.OperationalError: unable to open database file`
  - `sqlite3.OperationalError: attempt to write a readonly database`
- HTTP 500 returned on endpoints that call `database.db`.
- Multiple `.db-wal` or `.db-shm` files accumulating in `data/` without checkpointing.

## Severity

**P0 — Complete Production Outage / Data Integrity Threat**

## Immediate Actions

1. Check if the database file and directory exist and are writable:
   ```bash
   ls -la data/
   test -w data/securex.db && echo "DB file writable: OK" || echo "DB file writable: FAIL"
   ```
2. Verify if another process holds an open file lock on `data/securex.db`:
   ```bash
   fuser data/securex.db
   # or
   lsof data/securex.db
   ```
3. Take an immediate non-destructive snapshot of the current state before executing recovery:
   ```bash
   mkdir -p data/backups
   cp -p data/securex.db* data/backups/ 2>/dev/null || true
   ```

## Diagnosis

### Step 1: Run SQLite Integrity Check
Test the database integrity using the standard `sqlite3` CLI:
```bash
sqlite3 data/securex.db "PRAGMA integrity_check;"
```
- **Healthy Output:** `ok`
- **Corrupted Output:** List of specific corrupted pages or `Error: database disk image is malformed`.

### Step 2: Check WAL Mode and Pending Transactions
Inspect the Write-Ahead Log:
```bash
ls -lh data/securex.db*
```
If `data/securex.db-wal` is extraordinarily large (e.g. >100MB) while `data/securex.db` remains small, transactions are failing to checkpoint back into the main database.

### Step 3: Check Disk Space and Inodes
Verify that the filesystem is not full:
```bash
df -h data/
df -i data/
```

### Step 4: Check Permissions (Docker vs Host User)
If running inside Docker with mounted `./data:/app/data`, check that the container process UID matches host permissions:
```bash
docker compose exec securex id
ls -ld data/ data/securex.db
```

## Recovery

### Scenario A: Database Locked by Stale / Hung Process (SAFE AUTOMATION)
If an orphaned process is holding an exclusive lock on the database:
1. Identify the PIDs accessing `data/securex.db`:
   ```bash
   fuser data/securex.db
   ```
2. Gracefully stop the application service to release handles:
   ```bash
   # Docker deployment:
   docker compose stop mailguardian
   # Host deployment:
   pkill -f "uvicorn.*app:app"
   ```
3. Force a checkpoint and vacuum in truncate mode:
   ```bash
   sqlite3 data/securex.db "PRAGMA wal_checkpoint(TRUNCATE);"
   sqlite3 data/securex.db "VACUUM;"
   ```
4. Restart the service:
   ```bash
   docker compose start mailguardian
   # or
   python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 &
   ```

### Scenario B: Database Corrupted — Automated `.recover` (SAFE AUTOMATION)
If `PRAGMA integrity_check` reports corruption:
1. Stop writes immediately:
   ```bash
   docker compose stop mailguardian
   pkill -f "uvicorn.*app:app" || true
   ```
2. Create an archival copy of the corrupt file:
   ```bash
   TIMESTAMP=$(date +%s)
   cp data/securex.db "data/securex.db.corrupt_${TIMESTAMP}"
   ```
3. Use SQLite's official recovery extension to dump recoverable rows:
   ```bash
   sqlite3 data/securex.db ".recover" | sqlite3 data/securex_recovered.db
   ```
4. Verify the recovered database:
   ```bash
   sqlite3 data/securex_recovered.db "PRAGMA integrity_check;"
   ```
5. Swap the recovered database into place and fix permissions:
   ```bash
   mv data/securex.db "data/securex.db.old_${TIMESTAMP}"
   rm -f data/securex.db-wal data/securex.db-shm
   mv data/securex_recovered.db data/securex.db
   chmod 644 data/securex.db
   ```
6. Restart the application:
   ```bash
   docker compose start mailguardian
   # or
   python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 &
   ```

### Scenario C: Unrecoverable Database (Emergency Fresh Init) (REQUIRES HUMAN APPROVAL)
If the database cannot be recovered and no recent backup is restorable:
1. Move the corrupted file aside:
   ```bash
   TIMESTAMP=$(date +%Y%m%d_%H%M%S)
   mv data/securex.db "data/securex.db.dead_${TIMESTAMP}"
   rm -f data/securex.db-wal data/securex.db-shm
   ```
2. Let the application auto-initialize fresh schema tables on restart:
   ```bash
   docker compose start securex
   ```
3. Confirm fresh table creation:
   ```bash
   sqlite3 data/securex.db ".tables"
   # Expected output: analyses investigation_chat_history threat_intel_cache threat_memory
   ```

## Validation

1. Verify SQLite integrity:
   ```bash
   sqlite3 data/securex.db "PRAGMA integrity_check;"
   ```
   Expected output: `ok`
2. Verify table schema exists:
   ```bash
   sqlite3 data/securex.db "SELECT count(*) FROM analyses;"
   ```
   Expected output: An integer count $\ge 0$.
3. Run a synthetic sample scan through the API:
   ```bash
   # In terminal or container:
   python3 -c "from database import db; print('Cache stats:', db.get_cache_stats())"
   ```
   Expected output: `{'total_cached_indicators': ..., 'threat_memory_entries': ...}`

## Rollback

- If a database recovery attempt fails or causes table loss:
  - Restore the snapshot taken during Immediate Actions:
    ```bash
    cp data/backups/securex.db data/securex.db
    ```
- If no previous backup exists:
  "No verified rollback mechanism found; refer to manual recovery procedures."

## Escalation

- Escalate to Senior Database Administrator / Tech Lead if:
  - `.recover` outputs fatal syntax errors and unable to extract recent evidence records.
  - Disk corruption (bad sectors, filesystem read-only errors) detected in OS `dmesg`.

## Do Not

- **DO NOT** delete `data/securex.db-wal` while the application process is running; doing so permanently discards uncheckpointed transactions.
- **DO NOT** run concurrent write operations using external CLI tools while Uvicorn workers are actively writing.
- **DO NOT** edit database files directly using binary editors.

## Root Cause Follow-Up

1. Verify that `data/` is located on local SSD storage, not a network NFS/CIFS mount (SQLite WAL mode is unreliable over network-attached filesystems).
2. Schedule a daily automated backup cron:
   ```bash
   # Recommended safe SQLite backup command:
   sqlite3 data/securex.db ".backup 'data/backups/securex_backup_$(date +\%F).db'"
   ```
3. Check `dmesg` or system logs for kernel disk I/O errors.
