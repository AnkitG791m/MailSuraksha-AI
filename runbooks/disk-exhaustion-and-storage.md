# Incident: Storage Exhaustion in Reports and Data Volumes

## Purpose

Operational procedure when disk space or inode capacity is exhausted in the local host or Docker container volumes hosting `reports/` and `data/`.

## Impact

- Forensic analysis pipeline fails during report generation (`ReportLab` fails with `OSError: [Errno 28] No space left on device`).
- SQLite cannot write new analyses or WAL checkpoints (`sqlite3.OperationalError: disk I/O error`).
- System log writes fail, and container crashes or refuses to start.

## Symptoms

- Analysis API `POST /api/analyze` returns HTTP 500 with:
  - `OSError: [Errno 28] No space left on device`
  - `sqlite3.OperationalError: disk I/O error`
- PDF report download fails with `Forensic PDF report not found`.
- Operating system or monitoring alert: Disk utilization $\ge 90\%$ on `/app` or host filesystem.

## Severity

**P1 — Serious Production Degradation / Feature Failure**

## Immediate Actions

1. Check disk utilization and inode availability immediately:
   ```bash
   df -h . data reports
   df -i . data reports
   ```
2. Identify the largest files and directory space consumers:
   ```bash
   du -sh data reports ml static 2>/dev/null
   ```
3. Locate the largest files in `reports/`:
   ```bash
   ls -lhS reports/ | head -n 20
   ```

## Diagnosis

### Step 1: Differentiate Disk Space vs Inode Exhaustion
- If `df -h` shows space available, but `df -i` shows 100% inode usage: Millions of small temporary files or `.json` reports have consumed all inode metadata entries.
- If `df -h` shows 100% full: Large PDFs, Docker layers, or uncontrolled WAL files have consumed disk capacity.

### Step 2: Check SQLite WAL Log Size
```bash
ls -lh data/securex.db*
```
If `data/securex.db-wal` has grown excessively (e.g. several gigabytes), SQLite transactions have not been truncated.

### Step 3: Check Docker Storage (If Docker Deployed)
```bash
docker system df
```
Dangling images and build caches from repeated builds can fill the host `/var/lib/docker` volume.

## Recovery

### Scenario A: Pruning Stale Reports (>30 Days Old) (SAFE AUTOMATION)
If disk is filled by accumulated PDF/JSON reports:
1. Check the count of reports older than 30 days:
   ```bash
   find reports/ -type f \( -name "*.pdf" -o -name "*.json" \) -mtime +30 | wc -l
   ```
2. Archive older reports to a compressed tarball before removal (or directly purge if compliance allows):
   ```bash
   mkdir -p /tmp/report_archives
   find reports/ -type f \( -name "*.pdf" -o -name "*.json" \) -mtime +30 -print0 | \
     tar -czvf /tmp/report_archives/reports_archive_$(date +%F).tar.gz --null -T -
   ```
3. Remove files older than 30 days:
   ```bash
   find reports/ -type f \( -name "*.pdf" -o -name "*.json" \) -mtime +30 -delete
   ```

### Scenario B: Truncating SQLite WAL Files (SAFE AUTOMATION)
If `data/securex.db-wal` is occupying excessive disk:
1. Trigger a manual checkpoint to merge WAL frames and truncate the file:
   ```bash
   sqlite3 data/securex.db "PRAGMA wal_checkpoint(TRUNCATE);"
   ```
2. Re-check file size:
   ```bash
   ls -lh data/securex.db*
   ```

### Scenario C: Pruning Dangling Docker Resources (REQUIRES HUMAN APPROVAL)
If host disk is filled by Docker build artifacts:
```bash
# Remove unused build cache and dangling images safely:
docker image prune -f
docker builder prune -f
```

## Validation

1. Verify that disk utilization has dropped below 80%:
   ```bash
   df -h . data reports
   ```
2. Run a synthetic test analysis to confirm write capability:
   ```bash
   python3 -c "
   from core.pipeline import pipeline
   with open('samples/clean_sample.eml', 'rb') as f:
       res = pipeline.process_eml(f.read(), filename='disk_test.eml')
   print('Analysis generated report:', res.get('report_id'))
   "
   ```
   Expected output: `Analysis generated report: SECX-...`
3. Verify that the generated PDF and JSON report exist on disk:
   ```bash
   ls -l reports/ | grep "SECX-" | tail -n 2
   ```

## Rollback

- If files were deleted in error, unpack the tarball from `/tmp/report_archives`:
  ```bash
  tar -xzvf /tmp/report_archives/reports_archive_*.tar.gz -C .
  ```
- If no archive was created:
  "No verified rollback mechanism found for permanently deleted reports."

## Escalation

- Escalate to DevOps / System Administrator if:
  - Disk is physically full and no temporary files can be purged.
  - Host filesystem volume needs expansion (`lvextend` or cloud disk resizing).

## Do Not

- **DO NOT** delete the active `data/securex.db` database file to free space.
- **DO NOT** delete `.eml` sample files in `samples/` as they are required for regression testing.
- **DO NOT** run `rm -rf reports/*` indiscriminately without operator confirmation or archival.

## Root Cause Follow-Up

1. Set up an automated retention policy or cron job to archive reports older than 60/90 days.
2. Configure threshold alerting at 80% disk capacity to catch growth before it reaches 100%.
