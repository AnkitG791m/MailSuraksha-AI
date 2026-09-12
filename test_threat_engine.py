import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
packages_dir = BASE_DIR / "packages"
if packages_dir.exists() and str(packages_dir) not in sys.path:
    sys.path.insert(0, str(packages_dir))

from core.pipeline import pipeline
from core.threat_intel import vt_rotator
from database import db


def run_tests():
    print("=" * 70)
    print(" SECUREX PRODUCTION THREAT INTELLIGENCE & THREAT MEMORY TESTS ")
    print("=" * 70)

    # 1. Test Low Risk (< 50) -> Zero External API Calls Rule
    print("\n[TEST 1] Testing Low Risk (< 50) Zero-API-Call Rule with clean_sample.eml...")
    with open(BASE_DIR / "samples" / "clean_sample.eml", "rb") as f:
        clean_bytes = f.read()

    res_clean = pipeline.process_eml(clean_bytes, "clean_sample.eml")
    local_clean = res_clean["local_analysis"]
    telemetry_clean = res_clean["threat_intel"]["telemetry"]

    print(f"  • Local Risk Score: {local_clean['local_risk_score']}/100 ({local_clean['classification']} Risk)")
    print(f"  • Trigger Level: {telemetry_clean['trigger_level']}")
    print(f"  • External APIs Called: {telemetry_clean['external_apis_called']}")

    assert local_clean["local_risk_score"] < 50.0, "Expected local score < 50"
    assert telemetry_clean["external_apis_called"] is False, "External APIs MUST NOT be called for clean emails!"
    assert res_clean["threat_intel"]["origin_ip_intel"]["virustotal"]["status"].startswith("skipped"), "VT must be skipped"
    print("  ✓ PASS: Clean email scored < 50 and made ZERO external API requests!")

    # 2. Test High Risk (> 70) -> External Enrichment & 7-Day Cache Storage
    print("\n[TEST 2] Testing High Risk (> 70) Enrichment & Cache Storage with phishing_sample.eml...")
    with open(BASE_DIR / "samples" / "phishing_sample.eml", "rb") as f:
        phish_bytes = f.read()

    res_phish = pipeline.process_eml(phish_bytes, "phishing_sample.eml")
    local_phish = res_phish["local_analysis"]
    telemetry_phish = res_phish["threat_intel"]["telemetry"]

    print(f"  • Local Risk Score: {local_phish['local_risk_score']}/100 ({local_phish['classification']} Risk)")
    print(f"  • Trigger Level: {telemetry_phish['trigger_level']}")
    print(f"  • External APIs Called: {telemetry_phish['external_apis_called']}")
    print(f"  • AbuseIPDB Queried: {telemetry_phish['abuseipdb_queried']}")
    print(f"  • AlienVault OTX Queried: {telemetry_phish['otx_queried']}")
    print(f"  • VirusTotal Queried: {telemetry_phish['virustotal_queried']}")

    assert local_phish["local_risk_score"] > 70.0, "Expected local score > 70 for phishing sample"
    assert telemetry_phish["external_apis_called"] is True, "Expected external enrichment for high-risk"
    print("  ✓ PASS: High-risk email (> 70) triggered multi-tier enrichment!")

    # 3. Test 7-Day Cache Hit Rule
    print("\n[TEST 3] Testing 7-Day Indicator Cache Hit (Re-running same email)...")
    res_phish_cached = pipeline.process_eml(phish_bytes, "phishing_sample.eml")
    telemetry_cached = res_phish_cached["threat_intel"]["telemetry"]
    print(f"  • Cache Hits: {telemetry_cached['cache_hits']}")
    assert len(telemetry_cached["cache_hits"]) > 0, "Expected indicator to be served from 7-day cache!"
    print("  ✓ PASS: Indicator retrieved from 7-day SQLite cache, external API call avoided!")

    # 4. Test VirusTotal Multi-Key Rotator on 429
    print("\n[TEST 4] Testing VirusTotal Multi-Key Rotator & HTTP 429 Failover...")
    initial_stats = vt_rotator.get_telemetry()
    print(f"  • Configured VT Keys: {initial_stats['total_keys']}")
    assert initial_stats['total_keys'] >= 4, "Expected at least 4 VirusTotal API keys in rotator pool"
    initial_key_idx = vt_rotator.current_idx
    print(f"  • Current Active Key: #{initial_key_idx + 1}")

    # Simulate HTTP 429 rate limit trigger
    vt_rotator.rotate_on_429()
    new_key_idx = vt_rotator.current_idx
    print(f"  • Key After 429 Trigger: #{new_key_idx + 1}")
    assert new_key_idx == (initial_key_idx + 1) % len(vt_rotator.keys), "Rotator should advance to next key"
    print("  ✓ PASS: VirusTotal key rotation on HTTP 429 verified successfully!")

    # 5. Test Threat Memory Engine & Campaign Correlation
    print("\n[TEST 5] Testing Threat Memory Engine & Campaign Correlation...")
    correlation = db.correlate_threat(
        origin_ip="185.220.101.5",
        sender_domain="microsoft-support-verify.com",
        subject="URGENT: Account Suspension Notice",
        urls=[]
    )
    print(f"  • Has Correlation: {correlation['has_correlation']}")
    print(f"  • Historical Incidents for IP: {correlation['ip_incident_count']}")
    print(f"  • Detected Campaign: {correlation['detected_campaign']}")
    print(f"  • Insights: {correlation['insights']}")

    assert correlation["has_correlation"] is True, "Threat Memory should correlate recurring IP/domain"
    assert correlation["ip_incident_count"] >= 1, "Should link to past incident"
    print("  ✓ PASS: Threat Memory successfully correlated recurrent malicious infrastructure!")

    print("\n" + "=" * 70)
    print(" ALL THREAT INTELLIGENCE & THREAT MEMORY TESTS PASSED 100%! ")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
