import sys
import os
from pathlib import Path

# Add project root and workspace packages to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
packages_dir = BASE_DIR / "packages"
if packages_dir.exists() and str(packages_dir) not in sys.path:
    sys.path.insert(0, str(packages_dir))

from core.pipeline import pipeline
from core.parser import EmailParser
from core.auth_check import AuthChecker
from core.origin_ip import OriginIPExtractor


def test_clean_sample():
    print("\n[TEST 1] Testing clean_sample.eml...")
    file_path = BASE_DIR / "samples" / "clean_sample.eml"
    with open(file_path, "rb") as f:
        content = f.read()

    # Step 2: Parsing
    parser = EmailParser(content)
    parsed = parser.parse_all()
    assert parsed["headers"]["from"]["email"] == "support@github.com", "From email mismatch"
    assert len(parsed["received_chain"]) >= 2, "Received chain missing hops"
    print("  ✓ Step 2 (Parsing) Passed: Headers & Received chain extracted correctly.")

    # Step 3: Auth Check
    auth_checker = AuthChecker(parsed["headers"])
    auth = auth_checker.check_all()
    assert auth["spf"]["status"] == "pass", "SPF should pass for clean sample"
    assert not auth["is_spoofed"], "Clean sample should not be flagged as spoofed"
    print("  ✓ Step 3 (Auth Check) Passed: SPF & DKIM verified.")

    # Step 4: Origin IP
    ip_extractor = OriginIPExtractor(parsed["received_chain"])
    origin = ip_extractor.extract()
    assert origin["origin_ip"] == "140.82.112.21", f"Expected 140.82.112.21, got {origin['origin_ip']}"
    print(f"  ✓ Step 4 (Origin IP) Passed: Extracted public origin IP {origin['origin_ip']}.")

    # End-to-end pipeline (Steps 1-10)
    result = pipeline.process_eml(content, "clean_sample.eml")
    assert result["risk"]["verdict"] == "Clean", f"Expected Clean verdict, got {result['risk']['verdict']}"
    assert Path(result["pdf_report_path"]).exists(), "PDF report not generated"
    with open(result["pdf_report_path"], "rb") as pdf_f:
        header_bytes = pdf_f.read(4)
        assert header_bytes == b"%PDF", "Invalid PDF header magic bytes"
    print(f"  ✓ End-to-End Clean Sample Passed: Verdict={result['risk']['verdict']}, Score={result['risk']['risk_score']}/100, PDF verified.")


def test_phishing_sample():
    print("\n[TEST 2] Testing phishing_sample.eml...")
    file_path = BASE_DIR / "samples" / "phishing_sample.eml"
    with open(file_path, "rb") as f:
        content = f.read()

    # Step 2: Parsing & Deceptive link detection
    parser = EmailParser(content)
    parsed = parser.parse_all()
    assert parsed["urls"]["has_mismatches"], "Should detect mismatched hyperlink anchor vs href"
    print(f"  ✓ Step 2 (Parsing) Passed: Detected {len(parsed['urls']['mismatched_links'])} deceptive link mismatch(es).")

    # Step 3: Auth Check
    auth_checker = AuthChecker(parsed["headers"])
    auth = auth_checker.check_all()
    assert auth["spf"]["status"] == "fail", "SPF should fail for phishing sample"
    assert auth["is_spoofed"], "Should be flagged as spoofed identity"
    print("  ✓ Step 3 (Auth Check) Passed: Detected failing SPF and spoofed sender.")

    # Step 4: Origin IP
    ip_extractor = OriginIPExtractor(parsed["received_chain"])
    origin = ip_extractor.extract()
    assert origin["origin_ip"] == "185.220.101.5", f"Expected 185.220.101.5, got {origin['origin_ip']}"
    print(f"  ✓ Step 4 (Origin IP) Passed: Extracted origin IP {origin['origin_ip']}.")

    # End-to-end pipeline
    result = pipeline.process_eml(content, "phishing_sample.eml")
    assert result["risk"]["verdict"] == "Malicious", f"Expected Malicious, got {result['risk']['verdict']}"
    assert result["risk"]["risk_score"] >= 70.0, f"Expected risk score >= 70, got {result['risk']['risk_score']}"
    print(f"  ✓ End-to-End Phishing Sample Passed: Verdict={result['risk']['verdict']}, Score={result['risk']['risk_score']}/100, Confidence={result['risk']['confidence_pct']}%.")


def test_spoofed_sample():
    print("\n[TEST 3] Testing spoofed_sample.eml...")
    file_path = BASE_DIR / "samples" / "spoofed_sample.eml"
    with open(file_path, "rb") as f:
        content = f.read()

    # Step 2: Parsing & Reply-To / Return-Path mismatch
    parser = EmailParser(content)
    parsed = parser.parse_all()
    assert parsed["headers"]["reply_to"]["mismatch_with_from"], "Should detect Reply-To mismatch"
    assert parsed["headers"]["return_path"]["mismatch_with_from"], "Should detect Return-Path mismatch"
    print("  ✓ Step 2 (Parsing) Passed: Detected fraudulent Reply-To and Return-Path mismatches.")

    # Step 4: Origin IP
    ip_extractor = OriginIPExtractor(parsed["received_chain"])
    origin = ip_extractor.extract()
    assert origin["origin_ip"] == "194.26.29.112", f"Expected 194.26.29.112, got {origin['origin_ip']}"
    print(f"  ✓ Step 4 (Origin IP) Passed: Extracted offshore origin IP {origin['origin_ip']}.")

    # End-to-end pipeline
    result = pipeline.process_eml(content, "spoofed_sample.eml")
    assert result["risk"]["verdict"] in ("Suspicious", "Malicious"), f"Expected high risk, got {result['risk']['verdict']}"
    print(f"  ✓ End-to-End Spoofed Sample Passed: Verdict={result['risk']['verdict']}, Score={result['risk']['risk_score']}/100.")


if __name__ == "__main__":
    print("=" * 65)
    print(" SecureX Forensic Intelligence & Threat Detection Pipeline Tests")
    print("=" * 65)
    test_clean_sample()
    test_phishing_sample()
    test_spoofed_sample()
    print("\n" + "=" * 65)
    print(" ALL FORENSIC PIPELINE INTEGRATION TESTS PASSED SUCCESSFULLY! ")
    print("=" * 65)
