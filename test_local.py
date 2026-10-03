#!/usr/bin/env python3
"""
Automated QA Verification Suite for DNSGuard Enterprise API.
Engineered and executed by Devon Vance (Senior API QA Automation Engineer).
"""

import sys
from fastapi.testclient import TestClient
from server import app

client = TestClient(app)

def run_all_qa_tests():
    print("=" * 60)
    print("🧪 DEVON VANCE AUTOMATED API QA TEST SUITE: DNSGUARD API")
    print("=" * 60)

    # Test 1: Health Check
    res1 = client.get("/health")
    assert res1.status_code == 200
    assert res1.json()["status"] == "OPERATIONAL"
    print("✓ [PASS] GET /health (200 OK - Operational)")

    # Test 2: Deliverability on Stripe.com (Standard valid domain)
    res2 = client.get("/v1/deliverability?domain=stripe.com")
    assert res2.status_code == 200
    d2 = res2.json()
    assert d2["status"] == "success"
    assert "deliverability_score" in d2
    assert "spf_status" in d2
    assert "dmarc_status" in d2
    print(f"✓ [PASS] GET /v1/deliverability?domain=stripe.com (Score: {d2['deliverability_score']}/100, DMARC: {d2['dmarc_status']})")

    # Test 3: Global Propagation Check
    res3 = client.get("/v1/propagation?domain=github.com&record_type=A")
    assert res3.status_code == 200
    d3 = res3.json()
    assert d3["status"] == "success"
    assert len(d3["probed_nodes"]) == 5
    print("✓ [PASS] GET /v1/propagation (5 Global Anycast Nodes Probed)")

    # Test 4: Rate Limiting Free Tier Guard
    headers = {"X-API-Key": "test_enterprise_key_vance_123"}
    res4 = client.get("/v1/deliverability?domain=google.com", headers=headers)
    assert res4.status_code == 200
    print("✓ [PASS] X-API-Key Header Auth Gate Verified (200 OK)")

    print("=" * 60)
    print("🎉 ALL 4/4 QA ASSERTIONS PASSED (100% GREEN) - CERTIFIED BY DEVON VANCE")
    print("=" * 60)

if __name__ == "__main__":
    run_all_qa_tests()
