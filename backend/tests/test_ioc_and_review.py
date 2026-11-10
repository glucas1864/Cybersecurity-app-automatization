# Iteration 2: IOC lookup/history, review reviewed_at, analyze resets review, quick regression
import os
import re
import uuid
from datetime import datetime

import pytest
import requests

BASE_URL = os.environ.get("EXPO_PUBLIC_BACKEND_URL").rstrip("/")
LLM_TIMEOUT = 120
CREDS = {"email": "debug-blue@example.com", "password": "BlueTeam123!"}


def _new_user():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    r = s.post(f"{BASE_URL}/api/auth/register", json={"email": f"TEST_{uuid.uuid4().hex[:10]}@example.com", "password": "TestBlue123!", "name": "TEST Analyst"}, timeout=30)
    assert r.status_code == 200, r.text
    s.headers.update({"Authorization": f"Bearer {r.json()['token']}"})
    return s


@pytest.fixture(scope="module")
def client():
    return _new_user()


@pytest.fixture(scope="module")
def other_client():
    return _new_user()


def _assert_iso_utc(value):
    assert isinstance(value, str) and value
    dt = datetime.fromisoformat(value)
    assert dt.utcoffset() is not None and dt.utcoffset().total_seconds() == 0


def _assert_ioc_shape(data, indicator, ioc_type):
    assert "_id" not in data
    assert data["indicator"] == indicator
    assert data["ioc_type"] == ioc_type
    assert data["classification"] in {"green", "yellow", "red"}
    assert isinstance(data["classification_label"], str) and data["classification_label"]
    assert isinstance(data["confidence"], int) and 0 <= data["confidence"] <= 100
    assert isinstance(data["summary"], str) and data["summary"].strip()
    for k in ("hypotheses", "recommended_checks", "enrichment_sources"):
        assert isinstance(data[k], list), k
    assert data["requires_manual_review"] is True
    _assert_iso_utc(data["created_at"])


# Regression
def test_health():
    r = requests.get(f"{BASE_URL}/api/health", timeout=15)
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_login_debug_user():
    r = requests.post(f"{BASE_URL}/api/auth/login", json=CREDS, timeout=15)
    if r.status_code == 401:
        reg = requests.post(f"{BASE_URL}/api/auth/register", json={**CREDS, "name": "Debug Blue"}, timeout=15)
        assert reg.status_code == 200, reg.text
        r = requests.post(f"{BASE_URL}/api/auth/login", json=CREDS, timeout=15)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token"] and body["user"]["email"] == CREDS["email"]


def test_login_invalid():
    r = requests.post(f"{BASE_URL}/api/auth/login", json={"email": CREDS["email"], "password": "wrong-pass"}, timeout=15)
    assert r.status_code == 401


# IOC lookup
def test_ioc_requires_auth():
    r = requests.post(f"{BASE_URL}/api/ioc/lookup", json={"indicator": "1.1.1.1"}, timeout=15)
    assert r.status_code == 401
    assert requests.get(f"{BASE_URL}/api/ioc/history", timeout=15).status_code == 401


def test_ioc_ipv4(client):
    r = client.post(f"{BASE_URL}/api/ioc/lookup", json={"indicator": "185.199.108.153", "notes": "firewall"}, timeout=LLM_TIMEOUT)
    assert r.status_code == 200, r.text
    _assert_ioc_shape(r.json(), "185.199.108.153", "ipv4")


def test_ioc_sha256(client):
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r = client.post(f"{BASE_URL}/api/ioc/lookup", json={"indicator": h}, timeout=LLM_TIMEOUT)
    assert r.status_code == 200, r.text
    _assert_ioc_shape(r.json(), h, "sha256")


def test_ioc_defanged_domain(client):
    r = client.post(f"{BASE_URL}/api/ioc/lookup", json={"indicator": "malicioso[.]com"}, timeout=LLM_TIMEOUT)
    assert r.status_code == 200, r.text
    _assert_ioc_shape(r.json(), "malicioso.com", "domain")


def test_ioc_validation_short(client):
    r = client.post(f"{BASE_URL}/api/ioc/lookup", json={"indicator": "a"}, timeout=15)
    assert r.status_code == 422


def test_ioc_history_order_and_isolation(client, other_client):
    r = client.get(f"{BASE_URL}/api/ioc/history", timeout=15)
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 3
    assert [i["indicator"] for i in items] == ["malicioso.com", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "185.199.108.153"]
    dates = [i["created_at"] for i in items]
    assert dates == sorted(dates, reverse=True)
    assert all("_id" not in i for i in items)
    assert all("_id" not in i.get("result", {}) for i in items)
    assert items[2]["notes"] == "firewall"
    owner = items[0]["owner_id"]
    assert all(i["owner_id"] == owner for i in items)
    other = other_client.get(f"{BASE_URL}/api/ioc/history", timeout=15)
    assert other.status_code == 200 and other.json() == []


# Review + analyze
@pytest.fixture(scope="module")
def incident(client):
    r = client.post(f"{BASE_URL}/api/incidents", json={"title": "TEST brute force SSH", "source": "SIEM", "description": "TEST multiple failed logins", "raw_logs": "TEST sshd failed password for root from 203.0.113.9 x50"}, timeout=15)
    assert r.status_code == 200
    return r.json()


def test_analyze_sets_draft_and_resets(client, incident):
    iid = incident["id"]
    r = client.post(f"{BASE_URL}/api/incidents/{iid}/analyze", json={"context": "TEST"}, timeout=LLM_TIMEOUT)
    assert r.status_code == 200, r.text
    g = client.get(f"{BASE_URL}/api/incidents/{iid}", timeout=15).json()
    assert "_id" not in g
    assert g["report_draft"] and g["report_draft"] == g["report"]
    assert g["report_reviewed"] is False and g["reviewed_at"] is None


def test_review_returns_reviewed_at_and_preserves_draft(client, incident):
    iid = incident["id"]
    before = client.get(f"{BASE_URL}/api/incidents/{iid}", timeout=15).json()
    r = client.post(f"{BASE_URL}/api/incidents/{iid}/review", json={"report": "TEST revised report by analyst"}, timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["report_reviewed"] is True
    _assert_iso_utc(body["reviewed_at"])
    g = client.get(f"{BASE_URL}/api/incidents/{iid}", timeout=15).json()
    assert g["report_reviewed"] is True
    assert g["reviewed_at"] == body["reviewed_at"]
    assert g["report"] == "TEST revised report by analyst"
    assert g["report_draft"] == before["report_draft"] and g["report_draft"]


def test_reanalyze_invalidates_review(client, incident):
    iid = incident["id"]
    r = client.post(f"{BASE_URL}/api/incidents/{iid}/analyze", json={"context": "TEST re-run"}, timeout=LLM_TIMEOUT)
    assert r.status_code == 200, r.text
    g = client.get(f"{BASE_URL}/api/incidents/{iid}", timeout=15).json()
    assert g["report_reviewed"] is False and g["reviewed_at"] is None
    assert g["report_draft"] and g["report_draft"] == g["report"]
    assert g["report_draft"] == r.json().get("report_draft")


def test_review_other_user_404(other_client, incident):
    r = other_client.post(f"{BASE_URL}/api/incidents/{incident['id']}/review", json={"report": "x"}, timeout=15)
    assert r.status_code == 404
