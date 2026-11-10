# Iteration 3: batch IOC lookup, single IOC enrichment, incident timeline
import os
import time
import uuid
from datetime import datetime

import pytest
import requests
from dotenv import load_dotenv

load_dotenv("/app/frontend/.env")
BASE_URL = os.environ.get("EXPO_PUBLIC_BACKEND_URL").rstrip("/")
API = f"{BASE_URL}/api"
EMAIL = "debug-blue@example.com"
PASSWORD = "BlueTeam123!"


def _iso_utc(value):
    dt = datetime.fromisoformat(value)
    assert dt.utcoffset() is not None and dt.utcoffset().total_seconds() == 0
    return dt


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json={"email": EMAIL, "password": PASSWORD}, timeout=20)
    if r.status_code != 200:
        r = s.post(f"{API}/auth/register", json={"email": EMAIL, "password": PASSWORD, "name": "Debug Blue"}, timeout=20)
    if r.status_code != 200:
        pytest.skip(f"auth failed {r.status_code}")
    s.headers.update({"Authorization": f"Bearer {r.json()['token']}", "Content-Type": "application/json"})
    return s


@pytest.fixture(scope="module")
def other_session():
    s = requests.Session()
    r = s.post(f"{API}/auth/register", json={"email": f"test_other_{uuid.uuid4().hex[:8]}@example.com", "password": "OtherPass123!", "name": "TEST_Other"}, timeout=20)
    if r.status_code != 200:
        pytest.skip("cannot create other user")
    s.headers.update({"Authorization": f"Bearer {r.json()['token']}"})
    return s


# Regression
class TestRegression:
    def test_health(self):
        r = requests.get(f"{API}/health", timeout=20)
        assert r.status_code == 200

    def test_login(self):
        r = requests.post(f"{API}/auth/login", json={"email": EMAIL, "password": PASSWORD}, timeout=20)
        assert r.status_code == 200
        assert r.json()["user"]["email"] == EMAIL and r.json()["token"]


# Batch IOC lookup
class TestBatchLookup:
    PAYLOAD = {"indicators": ["8.8.8.8", "malicioso[.]com", "44d88612fea8a8f36de82e1278abb02f", "https://exemplo.com/mal", "nope"], "notes": "TEST_batch"}

    def test_batch_requires_auth(self):
        r = requests.post(f"{API}/ioc/lookup/batch", json=self.PAYLOAD, timeout=20)
        assert r.status_code == 401

    def test_batch_full(self, session):
        t0 = time.time()
        r = session.post(f"{API}/ioc/lookup/batch", json=self.PAYLOAD, timeout=60)
        elapsed = time.time() - t0
        assert r.status_code == 200, r.text
        print(f"batch elapsed {elapsed:.2f}s")
        assert elapsed < 10
        data = r.json()
        _iso_utc(data["created_at"])
        assert data["requires_manual_review"] is True
        assert set(data["totals"].keys()) == {"green", "yellow", "red"}
        assert all(isinstance(v, int) for v in data["totals"].values())
        items = data["items"]
        assert len(items) == 5
        assert sum(data["totals"].values()) == 5
        by_ind = {i["indicator"]: i for i in items}
        assert "malicioso.com" in by_ind
        expected = {"8.8.8.8": "ipv4", "malicioso.com": "domain", "44d88612fea8a8f36de82e1278abb02f": "md5", "https://exemplo.com/mal": "url", "nope": "unknown"}
        for ind, kind in expected.items():
            it = by_ind[ind]
            assert it["ioc_type"] == kind
            assert it["classification"] in {"green", "yellow", "red"}
            assert isinstance(it["classification_label"], str) and it["classification_label"]
            assert isinstance(it["reasons"], list)
            _iso_utc(it["created_at"])
            assert it["enrichment"]["virustotal"]["status"] == "not_configured"
            exp_abuse = "not_configured" if kind == "ipv4" else "not_applicable"
            assert it["enrichment"]["abuseipdb"]["status"] == exp_abuse
        assert by_ind["nope"]["classification"] == "yellow"
        pytest.batch_created_at = data["created_at"]

    def test_history_contains_batch(self, session):
        r = session.get(f"{API}/ioc/history", timeout=20)
        assert r.status_code == 200
        hist = r.json()
        assert all("_id" not in h for h in hist)
        dates = [h["created_at"] for h in hist]
        assert dates == sorted(dates, reverse=True)
        batch_inds = {h["indicator"] for h in hist if h.get("created_at") == getattr(pytest, "batch_created_at", None)}
        assert {"8.8.8.8", "malicioso.com", "nope"} <= batch_inds
        assert hist[0]["created_at"] == pytest.batch_created_at

    def test_dedup(self, session):
        r = session.post(f"{API}/ioc/lookup/batch", json={"indicators": ["8.8.8.8", "8.8.8.8", " 8.8.8.8 "]}, timeout=30)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1

    def test_empty_list_422(self, session):
        r = session.post(f"{API}/ioc/lookup/batch", json={"indicators": []}, timeout=20)
        assert r.status_code == 422

    def test_empty_after_cleanup_400(self, session):
        r = session.post(f"{API}/ioc/lookup/batch", json={"indicators": ["  ", ""]}, timeout=20)
        assert r.status_code == 400

    def test_over_50_422(self, session):
        r = session.post(f"{API}/ioc/lookup/batch", json={"indicators": [f"10.0.0.{i}" for i in range(51)]}, timeout=20)
        assert r.status_code == 422

    def test_exactly_50_ok(self, session):
        r = session.post(f"{API}/ioc/lookup/batch", json={"indicators": [f"10.0.1.{i}" for i in range(50)]}, timeout=60)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 50


# Single IOC lookup regression with enrichment (LLM)
class TestSingleLookup:
    def test_single_enrichment(self, session):
        r = session.post(f"{API}/ioc/lookup", json={"indicator": "1.1.1.1", "notes": "TEST_single"}, timeout=120)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["ioc_type"] == "ipv4"
        assert d["classification"] in {"green", "yellow", "red"}
        assert isinstance(d["confidence"], int) and 0 <= d["confidence"] <= 100
        assert isinstance(d.get("summary"), str)
        assert d["enrichment"]["virustotal"]["status"] == "not_configured"
        assert d["enrichment"]["abuseipdb"]["status"] == "not_configured"


# Incident timeline
class TestTimeline:
    @pytest.fixture(scope="class")
    def incident(self, session):
        r = session.post(f"{API}/incidents", json={"title": "TEST_timeline incident", "source": "SIEM", "description": "TEST", "raw_logs": "failed login x50 from 203.0.113.9"}, timeout=20)
        assert r.status_code == 200
        return r.json()

    def _check_event(self, e):
        for k in ("id", "kind", "icon", "title", "description", "severity", "at"):
            assert k in e, f"missing {k}"
        assert isinstance(e["icon"], str) and e["icon"]
        assert e["severity"] in (None, "green", "yellow", "red")
        if e["at"] is not None:
            _iso_utc(e["at"])

    def test_timeline_created_only(self, session, incident):
        r = session.get(f"{API}/incidents/{incident['id']}/timeline", timeout=20)
        assert r.status_code == 200
        d = r.json()
        assert d["incident_id"] == incident["id"] and d["total"] == 1
        assert d["events"][0]["kind"] == "created"

    def test_timeline_evidence_checklist(self, session, incident):
        assert session.post(f"{API}/incidents/{incident['id']}/evidence", json={"kind": "Log", "content": "TEST_evidence"}, timeout=20).status_code == 200
        assert session.post(f"{API}/incidents/{incident['id']}/checklist/contain", timeout=20).status_code == 200
        d = session.get(f"{API}/incidents/{incident['id']}/timeline", timeout=20).json()
        kinds = [e["kind"] for e in d["events"]]
        assert kinds[0] == "created"
        assert "evidence" in kinds and "checklist" in kinds
        assert d["total"] == len(d["events"]) == 3
        for e in d["events"]:
            self._check_event(e)
        ats = [e["at"] or "" for e in d["events"]]
        assert ats == sorted(ats)

    def test_timeline_analysis_review(self, session, incident):
        r = session.post(f"{API}/incidents/{incident['id']}/analyze", json={"context": "TEST"}, timeout=180)
        assert r.status_code == 200, r.text
        r = session.post(f"{API}/incidents/{incident['id']}/review", json={"report": "TEST_report reviewed"}, timeout=20)
        assert r.status_code == 200
        d = session.get(f"{API}/incidents/{incident['id']}/timeline", timeout=20).json()
        kinds = [e["kind"] for e in d["events"]]
        print(kinds)
        assert kinds[0] == "created"
        assert {"evidence", "checklist", "analysis", "review"} <= set(kinds)
        for e in d["events"]:
            self._check_event(e)
        ats = [e["at"] or "" for e in d["events"]]
        assert ats == sorted(ats)

    def test_timeline_other_user_404(self, other_session, incident):
        r = other_session.get(f"{API}/incidents/{incident['id']}/timeline", timeout=20)
        assert r.status_code == 404

    def test_timeline_unknown_404(self, session):
        r = session.get(f"{API}/incidents/{uuid.uuid4()}/timeline", timeout=20)
        assert r.status_code == 404

    def test_timeline_no_auth_401(self, incident):
        r = requests.get(f"{API}/incidents/{incident['id']}/timeline", timeout=20)
        assert r.status_code == 401
