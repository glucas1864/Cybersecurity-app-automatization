import os
import uuid

import pytest
import requests


BASE_URL = os.environ.get("EXPO_PUBLIC_BACKEND_URL", "").rstrip("/")


@pytest.fixture(scope="module")
def client():
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    email = f"TEST_{uuid.uuid4().hex}@example.com"
    response = session.post(f"{BASE_URL}/api/auth/register", json={"email": email, "password": "TestBlue123!", "name": "TEST Analyst"}, timeout=30)
    assert response.status_code == 200, response.text
    session.headers.update({"Authorization": f"Bearer {response.json()['token']}"})
    return session


def test_health():
    response = requests.get(f"{BASE_URL}/health", timeout=15)
    assert response.status_code == 200
    assert response.json().get("status") == "ok"


def test_authenticated_workspace_and_library(client):
    assert client.get(f"{BASE_URL}/api/auth/me", timeout=15).json()["email"].startswith("test_")
    summary = client.get(f"{BASE_URL}/api/summary", timeout=15).json()
    assert all(key in summary for key in ("total", "open", "red", "yellow", "green"))
    library = client.get(f"{BASE_URL}/api/library", timeout=15).json()
    assert isinstance(library, list) and library and "title" in library[0]


def test_incident_checklist_evidence_review_and_history(client):
    created = client.post(f"{BASE_URL}/api/incidents", json={"title": "TEST phishing alert", "description": "TEST suspicious login", "raw_logs": "TEST source=edr ip=10.0.0.4"}, timeout=15)
    assert created.status_code == 200
    incident = created.json()
    assert "_id" not in incident
    incident_id = incident["id"]
    assert client.get(f"{BASE_URL}/api/incidents/{incident_id}", timeout=15).json()["title"] == "TEST phishing alert"
    checklist = client.post(f"{BASE_URL}/api/incidents/{incident_id}/checklist/contain", timeout=15).json()
    assert next(item for item in checklist if item["id"] == "contain")["done"] is True
    evidence = client.post(f"{BASE_URL}/api/incidents/{incident_id}/evidence", json={"kind": "TEST note", "content": "TEST preserve EDR timeline"}, timeout=15)
    assert evidence.status_code == 200 and "_id" not in evidence.json()
    review = client.post(f"{BASE_URL}/api/incidents/{incident_id}/review", json={"report": "TEST manually reviewed report"}, timeout=15)
    assert review.json()["report_reviewed"] is True
    assert isinstance(client.get(f"{BASE_URL}/api/analysis-history", timeout=15).json(), list)


def test_ai_analysis_contract(client):
    incident = client.post(f"{BASE_URL}/api/incidents", json={"title": "TEST log review", "description": "TEST routine event", "raw_logs": "TEST status=ok"}, timeout=15).json()
    response = client.post(f"{BASE_URL}/api/incidents/{incident['id']}/analyze", json={"context": "TEST analyst context"}, timeout=90)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["classification"] in {"green", "yellow", "red"}
    assert result["requires_manual_review"] is True