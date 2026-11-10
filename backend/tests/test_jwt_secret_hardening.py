# JWT secret hardening tests: env-only secret, old-secret forged token rejection, auth regression
import os
import re
import time
import uuid
from pathlib import Path

import jwt
import pytest
import requests

BASE_URL = os.environ.get("EXPO_PUBLIC_BACKEND_URL").rstrip("/")
OLD_SECRET = "soc-sentinel-local-secret-change-me-32"
SERVER_PY = Path("/app/backend/server.py")
CRED_EMAIL = "debug-blue@example.com"
CRED_PASSWORD = "BlueTeam123!"


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="module")
def fresh_user(session):
    email = f"test_jwt_{uuid.uuid4().hex[:10]}@example.com"
    r = session.post(f"{BASE_URL}/api/auth/register", json={"email": email, "password": "TestPass123!", "name": "TEST_jwt"})
    assert r.status_code == 200, r.text
    data = r.json()
    return {"email": email, "password": "TestPass123!", "token": data["token"], "id": data["user"]["id"]}


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# Static check: no hardcoded secret in server.py
class TestNoHardcodedSecret:
    def test_old_secret_not_in_source(self):
        src = SERVER_PY.read_text()
        assert OLD_SECRET not in src
        assert "change-me" not in src

    def test_jwt_secret_from_env_without_fallback_value(self):
        src = SERVER_PY.read_text()
        m = re.search(r'JWT_SECRET\s*=\s*os\.environ\.get\("JWT_SECRET",\s*"([^"]*)"\)', src)
        assert m is not None
        assert m.group(1) == ""
        assert "raise RuntimeError" in src

    def test_env_secret_is_strong_and_differs_from_old(self):
        env = Path("/app/backend/.env").read_text()
        m = re.search(r'^JWT_SECRET=["\']?([^"\'\n]+)', env, re.M)
        assert m is not None
        assert len(m.group(1)) >= 32
        assert m.group(1) != OLD_SECRET


# Health / startup
class TestHealth:
    def test_api_health(self, session):
        r = session.get(f"{BASE_URL}/api/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


# Auth: register / login / me
class TestAuthFlows:
    def test_register_returns_token(self, fresh_user):
        assert isinstance(fresh_user["token"], str) and fresh_user["token"].count(".") == 2

    def test_login_fresh_user(self, session, fresh_user):
        r = session.post(f"{BASE_URL}/api/auth/login", json={"email": fresh_user["email"], "password": fresh_user["password"]})
        assert r.status_code == 200
        data = r.json()
        assert data["user"]["email"] == fresh_user["email"]
        assert data["user"]["id"] == fresh_user["id"]
        assert "password_hash" not in data["user"]

    def test_login_seeded_credentials(self, session):
        r = session.post(f"{BASE_URL}/api/auth/login", json={"email": CRED_EMAIL, "password": CRED_PASSWORD})
        if r.status_code == 401:
            pytest.skip("Seeded preview user not present in DB")
        assert r.status_code == 200
        me = session.get(f"{BASE_URL}/api/auth/me", headers=auth(r.json()["token"]))
        assert me.status_code == 200
        assert me.json()["email"] == CRED_EMAIL

    def test_me_with_valid_token(self, session, fresh_user):
        r = session.get(f"{BASE_URL}/api/auth/me", headers=auth(fresh_user["token"]))
        assert r.status_code == 200
        assert r.json()["id"] == fresh_user["id"]

    def test_wrong_password_401(self, session, fresh_user):
        r = session.post(f"{BASE_URL}/api/auth/login", json={"email": fresh_user["email"], "password": "WrongPass999!"})
        assert r.status_code == 401


# Negative token cases
class TestTokenRejection:
    def test_forged_old_secret_token_rejected(self, session, fresh_user):
        forged = jwt.encode({"sub": fresh_user["id"], "exp": int(time.time()) + 3600}, OLD_SECRET, algorithm="HS256")
        r = session.get(f"{BASE_URL}/api/auth/me", headers=auth(forged))
        assert r.status_code == 401
        # Also rejected on protected data endpoints
        r2 = session.get(f"{BASE_URL}/api/incidents", headers=auth(forged))
        assert r2.status_code == 401

    def test_alg_none_token_rejected(self, session, fresh_user):
        none_tok = jwt.encode({"sub": fresh_user["id"], "exp": int(time.time()) + 3600}, key=None, algorithm="none")
        r = session.get(f"{BASE_URL}/api/auth/me", headers=auth(none_tok))
        assert r.status_code == 401

    def test_tampered_signature_rejected(self, session, fresh_user):
        tok = fresh_user["token"]
        head, payload, sig = tok.split(".")
        bad = f"{head}.{payload}.{sig[:-4]}{'AAAA' if sig[-4:] != 'AAAA' else 'BBBB'}"
        r = session.get(f"{BASE_URL}/api/auth/me", headers=auth(bad))
        assert r.status_code == 401

    def test_garbage_token_rejected(self, session):
        r = session.get(f"{BASE_URL}/api/auth/me", headers=auth("not.a.jwt"))
        assert r.status_code == 401

    def test_missing_token_rejected(self, session):
        r = session.get(f"{BASE_URL}/api/auth/me")
        assert r.status_code == 401

    def test_non_bearer_scheme_rejected(self, session, fresh_user):
        r = session.get(f"{BASE_URL}/api/auth/me", headers={"Authorization": f"Token {fresh_user['token']}"})
        assert r.status_code == 401

    def test_expired_token_rejected(self, session, fresh_user):
        env = Path("/app/backend/.env").read_text()
        secret = re.search(r'^JWT_SECRET=["\']?([^"\'\n]+)', env, re.M).group(1)
        expired = jwt.encode({"sub": fresh_user["id"], "exp": int(time.time()) - 60}, secret, algorithm="HS256")
        r = session.get(f"{BASE_URL}/api/auth/me", headers=auth(expired))
        assert r.status_code == 401


# Regression on protected endpoints
class TestProtectedRegression:
    def test_incident_create_list_timeline(self, session, fresh_user):
        h = auth(fresh_user["token"])
        c = session.post(f"{BASE_URL}/api/incidents", headers=h, json={"title": "TEST_jwt incident", "source": "Manual", "description": "d", "raw_logs": "l"})
        assert c.status_code == 200
        inc = c.json()
        assert inc["title"] == "TEST_jwt incident" and inc["owner_id"] == fresh_user["id"]
        lst = session.get(f"{BASE_URL}/api/incidents", headers=h)
        assert lst.status_code == 200
        assert any(i["id"] == inc["id"] for i in lst.json())
        tl = session.get(f"{BASE_URL}/api/incidents/{inc['id']}/timeline", headers=h)
        assert tl.status_code == 200
        assert tl.json()["total"] >= 1 and tl.json()["events"][0]["kind"] == "created"

    def test_ioc_batch(self, session, fresh_user):
        r = session.post(f"{BASE_URL}/api/ioc/lookup/batch", headers=auth(fresh_user["token"]), json={"indicators": ["8.8.8.8", "example.com"]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert isinstance(body, dict)

    def test_protected_endpoints_require_token(self, session):
        assert session.get(f"{BASE_URL}/api/incidents").status_code == 401
        assert session.post(f"{BASE_URL}/api/ioc/lookup/batch", json={"indicators": ["8.8.8.8"]}).status_code == 401
