import asyncio

import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.core.auth import ironauth
from ironauth.core.session import SessionManager
from ironauth.core.config import ironauthConfig
from ironauth.plugins.two_factor import two_factor
from tests.conftest import get_csrf_headers

DATABASE_URL = "sqlite+aiosqlite:///:memory:"
SECRET = "test-secret-key-super-long-pour-les-tests"


@pytest.fixture
def client_2fa():
    db = SQLAlchemyAdapter(DATABASE_URL)
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(db.init())
    finally:
        loop.close()
    auth = ironauth(
        database=db,
        config={"secret_key": SECRET, "cookie": {"secure": False}},
        plugins=[two_factor()],
    )
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app)


def _register(client, email):
    h = get_csrf_headers(client)
    r = client.post(
        "/auth/register",
        json={"email": email, "password": "MonMotDePasse123!"},
        headers=h,
    )
    assert r.status_code == 200
    return r.json()["user_id"]


def test_config_rejette_secret_court():
    with pytest.raises(Exception):
        ironauthConfig(secret_key="trop-court")


def test_login_avec_2fa_ne_donne_pas_de_session(client_2fa):
    _register(client_2fa, "twofa@test.com")
    # Active le 2FA
    h = get_csrf_headers(client_2fa)
    r = client_2fa.post("/auth/2fa/enable", headers=h)
    assert r.status_code == 200
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    h = get_csrf_headers(client_2fa)
    r = client_2fa.post("/auth/2fa/confirm", json={"code": code}, headers=h)
    assert r.status_code == 200

    # Login : mot de passe correct MAIS 2FA actif -> pas de session, token intermediaire
    client_2fa.cookies.clear()
    h = get_csrf_headers(client_2fa)
    r = client_2fa.post(
        "/auth/login",
        json={"email": "twofa@test.com", "password": "MonMotDePasse123!"},
        headers=h,
    )
    assert r.status_code == 200
    body = r.json()
    assert body.get("two_factor_required") is True
    assert "two_factor_token" in body
    assert "af_access_token" not in r.cookies  # PAS de session complete

    # Validation avec le bon code -> session emise
    code = pyotp.TOTP(secret).now()
    h = get_csrf_headers(client_2fa)
    r = client_2fa.post(
        "/auth/2fa/validate",
        json={"two_factor_token": body["two_factor_token"], "code": code},
        headers=h,
    )
    assert r.status_code == 200
    assert "af_access_token" in r.cookies


def test_2fa_validate_mauvais_code_refuse(client_2fa):
    _register(client_2fa, "twofa2@test.com")
    h = get_csrf_headers(client_2fa)
    secret = client_2fa.post("/auth/2fa/enable", headers=h).json()["secret"]
    h = get_csrf_headers(client_2fa)
    client_2fa.post("/auth/2fa/confirm", json={"code": pyotp.TOTP(secret).now()}, headers=h)
    client_2fa.cookies.clear()
    h = get_csrf_headers(client_2fa)
    token = client_2fa.post(
        "/auth/login",
        json={"email": "twofa2@test.com", "password": "MonMotDePasse123!"},
        headers=h,
    ).json()["two_factor_token"]
    h = get_csrf_headers(client_2fa)
    r = client_2fa.post(
        "/auth/2fa/validate",
        json={"two_factor_token": token, "code": "000000"},
        headers=h,
    )
    assert r.status_code == 401


def test_enable_2fa_refuse_si_deja_actif(client_2fa):
    _register(client_2fa, "twofa3@test.com")
    h = get_csrf_headers(client_2fa)
    secret = client_2fa.post("/auth/2fa/enable", headers=h).json()["secret"]
    h = get_csrf_headers(client_2fa)
    client_2fa.post("/auth/2fa/confirm", json={"code": pyotp.TOTP(secret).now()}, headers=h)
    # Deuxieme enable sans passer par disable -> refuse (sinon 2FA desactive sans code)
    h = get_csrf_headers(client_2fa)
    r = client_2fa.post("/auth/2fa/enable", headers=h)
    assert r.status_code == 400


def test_2fa_routes_exigent_csrf(client_2fa):
    # Authentifie (cookie de session pose au register) mais SANS header CSRF -> 403
    _register(client_2fa, "csrf2fa@test.com")
    r = client_2fa.post("/auth/2fa/enable")
    assert r.status_code == 403


def test_is_session_valid_revocation():
    cfg = ironauthConfig(secret_key=SECRET)
    sm = SessionManager(cfg)
    # iat 1000, revocation a 2000 -> invalide
    assert sm.is_session_valid({"iat": 1000}, 2000) is False
    # iat 3000, revocation a 2000 -> valide
    assert sm.is_session_valid({"iat": 3000}, 2000) is True
    # pas de revocation -> valide
    assert sm.is_session_valid({"iat": 1000}, None) is True


def test_refresh_token_expire_ne_crash_pas():
    """Un refresh token expire -> None (pas d'exception 500)."""
    cfg = ironauthConfig(secret_key=SECRET)
    cfg.token.refresh_token_expiry = 1
    sm = SessionManager(cfg)

    class FakeReq:
        cookies = {}

    class FakeResp:
        def set_cookie(self, **k):
            pass

    import time as _t

    token = sm.create_refresh_token("u1")
    FakeReq.cookies = {cfg.cookie.refresh_token_name: token}
    _t.sleep(2)
    out = asyncio.new_event_loop().run_until_complete(
        sm.refresh_session(FakeReq(), FakeResp())
    )
    assert out is None
