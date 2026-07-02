import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.core.auth import ironauth
from tests.conftest import get_csrf_headers

DATABASE_URL = "sqlite+aiosqlite:///:memory:"
SECRET = "test-secret-key-super-long-pour-les-tests"
PWD = "MonMotDePasse123!"


def _make_client(**config_extra):
    db = SQLAlchemyAdapter(DATABASE_URL)
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(db.init())
    finally:
        loop.close()
    config = {"secret_key": SECRET, "cookie": {"secure": False}}
    config.update(config_extra)
    auth = ironauth(database=db, config=config)
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app)


@pytest.fixture
def client():
    return _make_client()


def _register(client, email, pwd=PWD):
    h = get_csrf_headers(client)
    r = client.post("/auth/register", json={"email": email, "password": pwd}, headers=h)
    assert r.status_code == 200
    return r


def test_public_imports():
    # L'API publique doit être importable depuis le paquet racine
    from ironauth import (  # noqa: F401
        IronAuth,
        User,
        oauth,
        rate_limit,
        resend,
        smtp,
        sqlalchemy_adapter,
        two_factor,
    )

    assert IronAuth is not None


def test_me_retourne_utilisateur_courant(client):
    _register(client, "me@test.com")
    r = client.get("/auth/me")
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "me@test.com"
    assert body["is_active"] is True
    assert body["totp_enabled"] is False


def test_me_sans_auth_401(client):
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_change_password(client):
    _register(client, "chg@test.com")
    new_pwd = "NouveauPass456!"
    h = get_csrf_headers(client)
    r = client.post(
        "/auth/change-password",
        json={"current_password": PWD, "new_password": new_pwd},
        headers=h,
    )
    assert r.status_code == 200

    # L'ancien mot de passe ne marche plus, le nouveau oui
    client.cookies.clear()
    h = get_csrf_headers(client)
    r = client.post("/auth/login", json={"email": "chg@test.com", "password": PWD}, headers=h)
    assert r.status_code == 401
    h = get_csrf_headers(client)
    r = client.post("/auth/login", json={"email": "chg@test.com", "password": new_pwd}, headers=h)
    assert r.status_code == 200


def test_change_password_mauvais_actuel(client):
    _register(client, "chg2@test.com")
    h = get_csrf_headers(client)
    r = client.post(
        "/auth/change-password",
        json={"current_password": "FauxMotDePasse1!", "new_password": "NouveauPass456!"},
        headers=h,
    )
    assert r.status_code == 400


def test_logout_coupe_la_session(client):
    _register(client, "out@test.com")
    assert client.get("/auth/me").status_code == 200
    h = get_csrf_headers(client)
    r = client.post("/auth/logout", headers=h)
    assert r.status_code == 200
    # Cookies effacés → plus d'accès
    assert client.get("/auth/me").status_code == 401


def test_require_verified_email_bloque_login():
    client = _make_client(require_verified_email=True)
    # register ne connecte pas quand la vérif est requise
    r = _register(client, "unverif@test.com")
    assert "af_access_token" not in r.cookies
    # login refusé tant que non vérifié
    h = get_csrf_headers(client)
    r = client.post("/auth/login", json={"email": "unverif@test.com", "password": PWD}, headers=h)
    assert r.status_code == 403
