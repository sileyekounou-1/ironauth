import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.core.auth import ironauth

DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
def client():
    db = SQLAlchemyAdapter(DATABASE_URL)
    asyncio.get_event_loop().run_until_complete(db.init())

    auth = ironauth(
        database=db,
        config={"secret_key": "test-secret-key-super-long-pour-les-tests"},
    )
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app)


def test_register(client):
    res = client.post(
        "/auth/register",
        json={"email": "tug@test.com", "password": "MonMotDePasse123!"},
    )
    assert res.status_code == 200
    assert "user_id" in res.json()


def test_register_email_deja_utilise(client):
    client.post(
        "/auth/register",
        json={"email": "double@test.com", "password": "MonMotDePasse123!"},
    )
    res = client.post(
        "/auth/register",
        json={"email": "double@test.com", "password": "MonMotDePasse123!"},
    )
    assert res.status_code == 400


def test_login(client):
    client.post(
        "/auth/register",
        json={"email": "login@test.com", "password": "MonMotDePasse123!"},
    )
    res = client.post(
        "/auth/login", json={"email": "login@test.com", "password": "MonMotDePasse123!"}
    )
    assert res.status_code == 200
    assert "af_access_token" in res.cookies


def test_login_mauvais_mdp(client):
    client.post(
        "/auth/register",
        json={"email": "wrong@test.com", "password": "MonMotDePasse123!"},
    )
    res = client.post(
        "/auth/login",
        json={"email": "wrong@test.com", "password": "MauvaisMotDePasse123!"},
    )
    assert res.status_code == 401


def test_logout(client):
    client.post(
        "/auth/register",
        json={"email": "logout@test.com", "password": "MonMotDePasse123!"},
    )
    client.post(
        "/auth/login",
        json={"email": "logout@test.com", "password": "MonMotDePasse123!"},
    )
    res = client.post("/auth/logout")
    assert res.status_code == 200
    assert "af_access_token" not in res.cookies


def test_refresh(client):
    client.post(
        "/auth/register",
        json={"email": "refresh@test.com", "password": "MonMotDePasse123!"},
    )
    login_res = client.post(
        "/auth/login",
        json={"email": "refresh@test.com", "password": "MonMotDePasse123!"},
    )
    # Extraire le refresh token du cookie et le passer explicitement
    refresh_token = login_res.cookies.get("af_refresh_token")
    res = client.post("/auth/refresh", cookies={"af_refresh_token": refresh_token})
    assert res.status_code == 200
