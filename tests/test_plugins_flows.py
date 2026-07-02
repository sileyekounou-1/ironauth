import asyncio
import time

import pytest
import pytest_asyncio

from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.core.config import ironauthConfig
from ironauth.core.email_manager import EmailManager, _hash_token
from ironauth.core.password import PasswordManager
from ironauth.core.session import SessionManager
from ironauth.plugins.email.base import EmailMessage, EmailProvider
from ironauth.plugins.oauth import OAuthPlugin

DATABASE_URL = "sqlite+aiosqlite:///:memory:"
SECRET = "test-secret-key-super-long-pour-les-tests"


class CapturingProvider(EmailProvider):
    """Provider de test : capture les emails au lieu de les envoyer."""

    def __init__(self):
        self.sent: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        self.sent.append(message)


@pytest_asyncio.fixture
async def db():
    adapter = SQLAlchemyAdapter(DATABASE_URL)
    await adapter.init()
    return adapter


# --- Email : vérification ---

@pytest.mark.asyncio
async def test_email_verification_flow(db):
    provider = CapturingProvider()
    em = EmailManager(db=db, provider=provider, base_url="http://x")
    user = await db.create_user(email="v@test.com", hashed_password="x")

    await em.send_verification_email(user.id)
    assert len(provider.sent) == 1
    # Le token stocké est hashé, pas en clair
    stored = (await db.get_user_by_id(user.id)).email_verification_token
    assert stored and len(stored) == 64  # SHA-256 hex

    # Extrait le token clair depuis l'URL de l'email
    url = provider.sent[0].html
    raw = url.split("token=")[1].split('"')[0]
    assert _hash_token(raw) == stored

    assert await em.verify_email(raw) is True
    refreshed = await db.get_user_by_id(user.id)
    assert refreshed.is_verified is True
    assert refreshed.email_verification_token is None


@pytest.mark.asyncio
async def test_email_verification_token_expire(db):
    provider = CapturingProvider()
    em = EmailManager(db=db, provider=provider, base_url="http://x")
    user = await db.create_user(email="exp@test.com", hashed_password="x")
    await em.send_verification_email(user.id)
    # Force l'expiration
    await db.update_user(user.id, email_verification_expires_at=time.time() - 1)
    raw = provider.sent[0].html.split("token=")[1].split('"')[0]
    assert await em.verify_email(raw) is False


# --- Email : reset + révocation de session ---

@pytest.mark.asyncio
async def test_reset_password_revoque_sessions(db):
    provider = CapturingProvider()
    em = EmailManager(db=db, provider=provider, base_url="http://x")
    pm = PasswordManager()
    user = await db.create_user(email="r@test.com", hashed_password=pm.hash("Ancien123!!!"))

    await em.send_reset_password_email("r@test.com")
    raw = provider.sent[0].html.split("token=")[1].split('"')[0]

    ok = await em.reset_password(raw, "NouveauPass456!", pm)
    assert ok is True
    refreshed = await db.get_user_by_id(user.id)
    assert pm.verify("NouveauPass456!", refreshed.hashed_password)
    # sessions_valid_from posé → invalide les anciens tokens
    assert refreshed.sessions_valid_from is not None
    sm = SessionManager(ironauthConfig(secret_key=SECRET))
    old_token_payload = {"iat": int(refreshed.sessions_valid_from) - 10}
    assert sm.is_session_valid(old_token_payload, refreshed.sessions_valid_from) is False


@pytest.mark.asyncio
async def test_reset_password_anti_enumeration(db):
    provider = CapturingProvider()
    em = EmailManager(db=db, provider=provider, base_url="http://x")
    # Email inexistant : pas d'erreur, pas d'email envoyé
    await em.send_reset_password_email("inconnu@test.com")
    assert provider.sent == []


# --- OAuth : protection anti-takeover ---

def _make_oauth(db):
    sm = SessionManager(ironauthConfig(secret_key=SECRET))
    plugin = OAuthPlugin(["google"])
    # Injecte une config minimale sans passer par init()
    plugin._db = db
    plugin._session = sm
    return plugin


class FakeResponse:
    def set_cookie(self, **k):
        pass


@pytest.mark.asyncio
async def test_oauth_email_non_verifie_refuse_liaison(db, monkeypatch):
    # Un compte local existe déjà avec cet email
    await db.create_user(email="victim@test.com", hashed_password="x")
    plugin = _make_oauth(db)

    async def fake_exchange(provider, code):
        return {"access_token": "tok"}

    async def fake_userinfo(provider, access_token):
        # Google renvoie un email NON vérifié correspondant à la victime
        return {"sub": "google-123", "email": "victim@test.com", "email_verified": False}

    monkeypatch.setattr(plugin, "_exchange_code", fake_exchange)
    monkeypatch.setattr(plugin, "_get_userinfo", fake_userinfo)

    with pytest.raises(ValueError, match="verifie"):
        await plugin.handle_callback("google", "code", FakeResponse())


@pytest.mark.asyncio
async def test_oauth_email_verifie_lie_le_compte(db, monkeypatch):
    existing = await db.create_user(email="ok@test.com", hashed_password="x")
    plugin = _make_oauth(db)

    async def fake_exchange(provider, code):
        return {"access_token": "tok"}

    async def fake_userinfo(provider, access_token):
        return {"sub": "google-999", "email": "ok@test.com", "email_verified": True}

    monkeypatch.setattr(plugin, "_exchange_code", fake_exchange)
    monkeypatch.setattr(plugin, "_get_userinfo", fake_userinfo)

    result = await plugin.handle_callback("google", "code", FakeResponse())
    assert result["user_id"] == existing.id  # lié au compte existant, pas de doublon


# --- Rate limiter : verrou réel ---

class FakeReq:
    def __init__(self, ip="1.2.3.4"):
        self.client = type("C", (), {"host": ip})()
        self.headers = {}


@pytest.mark.asyncio
async def test_rate_limiter_verrou_reel():
    from fastapi import HTTPException

    from ironauth.plugins.rate_limit import RateLimiter

    rl = RateLimiter(max_attempts=3, window=300, block_duration=900)
    req = FakeReq()

    # 3 échecs → atteint le seuil
    for _ in range(3):
        await rl.record_failure(req, "login")

    # check() doit lever 429 avec un Retry-After proche de block_duration (900),
    # PAS de window (300) : le verrou est réel.
    with pytest.raises(HTTPException) as exc:
        await rl.check(req, "login")
    assert exc.value.status_code == 429
    retry = int(exc.value.headers["Retry-After"])
    assert retry > 300  # verrou de 15 min, pas la simple fenêtre de 5 min


@pytest.mark.asyncio
async def test_rate_limiter_success_reset():
    from ironauth.plugins.rate_limit import RateLimiter

    rl = RateLimiter(max_attempts=3, window=300, block_duration=900)
    req = FakeReq(ip="5.6.7.8")
    for _ in range(3):
        await rl.record_failure(req, "login")
    await rl.record_success(req, "login")  # doit vider tentatives ET verrou
    # Ne lève plus
    await rl.check(req, "login")
