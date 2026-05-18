import time

import pytest
from ironauth.core.session import SessionManager


@pytest.fixture
def session(config):
    return SessionManager(config)


def test_create_and_decode_access_token(session):
    token = session.create_access_token("user-123")
    user_id = session.decode_token(token, "access")
    assert user_id == "user-123"


def test_create_and_decode_refresh_token(session):
    token = session.create_refresh_token("user-456")
    user_id = session.decode_token(token, "refresh")
    assert user_id == "user-456"


def test_token_type_mismatch(session):
    access_token = session.create_access_token("user-123")
    result = session.decode_token(access_token, "refresh")
    assert result is None  # Access token != refresh token


def test_token_expire(config):
    config.token.access_token_expiry = 1  # 1 seconde
    session = SessionManager(config)
    token = session.create_access_token("user-123")
    time.sleep(2)
    with pytest.raises(ValueError, match="expiré"):
        session.decode_token(token, "access")


def test_invalid_token(session):
    with pytest.raises(ValueError, match="invalide"):
        session.decode_token("token.bidon.ici", "access")
