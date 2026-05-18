import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.core.auth import ironauth
from ironauth.core.config import ironauthConfig
from ironauth.core.password import PasswordManager
from ironauth.core.session import SessionManager

DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
def config():
    return ironauthConfig(
        secret_key="test-secret-key-super-long-pour-les-tests",
    )


@pytest_asyncio.fixture
async def db():
    adapter = SQLAlchemyAdapter(DATABASE_URL)
    await adapter.init()
    return adapter


@pytest.fixture
def session_manager(config):
    return SessionManager(config)


@pytest.fixture
def password_manager():
    return PasswordManager()


@pytest_asyncio.fixture
async def auth(db):
    instance = ironauth(
        database=db,
        config={"secret_key": "test-secret-key-super-long-pour-les-tests"},
    )
    return instance


@pytest_asyncio.fixture
async def client(auth):
    app = FastAPI()
    app.include_router(auth.router)
    return TestClient(app)
