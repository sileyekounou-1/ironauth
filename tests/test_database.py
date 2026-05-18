import pytest


@pytest.mark.asyncio
async def test_create_user(db):
    user = await db.create_user(email="tug@test.com", hashed_password="hashed")
    assert user.id is not None
    assert user.email == "tug@test.com"


@pytest.mark.asyncio
async def test_get_user_by_email(db):
    await db.create_user(email="find@test.com")
    user = await db.get_user_by_email("find@test.com")
    assert user is not None
    assert user.email == "find@test.com"


@pytest.mark.asyncio
async def test_get_user_by_email_not_found(db):
    user = await db.get_user_by_email("ghost@test.com")
    assert user is None


@pytest.mark.asyncio
async def test_update_user(db):
    user = await db.create_user(email="update@test.com")
    updated = await db.update_user(user.id, is_verified=True)
    assert updated.is_verified is True


@pytest.mark.asyncio
async def test_delete_user(db):
    user = await db.create_user(email="delete@test.com")
    await db.delete_user(user.id)
    result = await db.get_user_by_email("delete@test.com")
    assert result is None


@pytest.mark.asyncio
async def test_create_oauth_account(db):
    user = await db.create_user(email="oauth@test.com")
    account = await db.create_oauth_account(
        user_id=user.id,
        provider="google",
        provider_user_id="google-uid-123",
        access_token="token-xyz",
    )
    assert account.id is not None
    assert account.provider == "google"


@pytest.mark.asyncio
async def test_get_oauth_account(db):
    user = await db.create_user(email="oauth2@test.com")
    await db.create_oauth_account(
        user_id=user.id,
        provider="github",
        provider_user_id="github-uid-456",
        access_token="token-abc",
    )
    account = await db.get_oauth_account("github", "github-uid-456")
    assert account is not None
    assert account.user_id == user.id
