from typing import Any, Optional

from ironauth.models.user import Base, OAuthAccount, User
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


class SQLAlchemyAdapter:
    def __init__(self, database_url: str):
        self.engine = create_async_engine(database_url, echo=False)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def init(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    # --- User ---

    async def create_user(
        self, email: str, hashed_password: Optional[str] = None
    ) -> User:
        async with self.session_factory() as session:
            user = User(email=email, hashed_password=hashed_password)
            session.add(user)
            await session.commit()
            await session.refresh(user)
            return user

    async def get_user_by_email(self, email: str) -> Optional[User]:
        async with self.session_factory() as session:
            result = await session.execute(select(User).where(User.email == email))
            return result.scalar_one_or_none()

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        async with self.session_factory() as session:
            result = await session.execute(select(User).where(User.id == user_id))
            return result.scalar_one_or_none()

    async def update_user(self, user_id: str, **kwargs: Any) -> Optional[User]:
        async with self.session_factory() as session:
            await session.execute(
                update(User).where(User.id == user_id).values(**kwargs)
            )
            await session.commit()
            return await self.get_user_by_id(user_id)

    async def delete_user(self, user_id: str) -> None:
        async with self.session_factory() as session:
            await session.execute(delete(User).where(User.id == user_id))
            await session.commit()

    # --- OAuth ---

    async def create_oauth_account(
        self,
        user_id: str,
        provider: str,
        provider_user_id: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        expires_at=None,
    ) -> OAuthAccount:
        async with self.session_factory() as session:
            account = OAuthAccount(
                user_id=user_id,
                provider=provider,
                provider_user_id=provider_user_id,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=expires_at,
            )
            session.add(account)
            await session.commit()
            await session.refresh(account)
            return account

    async def get_oauth_account(
        self, provider: str, provider_user_id: str
    ) -> Optional[OAuthAccount]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(OAuthAccount).where(
                    OAuthAccount.provider == provider,
                    OAuthAccount.provider_user_id == provider_user_id,
                )
            )
            return result.scalar_one_or_none()


def sqlalchemy_adapter(database_url: str) -> SQLAlchemyAdapter:
    return SQLAlchemyAdapter(database_url)
