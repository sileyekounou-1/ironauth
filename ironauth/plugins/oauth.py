from typing import Optional

import httpx
from fastapi import Response
from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.core.config import OAuthProviderConfig
from ironauth.core.session import SessionManager

PROVIDERS = {
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
        "scopes": ["openid", "email", "profile"],
    },
    "github": {
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scopes": ["read:user", "user:email"],
    },
}


class OAuthPlugin:
    def __init__(self, providers: list[str]):
        self.providers = providers
        self._configs: dict[str, OAuthProviderConfig] = {}
        self._db: Optional[SQLAlchemyAdapter] = None
        self._session: Optional[SessionManager] = None

    def init(self, db: SQLAlchemyAdapter, session: SessionManager, oauth_config):
        self._db = db
        self._session = session
        for provider in self.providers:
            config = getattr(oauth_config, provider, None)
            if not config:
                raise ValueError(
                    f"Configuration manquante pour le provider : {provider}"
                )
            self._configs[provider] = config

    def get_authorization_url(self, provider: str, state: str) -> str:
        if provider not in PROVIDERS:
            raise ValueError(f"Provider non supporté : {provider}")

        meta = PROVIDERS[provider]
        config = self._configs[provider]
        scopes = "%20".join(meta["scopes"])

        return (
            f"{meta['auth_url']}"
            f"?client_id={config.client_id}"
            f"&redirect_uri={config.redirect_uri}"
            f"&response_type=code"
            f"&scope={scopes}"
            f"&state={state}"
        )

    async def _exchange_code(self, provider: str, code: str) -> dict:
        meta = PROVIDERS[provider]
        config = self._configs[provider]

        async with httpx.AsyncClient() as client:
            response = await client.post(
                meta["token_url"],
                data={
                    "client_id": config.client_id,
                    "client_secret": config.client_secret.get_secret_value(),
                    "code": code,
                    "redirect_uri": config.redirect_uri,
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            return response.json()

    async def _get_userinfo(self, provider: str, access_token: str) -> dict:
        meta = PROVIDERS[provider]
        async with httpx.AsyncClient() as client:
            response = await client.get(
                meta["userinfo_url"],
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            return response.json()

    def _extract_user_data(self, provider: str, userinfo: dict) -> dict:
        if provider == "google":
            return {
                "provider_user_id": userinfo["sub"],
                "email": userinfo["email"],
            }
        if provider == "github":
            return {
                "provider_user_id": str(userinfo["id"]),
                "email": userinfo.get("email") or f"{userinfo['login']}@github.noemail",
            }
        raise ValueError(f"Provider inconnu : {provider}")

    async def handle_callback(
        self, provider: str, code: str, response: Response
    ) -> dict:
        # 1. Échange du code contre un token
        token_data = await self._exchange_code(provider, code)
        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token")

        # 2. Récupération des infos utilisateur
        userinfo = await self._get_userinfo(provider, access_token)
        user_data = self._extract_user_data(provider, userinfo)

        # 3. Recherche du compte OAuth existant
        oauth_account = await self._db.get_oauth_account(
            provider, user_data["provider_user_id"]
        )

        if oauth_account:
            # Utilisateur existant → on récupère son profil
            user = await self._db.get_user_by_id(oauth_account.user_id)
        else:
            # Nouvel utilisateur → création compte + liaison OAuth
            user = await self._db.get_user_by_email(user_data["email"])
            if not user:
                user = await self._db.create_user(email=user_data["email"])

            await self._db.create_oauth_account(
                user_id=user.id,
                provider=provider,
                provider_user_id=user_data["provider_user_id"],
                access_token=access_token,
                refresh_token=refresh_token,
            )

        # 4. Création session ironauth
        self._session.set_tokens(response, user.id)
        return {"user_id": user.id, "email": user.email}


def oauth(providers: list[str]) -> OAuthPlugin:
    return OAuthPlugin(providers)
