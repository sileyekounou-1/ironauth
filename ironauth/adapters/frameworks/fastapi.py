import secrets
from typing import Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.core.config import ironauthConfig
from ironauth.core.password import PasswordManager
from ironauth.core.session import SessionManager
from ironauth.models.user import User
from ironauth.plugins.oauth import OAuthPlugin
from ironauth.plugins.two_factor import TwoFactorPlugin
from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class FastAPIAdapter:
    def __init__(
        self,
        config: ironauthConfig,
        db: SQLAlchemyAdapter,
        session: SessionManager,
        password: PasswordManager,
        oauth_plugin: Optional[OAuthPlugin] = None,
        two_factor_plugin: Optional[TwoFactorPlugin] = None,
    ):
        self.config = config
        self.db = db
        self.session = session
        self.password = password
        self.oauth_plugin = oauth_plugin
        self.two_factor_plugin = two_factor_plugin
        self.router = APIRouter(prefix="/auth", tags=["auth"])
        self._register_routes()

    def _register_routes(self):

        # --- Email / Password ---

        @self.router.post("/register")
        async def register(body: RegisterRequest, response: Response):
            existing = await self.db.get_user_by_email(body.email)
            if existing:
                raise HTTPException(status_code=400, detail="Email déjà utilisé")

            self.password.validate_strength(body.password)
            hashed = self.password.hash(body.password)
            user = await self.db.create_user(email=body.email, hashed_password=hashed)
            self.session.set_tokens(response, user.id)
            return {"message": "Compte créé", "user_id": user.id}

        @self.router.post("/login")
        async def login(body: LoginRequest, response: Response):
            user = await self.db.get_user_by_email(body.email)
            if not user or not user.hashed_password:
                raise HTTPException(status_code=401, detail="Identifiants invalides")
            if not self.password.verify(body.password, user.hashed_password):
                raise HTTPException(status_code=401, detail="Identifiants invalides")
            if not user.is_active:
                raise HTTPException(status_code=403, detail="Compte désactivé")

            self.session.set_tokens(response, user.id)
            return {"message": "Connecté", "user_id": user.id}

        @self.router.post("/logout")
        async def logout(response: Response):
            self.session.clear_tokens(response)
            return {"message": "Déconnecté"}

        @self.router.post("/refresh")
        async def refresh(request: Request, response: Response):
            user_id = await self.session.refresh_session(request, response)
            if not user_id:
                raise HTTPException(status_code=401, detail="Session expirée")
            return {"message": "Session renouvelée"}

        # --- OAuth ---

        if self.oauth_plugin:

            @self.router.get("/oauth/{provider}")
            async def oauth_redirect(provider: str, response: Response):
                assert self.oauth_plugin is not None
                state = secrets.token_urlsafe(16)
                url = self.oauth_plugin.get_authorization_url(provider, state)
                return RedirectResponse(url)

            @self.router.get("/oauth/{provider}/callback")
            async def oauth_callback(provider: str, code: str, response: Response):
                assert self.oauth_plugin is not None
                try:
                    result = await self.oauth_plugin.handle_callback(
                        provider, code, response
                    )
                    return {"message": "Connecté via OAuth", **result}
                except Exception as e:
                    raise HTTPException(status_code=400, detail=str(e))

        # --- 2FA ---

        if self.two_factor_plugin:

            @self.router.post("/2fa/enable")
            async def enable_2fa(
                request: Request, user: User = Depends(self.current_user())
            ):
                assert self.two_factor_plugin is not None
                result = await self.two_factor_plugin.enable_2fa(user.id)
                return result

            @self.router.post("/2fa/confirm")
            async def confirm_2fa(
                body: dict, user: User = Depends(self.current_user())
            ):
                assert self.two_factor_plugin is not None
                confirmed = await self.two_factor_plugin.confirm_2fa(
                    user.id, body["code"]
                )
                if not confirmed:
                    raise HTTPException(status_code=400, detail="Code invalide")
                return {"message": "2FA activé"}

            @self.router.post("/2fa/validate")
            async def validate_2fa(body: dict):
                assert self.two_factor_plugin is not None
                user_id = body.get("user_id")
                code = body.get("code")
                if not user_id or not code:
                    raise HTTPException(
                        status_code=400, detail="user_id et code requis"
                    )
                valid = await self.two_factor_plugin.validate_2fa(user_id, code)
                if not valid:
                    raise HTTPException(status_code=401, detail="Code 2FA invalide")
                return {"message": "2FA validé"}

            @self.router.post("/2fa/disable")
            async def disable_2fa(
                body: dict, user: User = Depends(self.current_user())
            ):
                assert self.two_factor_plugin is not None
                disabled = await self.two_factor_plugin.disable_2fa(
                    user.id, body["code"]
                )
                if not disabled:
                    raise HTTPException(status_code=400, detail="Code invalide")
                return {"message": "2FA désactivé"}

    # --- Dependency : current_user ---

    def current_user(self, required: bool = True) -> Callable:
        async def _get_current_user(request: Request) -> Optional[User]:
            token = self.session.get_access_token(request)
            if not token:
                if required:
                    raise HTTPException(status_code=401, detail="Non authentifié")
                return None
            try:
                user_id = self.session.decode_token(token, "access")
                if not user_id:
                    raise HTTPException(status_code=401, detail="Token invalide")
                user = await self.db.get_user_by_id(user_id)
            except ValueError as e:
                raise HTTPException(status_code=401, detail=str(e))

            user = await self.db.get_user_by_id(user_id)
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="Utilisateur introuvable")
            return user

        return _get_current_user


def fastapi_adapter() -> dict:
    return {"type": "fastapi"}
