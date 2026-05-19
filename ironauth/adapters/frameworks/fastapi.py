import secrets
from typing import Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr

from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.core.config import ironauthConfig
from ironauth.core.csrf import CSRFProtection
from ironauth.core.email_manager import EmailManager
from ironauth.core.password import PasswordManager
from ironauth.core.session import SessionManager
from ironauth.models.user import User
from ironauth.plugins.oauth import OAuthPlugin
from ironauth.plugins.rate_limit import RateLimiter
from ironauth.plugins.two_factor import TwoFactorPlugin


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
        oauth_plugin: OAuthPlugin | None = None,
        two_factor_plugin: TwoFactorPlugin | None = None,
        rate_limiter: RateLimiter | None = None,
        email_manager: Optional[EmailManager] = None,
    ):
        self.config = config
        self.db = db
        self.session = session
        self.password = password
        self.oauth_plugin = oauth_plugin
        self.two_factor_plugin = two_factor_plugin
        self.rate_limiter = rate_limiter
        self.email_manager = email_manager
        self.csrf = CSRFProtection(config.secret_key.get_secret_value())
        self.router = APIRouter(prefix="/auth", tags=["auth"])
        self._register_routes()

    def _register_routes(self):

        # --- Email / Password ---

        @self.router.get("/csrf-token")
        async def get_csrf_token(response: Response):
            raw_token, signed_token = self.csrf.generate_token()
            self.csrf.set_cookie(response, raw_token)
            return {"csrf_token": signed_token}

        @self.router.post("/register")
        async def register(body: RegisterRequest, request: Request, response: Response):
            await self.csrf.validate_request(request)
            if self.rate_limiter:
                await self.rate_limiter.check(request, "register")
            existing = await self.db.get_user_by_email(body.email)
            if existing:
                if self.rate_limiter:
                    await self.rate_limiter.record_failure(request, "register")
                raise HTTPException(status_code=400, detail="Email déjà utilisé")
            try:
                self.password.validate_strength(body.password)
            except ValueError as e:
                raise HTTPException(status_code=422, detail=str(e))
            hashed = self.password.hash(body.password)
            user = await self.db.create_user(email=body.email, hashed_password=hashed)
            self.session.set_tokens(response, user.id)
            return {"message": "Compte créé", "user_id": user.id}

        @self.router.post("/login")
        async def login(body: LoginRequest, request: Request, response: Response):
            await self.csrf.validate_request(request)
            if self.rate_limiter:
                await self.rate_limiter.check(request, "login")
            user = await self.db.get_user_by_email(body.email)
            if not user or not user.hashed_password:
                if self.rate_limiter:
                    await self.rate_limiter.record_failure(request, "login")
                raise HTTPException(status_code=401, detail="Identifiants invalides")
            if not self.password.verify(body.password, user.hashed_password):
                if self.rate_limiter:
                    await self.rate_limiter.record_failure(request, "login")
                raise HTTPException(status_code=401, detail="Identifiants invalides")
            if self.rate_limiter:
                await self.rate_limiter.record_success(request, "login")
            self.session.set_tokens(response, user.id)
            return {"message": "Connecté", "user_id": user.id}

        @self.router.post("/logout")
        async def logout(request: Request, response: Response):
            await self.csrf.validate_request(request)
            refresh_token = self.session.get_refresh_token(request)
            if refresh_token:
                await self.session.revoke_token(refresh_token)
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

        # --- Email Verification + Reset Password ---

        if self.email_manager:

            @self.router.post("/send-verification-email")
            async def send_verification(
                user: User = Depends(self.current_user())
            ):
                assert self.email_manager is not None
                try:
                    await self.email_manager.send_verification_email(user.id)
                    return {"message": "Email de vérification envoyé"}
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))

            @self.router.get("/verify-email")
            async def verify_email(token: str):
                assert self.email_manager is not None
                verified = await self.email_manager.verify_email(token)
                if not verified:
                    raise HTTPException(status_code=400, detail="Token invalide ou expiré")
                return {"message": "Email vérifié"}

            @self.router.post("/forgot-password")
            async def forgot_password(request: Request, body: dict):
                await self.csrf.validate_request(request)
                assert self.email_manager is not None
                email = body.get("email")
                if not email:
                    raise HTTPException(status_code=400, detail="Email requis")
                # Toujours retourner 200 — anti-énumération
                await self.email_manager.send_reset_password_email(email)
                return {"message": "Si cet email existe, un lien de réinitialisation a été envoyé"}

            @self.router.post("/reset-password")
            async def reset_password(request: Request, body: dict):
                await self.csrf.validate_request(request)
                assert self.email_manager is not None
                token = body.get("token")
                new_password = body.get("password")
                if not token or not new_password:
                    raise HTTPException(status_code=400, detail="Token et mot de passe requis")
                try:
                    success = await self.email_manager.reset_password(
                        token, new_password, self.password
                    )
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                if not success:
                    raise HTTPException(status_code=400, detail="Token invalide ou expiré")
                return {"message": "Mot de passe réinitialisé"}

        # --- 2FA ---

        if self.two_factor_plugin:

            @self.router.post("/2fa/enable")
            async def enable_2fa(
                request: Request, user: User = Depends(self.current_user())
            ):
                assert self.two_factor_plugin is not None
                try:
                    result = await self.two_factor_plugin.enable_2fa(user.id)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                return result

            @self.router.post("/2fa/confirm")
            async def confirm_2fa(
                body: dict, user: User = Depends(self.current_user())
            ):
                assert self.two_factor_plugin is not None
                if "code" not in body:
                    raise HTTPException(status_code=400, detail="Code requis")
                try:
                    confirmed = await self.two_factor_plugin.confirm_2fa(
                        user.id, body["code"]
                    )
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
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
                try:
                    valid = await self.two_factor_plugin.validate_2fa(user_id, code)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                if not valid:
                    raise HTTPException(status_code=401, detail="Code 2FA invalide")
                return {"message": "2FA validé"}

            @self.router.post("/2fa/disable")
            async def disable_2fa(
                body: dict, user: User = Depends(self.current_user())
            ):
                assert self.two_factor_plugin is not None
                if "code" not in body:
                    raise HTTPException(status_code=400, detail="Code requis")
                try:
                    disabled = await self.two_factor_plugin.disable_2fa(
                        user.id, body["code"]
                    )
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                if not disabled:
                    raise HTTPException(status_code=400, detail="Code invalide")
                return {"message": "2FA désactivé"}

    # --- Dependency : current_user ---

    def current_user(self, required: bool = True) -> Callable:
        async def _get_current_user(request: Request) -> User | None:
            token = self.session.get_access_token(request)
            if not token:
                if required:
                    raise HTTPException(status_code=401, detail="Non authentifié")
                return None
            try:
                user_id = await self.session.decode_token_safe(token, "access")
                if not user_id:
                    raise HTTPException(status_code=401, detail="Token invalide")
            except ValueError as e:
                raise HTTPException(status_code=401, detail=str(e))

            user = await self.db.get_user_by_id(user_id)
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="Utilisateur introuvable")
            return user

        return _get_current_user


def fastapi_adapter() -> dict:
    return {"type": "fastapi"}
