import secrets
from typing import Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.exc import IntegrityError

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


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    password: str


class VerifyEmailRequest(BaseModel):
    token: str


class TwoFactorValidateRequest(BaseModel):
    two_factor_token: str
    code: str


class TwoFactorCodeRequest(BaseModel):
    code: str


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
        if self.rate_limiter is not None and config.trust_proxy:
            self.rate_limiter.trust_proxy = True
        self.email_manager = email_manager
        self.csrf = CSRFProtection(config.secret_key.get_secret_value())
        self.router = APIRouter(prefix="/auth", tags=["auth"])
        self._register_routes()

    def _register_routes(self):

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
            try:
                self.password.validate_strength(body.password)
            except ValueError as e:
                raise HTTPException(status_code=422, detail=str(e))
            existing = await self.db.get_user_by_email(body.email)
            if existing:
                if self.rate_limiter:
                    await self.rate_limiter.record_failure(request, "register")
                raise HTTPException(status_code=400, detail="Email deja utilise")
            hashed = self.password.hash(body.password)
            try:
                user = await self.db.create_user(email=body.email, hashed_password=hashed)
            except IntegrityError:
                # Race : un autre register concurrent a inséré le même email
                raise HTTPException(status_code=400, detail="Email deja utilise")
            self.session.set_tokens(response, user.id)
            return {"message": "Compte cree", "user_id": user.id}

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
            if not user.is_active:
                raise HTTPException(status_code=401, detail="Compte desactive")
            if self.rate_limiter:
                await self.rate_limiter.record_success(request, "login")

            # Rehash transparent si les paramètres Argon2 ont évolué
            if self.password.needs_rehash(user.hashed_password):
                await self.db.update_user(
                    user.id, hashed_password=self.password.hash(body.password)
                )

            # 2FA activé : on n'émet PAS la session complète. On renvoie un token
            # intermédiaire court à échanger sur /2fa/validate avec le code TOTP.
            if self.two_factor_plugin and user.totp_enabled:
                two_factor_token = self.session.create_2fa_token(user.id)
                return {
                    "message": "2FA requis",
                    "two_factor_required": True,
                    "two_factor_token": two_factor_token,
                }

            self.session.set_tokens(response, user.id)
            return {"message": "Connecte"}

        @self.router.post("/logout")
        async def logout(request: Request, response: Response):
            await self.csrf.validate_request(request)
            refresh_token = self.session.get_refresh_token(request)
            if refresh_token:
                await self.session.revoke_token(refresh_token)
            self.session.clear_tokens(response)
            return {"message": "Deconnecte"}

        @self.router.post("/refresh")
        async def refresh(request: Request, response: Response):
            await self.csrf.validate_request(request)

            async def _validate(user_id: str, payload: dict) -> bool:
                user = await self.db.get_user_by_id(user_id)
                if not user or not user.is_active:
                    return False
                return self.session.is_session_valid(payload, user.sessions_valid_from)

            user_id = await self.session.refresh_session(
                request, response, validate=_validate
            )
            if not user_id:
                raise HTTPException(status_code=401, detail="Session expiree")
            return {"message": "Session renouvelee"}

        if self.oauth_plugin:

            @self.router.get("/oauth/{provider}")
            async def oauth_redirect(provider: str, response: Response):
                assert self.oauth_plugin is not None
                state = secrets.token_urlsafe(32)
                url = self.oauth_plugin.get_authorization_url(provider, state)
                response.set_cookie(
                    key="af_oauth_state",
                    value=state,
                    max_age=600,
                    httponly=True,
                    secure=self.config.cookie.secure,
                    samesite="lax",
                )
                return RedirectResponse(url)

            @self.router.get("/oauth/{provider}/callback")
            async def oauth_callback(
                provider: str, code: str, state: str, request: Request, response: Response
            ):
                assert self.oauth_plugin is not None
                expected_state = request.cookies.get("af_oauth_state")
                if not expected_state or not secrets.compare_digest(state, expected_state):
                    raise HTTPException(status_code=400, detail="State OAuth invalide")
                response.delete_cookie("af_oauth_state")
                try:
                    result = await self.oauth_plugin.handle_callback(provider, code, response)
                    return {"message": "Connecte via OAuth", **result}
                except Exception as e:
                    raise HTTPException(status_code=400, detail=str(e))

        if self.email_manager:

            @self.router.post("/send-verification-email")
            async def send_verification(user: User = Depends(self.current_user())):
                assert self.email_manager is not None
                try:
                    await self.email_manager.send_verification_email(user.id)
                    return {"message": "Email de verification envoye"}
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))

            @self.router.post("/verify-email")
            async def verify_email(body: VerifyEmailRequest):
                # POST + token dans le body : évite la fuite du token via logs/referrer,
                # et le prefetch de lien (GET) qui consommerait le token.
                assert self.email_manager is not None
                verified = await self.email_manager.verify_email(body.token)
                if not verified:
                    raise HTTPException(status_code=400, detail="Token invalide ou expire")
                return {"message": "Email verifie"}

            @self.router.post("/forgot-password")
            async def forgot_password(request: Request, body: ForgotPasswordRequest):
                await self.csrf.validate_request(request)
                assert self.email_manager is not None
                await self.email_manager.send_reset_password_email(body.email)
                return {"message": "Si cet email existe, un lien a ete envoye"}

            @self.router.post("/reset-password")
            async def reset_password(request: Request, body: ResetPasswordRequest):
                await self.csrf.validate_request(request)
                assert self.email_manager is not None
                try:
                    success = await self.email_manager.reset_password(
                        body.token, body.password, self.password
                    )
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                if not success:
                    raise HTTPException(status_code=400, detail="Token invalide ou expire")
                return {"message": "Mot de passe reinitialise"}

        if self.two_factor_plugin:

            @self.router.post("/2fa/enable")
            async def enable_2fa(request: Request, user: User = Depends(self.current_user())):
                await self.csrf.validate_request(request)
                assert self.two_factor_plugin is not None
                try:
                    result = await self.two_factor_plugin.enable_2fa(user.id)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                return result

            @self.router.post("/2fa/confirm")
            async def confirm_2fa(body: TwoFactorCodeRequest, request: Request, user: User = Depends(self.current_user())):
                await self.csrf.validate_request(request)
                assert self.two_factor_plugin is not None
                try:
                    confirmed = await self.two_factor_plugin.confirm_2fa(user.id, body.code)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                if not confirmed:
                    raise HTTPException(status_code=400, detail="Code invalide")
                return {"message": "2FA active"}

            @self.router.post("/2fa/validate")
            async def validate_2fa(
                body: TwoFactorValidateRequest, request: Request, response: Response
            ):
                # L'utilisateur est identifié par le token 2FA émis au login,
                # PAS par un user_id arbitraire dans le body (sinon oracle TOTP).
                await self.csrf.validate_request(request)
                assert self.two_factor_plugin is not None
                if self.rate_limiter:
                    await self.rate_limiter.check(request, "2fa_validate")
                try:
                    user_id = self.session.decode_token(body.two_factor_token, "2fa")
                except ValueError:
                    raise HTTPException(status_code=401, detail="Token 2FA expire ou invalide")
                if not user_id:
                    raise HTTPException(status_code=401, detail="Token 2FA invalide")
                try:
                    valid = await self.two_factor_plugin.validate_2fa(user_id, body.code)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                if not valid:
                    if self.rate_limiter:
                        await self.rate_limiter.record_failure(request, "2fa_validate")
                    raise HTTPException(status_code=401, detail="Code 2FA invalide")
                if self.rate_limiter:
                    await self.rate_limiter.record_success(request, "2fa_validate")
                # Code correct → on émet enfin la vraie session
                self.session.set_tokens(response, user_id)
                return {"message": "Connecte"}

            @self.router.post("/2fa/disable")
            async def disable_2fa(body: TwoFactorCodeRequest, request: Request, user: User = Depends(self.current_user())):
                await self.csrf.validate_request(request)
                assert self.two_factor_plugin is not None
                try:
                    disabled = await self.two_factor_plugin.disable_2fa(user.id, body.code)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                if not disabled:
                    raise HTTPException(status_code=400, detail="Code invalide")
                return {"message": "2FA desactive"}

    def current_user(self, required: bool = True) -> Callable:
        async def _get_current_user(request: Request) -> User | None:
            token = self.session.get_access_token(request)
            if not token:
                if required:
                    raise HTTPException(status_code=401, detail="Non authentifie")
                return None
            try:
                payload = await self.session.decode_token_safe(token, "access")
                if not payload or not payload.get("sub"):
                    raise HTTPException(status_code=401, detail="Token invalide")
            except ValueError as e:
                raise HTTPException(status_code=401, detail=str(e))

            user = await self.db.get_user_by_id(payload["sub"])
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="Utilisateur introuvable")
            # Token émis avant une révocation de masse (reset mdp) → invalide
            if not self.session.is_session_valid(payload, user.sessions_valid_from):
                raise HTTPException(status_code=401, detail="Session revoquee")
            return user

        return _get_current_user


def fastapi_adapter() -> dict:
    return {"type": "fastapi"}
