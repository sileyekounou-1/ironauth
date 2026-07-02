import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Request, Response

from ironauth.core.config import ironauthConfig
from ironauth.core.token_blacklist import TokenBlacklist


class SessionManager:
    def __init__(
        self, config: ironauthConfig, blacklist: TokenBlacklist | None = None
    ):
        self.config = config
        self.secret = config.secret_key.get_secret_value()
        self.algorithm = config.token.algorithm
        self.cookie = config.cookie
        self.token = config.token
        self.blacklist = blacklist or TokenBlacklist()

    # --- JWT ---

    def _create_token(self, payload: dict, expiry_seconds: int) -> str:
        now = datetime.now(timezone.utc)
        payload.update(
            {
                "iat": now,
                "exp": now + timedelta(seconds=expiry_seconds),
            }
        )
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def create_access_token(self, user_id: str) -> str:
        return self._create_token(
            {"sub": user_id, "type": "access"}, self.token.access_token_expiry
        )

    def create_refresh_token(self, user_id: str) -> str:
        return self._create_token(
            {"sub": user_id, "type": "refresh"}, self.token.refresh_token_expiry
        )

    def create_2fa_token(self, user_id: str) -> str:
        """Token intermédiaire court (5 min) émis après le mot de passe,
        avant la validation du code TOTP. Ne donne accès à rien d'autre."""
        return self._create_token({"sub": user_id, "type": "2fa"}, 300)

    def _decode(self, token: str, token_type: str) -> Optional[dict]:
        """Décode et valide le payload complet. Lève ValueError si expiré/invalide."""
        try:
            payload = jwt.decode(token, self.secret, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expiré")
        except jwt.InvalidTokenError:
            raise ValueError("Token invalide")
        if payload.get("type") != token_type:
            return None
        return payload

    def decode_token(self, token: str, token_type: str) -> Optional[str]:
        payload = self._decode(token, token_type)
        return payload.get("sub") if payload else None

    def decode_token_full(self, token: str, token_type: str) -> Optional[dict]:
        """Retourne le payload complet (sub, iat, exp...) ou None si type incorrect."""
        return self._decode(token, token_type)

    async def decode_token_safe(self, token: str, token_type: str) -> Optional[dict]:
        """Vérifie le token ET la blacklist, retourne le payload complet."""
        if await self.blacklist.is_blacklisted(token):
            raise ValueError("Token révoqué")
        return self._decode(token, token_type)

    @staticmethod
    def is_session_valid(payload: dict, sessions_valid_from: Optional[float]) -> bool:
        """False si le token a été émis avant une révocation de masse (reset mdp...)."""
        if sessions_valid_from is None:
            return True
        iat = payload.get("iat")
        if iat is None:
            return False
        # iat est un int epoch (PyJWT sérialise les datetime en timestamp)
        return float(iat) >= sessions_valid_from

    async def revoke_token(self, token: str) -> None:
        """Ajoute un token à la blacklist jusqu'à son expiration."""
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                options={"verify_exp": False},  # on révoque même les tokens expirés
            )
            expires_at = float(payload.get("exp", time.time()))
            await self.blacklist.add(token, expires_at)
        except jwt.InvalidTokenError:
            pass  # Token déjà invalide, rien à faire

    # --- Cookies ---

    def set_tokens(self, response: Response, user_id: str) -> None:
        access_token = self.create_access_token(user_id)
        refresh_token = self.create_refresh_token(user_id)

        response.set_cookie(
            key=self.cookie.access_token_name,
            value=access_token,
            max_age=self.token.access_token_expiry,
            httponly=self.cookie.http_only,
            secure=self.cookie.secure,
            samesite=self.cookie.same_site,
        )
        response.set_cookie(
            key=self.cookie.refresh_token_name,
            value=refresh_token,
            max_age=self.token.refresh_token_expiry,
            httponly=self.cookie.http_only,
            secure=self.cookie.secure,
            samesite=self.cookie.same_site,
        )

    def clear_tokens(self, response: Response) -> None:
        response.delete_cookie(self.cookie.access_token_name)
        response.delete_cookie(self.cookie.refresh_token_name)

    def get_access_token(self, request: Request) -> Optional[str]:
        return request.cookies.get(self.cookie.access_token_name)

    def get_refresh_token(self, request: Request) -> Optional[str]:
        return request.cookies.get(self.cookie.refresh_token_name)

    # --- Refresh ---

    async def refresh_session(
        self, request: Request, response: Response, validate=None
    ) -> Optional[str]:
        """
        Fait tourner la paire de tokens.

        `validate` : callback async optionnel (user_id, payload) -> bool.
        Permet à l'appelant de vérifier is_active et sessions_valid_from
        avant d'émettre une nouvelle session. Retourne None si invalide.
        """
        refresh_token = self.get_refresh_token(request)
        if not refresh_token:
            return None

        # Vérifie blacklist avant de décoder
        if await self.blacklist.is_blacklisted(refresh_token):
            return None

        try:
            payload = self._decode(refresh_token, "refresh")
        except ValueError:
            return None  # Token expiré ou invalide → 401 côté route, pas 500
        if not payload:
            return None

        user_id = payload.get("sub")
        if not user_id:
            return None

        if validate is not None and not await validate(user_id, payload):
            return None

        # Révoque l'ancien refresh token — rotation réelle
        await self.revoke_token(refresh_token)

        # Émet une nouvelle paire
        self.set_tokens(response, user_id)
        return user_id
