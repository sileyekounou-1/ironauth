from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Request, Response
from ironauth.core.config import ironauthConfig


class SessionManager:
    def __init__(self, config: ironauthConfig):
        self.config = config
        self.secret = config.secret_key.get_secret_value()
        self.algorithm = config.token.algorithm
        self.cookie = config.cookie
        self.token = config.token

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

    def decode_token(self, token: str, token_type: str) -> Optional[str]:
        try:
            payload = jwt.decode(token, self.secret, algorithms=[self.algorithm])
            if payload.get("type") != token_type:
                return None
            return payload.get("sub")
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expiré")
        except jwt.InvalidTokenError:
            raise ValueError("Token invalide")

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
        self, request: Request, response: Response
    ) -> Optional[str]:
        refresh_token = self.get_refresh_token(request)
        if not refresh_token:
            return None

        user_id = self.decode_token(refresh_token, "refresh")
        if not user_id:
            return None

        # Rotation : on génère une nouvelle paire de tokens
        self.set_tokens(response, user_id)
        return user_id
