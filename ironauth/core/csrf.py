import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request


class CSRFProtection:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.cookie_name = "af_csrf_token"
        self.header_name = "X-CSRF-Token"

    def _sign(self, token: str) -> str:
        """Signe le token avec HMAC-SHA256."""
        return hmac.new(
            self.secret_key.encode(), token.encode(), hashlib.sha256
        ).hexdigest()

    def generate_token(self) -> tuple[str, str]:
        """Retourne (token_brut, token_signé)."""
        token = secrets.token_urlsafe(32)
        signed = self._sign(token)
        return token, signed

    def verify(self, raw_token: str, signed_token: str) -> bool:
        """Vérifie que le token brut correspond au token signé."""
        expected = self._sign(raw_token)
        return hmac.compare_digest(expected, signed_token)

    def set_cookie(self, response, token: str) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value=token,
            httponly=False,  # Doit être lisible par le JS pour l'envoyer en header
            secure=True,
            samesite="strict",
        )

    async def validate_request(self, request: Request) -> None:
        """Middleware de validation CSRF sur les mutations."""
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return  # Pas de CSRF sur les lectures

        # Token brut depuis le cookie
        raw_token = request.cookies.get(self.cookie_name)
        # Token signé depuis le header
        signed_token = request.headers.get(self.header_name)

        if not raw_token or not signed_token:
            raise HTTPException(status_code=403, detail="Token CSRF manquant")

        if not self.verify(raw_token, signed_token):
            raise HTTPException(status_code=403, detail="Token CSRF invalide")
