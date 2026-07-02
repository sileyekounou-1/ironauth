import hashlib
import secrets
import time

from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.plugins.email.base import EmailMessage, EmailProvider
from ironauth.plugins.email.templates import reset_password_email, verification_email

VERIFICATION_TOKEN_TTL = 86400  # 24 heures
RESET_TOKEN_TTL = 3600  # 1 heure


def _hash_token(token: str) -> str:
    """Hash SHA-256 d'un token. Suffisant car le token brut a 256 bits d'entropie."""
    return hashlib.sha256(token.encode()).hexdigest()


class EmailManager:
    def __init__(
        self,
        db: SQLAlchemyAdapter,
        provider: EmailProvider,
        base_url: str,
        app_name: str = "IronAuth",
        from_email: str = "noreply@ironauth.dev",
        from_name: str = "IronAuth",
    ):
        self._db = db
        self._provider = provider
        self._base_url = base_url.rstrip("/")
        self._app_name = app_name
        self._from_email = from_email
        self._from_name = from_name

    # --- Email Verification ---

    async def send_verification_email(self, user_id: str) -> None:
        user = await self._db.get_user_by_id(user_id)
        if not user:
            raise ValueError("Utilisateur introuvable")
        if user.is_verified:
            raise ValueError("Email déjà vérifié")

        token = secrets.token_urlsafe(32)
        await self._db.update_user(
            user_id,
            email_verification_token=_hash_token(token),
            email_verification_expires_at=time.time() + VERIFICATION_TOKEN_TTL,
        )

        verification_url = f"{self._base_url}/auth/verify-email?token={token}"
        html = verification_email(user.email, verification_url, self._app_name)

        await self._provider.send(EmailMessage(
            to=user.email,
            subject=f"Vérifiez votre email — {self._app_name}",
            html=html,
            from_email=self._from_email,
            from_name=self._from_name,
        ))

    async def verify_email(self, token: str) -> bool:
        user = await self._db.get_user_by_verification_token(_hash_token(token))
        if not user:
            return False

        # Vérifie l'expiration du token
        if not user.email_verification_expires_at:
            return False
        if time.time() > user.email_verification_expires_at:
            return False

        await self._db.update_user(
            user.id,
            is_verified=True,
            email_verification_token=None,
            email_verification_expires_at=None,
        )
        return True

    # --- Reset Password ---

    async def send_reset_password_email(self, email: str) -> None:
        user = await self._db.get_user_by_email(email)
        # On ne lève pas d'erreur si l'email n'existe pas — anti-enumération
        if not user:
            return

        token = secrets.token_urlsafe(32)
        expires_at = time.time() + RESET_TOKEN_TTL

        await self._db.update_user(
            user.id,
            password_reset_token=_hash_token(token),
            password_reset_expires_at=expires_at,
        )

        reset_url = f"{self._base_url}/auth/reset-password?token={token}"
        html = reset_password_email(user.email, reset_url, self._app_name)

        await self._provider.send(EmailMessage(
            to=user.email,
            subject=f"Réinitialisation de mot de passe — {self._app_name}",
            html=html,
            from_email=self._from_email,
            from_name=self._from_name,
        ))

    async def reset_password(self, token: str, new_password: str, password_manager) -> bool:
        user = await self._db.get_user_by_reset_token(_hash_token(token))
        if not user:
            return False

        # Vérifie expiration
        if not user.password_reset_expires_at:
            return False
        if time.time() > user.password_reset_expires_at:
            return False

        password_manager.validate_strength(new_password)
        hashed = password_manager.hash(new_password)

        await self._db.update_user(
            user.id,
            hashed_password=hashed,
            password_reset_token=None,
            password_reset_expires_at=None,
            # Invalide toutes les sessions émises avant le reset
            sessions_valid_from=time.time(),
        )
        return True
