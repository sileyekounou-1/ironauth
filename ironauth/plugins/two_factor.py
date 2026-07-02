# ironauth/plugins/two_factor.py
import base64
import io
from typing import Optional

import pyotp
import qrcode
import qrcode.image.svg
from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter


class TwoFactorPlugin:
    def __init__(self):
        self._db: Optional[SQLAlchemyAdapter] = None

    def init(self, db: SQLAlchemyAdapter):
        self._db = db

    def generate_secret(self) -> str:
        """Génère un secret TOTP unique par utilisateur."""
        return pyotp.random_base32()

    def get_totp_uri(self, secret: str, email: str, issuer: str = "ironauth") -> str:
        """Génère l'URI TOTP pour le QR code."""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=issuer)

    def generate_qr_code(self, totp_uri: str) -> str:
        """Génère un QR code en base64 (PNG) à afficher côté client."""
        img = qrcode.make(totp_uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return base64.b64encode(buffer.read()).decode("utf-8")

    def verify_code(self, secret: str, code: str) -> bool:
        """Vérifie un code TOTP — fenêtre de 1 intervalle (30s avant/après)."""
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    async def enable_2fa(self, user_id: str) -> dict:
        """Étape 1 : génère le secret et le QR code, stocke le secret (non activé)."""
        user = await self._db.get_user_by_id(user_id)
        if not user:
            raise ValueError("Utilisateur introuvable")

        # Refuse d'écraser un 2FA déjà actif : sinon on le désactive sans code.
        # Pour reconfigurer, il faut d'abord appeler /2fa/disable avec un code valide.
        if user.totp_enabled:
            raise ValueError("2FA déjà activé — désactive-le d'abord pour le reconfigurer")

        secret = self.generate_secret()
        # Stocke le secret en attente de confirmation
        await self._db.update_user(user_id, totp_secret=secret, totp_enabled=False)

        uri = self.get_totp_uri(secret, user.email)
        qr = self.generate_qr_code(uri)

        return {
            "secret": secret,  # À afficher en fallback texte
            "qr_code": qr,  # Image PNG base64
        }

    async def confirm_2fa(self, user_id: str, code: str) -> bool:
        """Étape 2 : l'utilisateur confirme avec son premier code TOTP."""
        user = await self._db.get_user_by_id(user_id)
        if not user or not user.totp_secret:
            raise ValueError("2FA non initialisé")

        if not self.verify_code(user.totp_secret, code):
            return False

        await self._db.update_user(user_id, totp_enabled=True)
        return True

    async def validate_2fa(self, user_id: str, code: str) -> bool:
        """Vérifie le code TOTP lors de la connexion."""
        user = await self._db.get_user_by_id(user_id)
        if not user or not user.totp_enabled or not user.totp_secret:
            raise ValueError("2FA non activé pour cet utilisateur")

        return self.verify_code(user.totp_secret, code)

    async def disable_2fa(self, user_id: str, code: str) -> bool:
        """Désactive le 2FA après vérification du code actuel."""
        user = await self._db.get_user_by_id(user_id)
        if not user or not user.totp_secret:
            raise ValueError("2FA non activé")

        if not self.verify_code(user.totp_secret, code):
            return False

        await self._db.update_user(user_id, totp_secret=None, totp_enabled=False)
        return True


def two_factor() -> TwoFactorPlugin:
    return TwoFactorPlugin()
