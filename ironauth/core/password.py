import secrets
import string

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Argon2id — mêmes paramètres que l'ancienne config passlib
_ph = PasswordHasher(
    memory_cost=65536,  # 64 MB
    time_cost=3,
    parallelism=4,
)


class PasswordManager:
    def hash(self, password: str) -> str:
        return _ph.hash(password)

    def verify(self, plain: str, hashed: str) -> bool:
        try:
            return _ph.verify(hashed, plain)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, hashed: str) -> bool:
        """True si le hash a été produit avec des paramètres obsolètes."""
        try:
            return _ph.check_needs_rehash(hashed)
        except InvalidHashError:
            return True

    def validate_strength(self, password: str) -> None:
        errors = []
        if len(password) < 12:
            errors.append("Minimum 12 caractères")
        if not any(c.isupper() for c in password):
            errors.append("Au moins 1 majuscule")
        if not any(c.islower() for c in password):
            errors.append("Au moins 1 minuscule")
        if not any(c.isdigit() for c in password):
            errors.append("Au moins 1 chiffre")
        if not any(c in string.punctuation for c in password):
            errors.append("Au moins 1 caractère spécial")
        if errors:
            raise ValueError(f"Mot de passe trop faible : {', '.join(errors)}")

    def generate_reset_token(self) -> str:
        return secrets.token_urlsafe(32)


password_manager = PasswordManager()
