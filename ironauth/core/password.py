import secrets
import string

from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64MB
    argon2__time_cost=3,
    argon2__parallelism=4,
)


class PasswordManager:
    def hash(self, password: str) -> str:
        return pwd_context.hash(password)

    def verify(self, plain: str, hashed: str) -> bool:
        return pwd_context.verify(plain, hashed)

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
