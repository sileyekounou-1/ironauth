"""IronAuth — bibliothèque d'authentification agnostique du framework pour Python."""

from ironauth.adapters.database.sqlalchemy import (
    SQLAlchemyAdapter,
    sqlalchemy_adapter,
)
from ironauth.adapters.frameworks.fastapi import fastapi_adapter
from ironauth.core.auth import ironauth
from ironauth.core.config import (
    CookieConfig,
    EmailConfig,
    OAuthConfig,
    OAuthProviderConfig,
    TokenConfig,
    ironauthConfig,
)
from ironauth.models.user import Base, OAuthAccount, User
from ironauth.plugins.email.base import EmailMessage, EmailProvider
from ironauth.plugins.email.resend import ResendProvider, resend
from ironauth.plugins.email.smtp import SMTPProvider, smtp
from ironauth.plugins.oauth import OAuthPlugin, oauth
from ironauth.plugins.rate_limit import RateLimiter, rate_limit
from ironauth.plugins.two_factor import TwoFactorPlugin, two_factor

# Alias PascalCase recommandé pour le point d'entrée public
IronAuth = ironauth

__version__ = "0.2.1"

__all__ = [
    "IronAuth",
    "ironauth",
    "ironauthConfig",
    "CookieConfig",
    "TokenConfig",
    "OAuthConfig",
    "OAuthProviderConfig",
    "EmailConfig",
    "SQLAlchemyAdapter",
    "sqlalchemy_adapter",
    "fastapi_adapter",
    "Base",
    "User",
    "OAuthAccount",
    "oauth",
    "OAuthPlugin",
    "two_factor",
    "TwoFactorPlugin",
    "rate_limit",
    "RateLimiter",
    "smtp",
    "SMTPProvider",
    "resend",
    "ResendProvider",
    "EmailProvider",
    "EmailMessage",
]
