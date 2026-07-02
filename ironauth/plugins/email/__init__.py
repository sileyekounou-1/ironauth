from ironauth.plugins.email.base import EmailMessage, EmailProvider
from ironauth.plugins.email.resend import ResendProvider, resend
from ironauth.plugins.email.smtp import SMTPProvider, smtp

__all__ = [
    "EmailProvider",
    "EmailMessage",
    "smtp",
    "SMTPProvider",
    "resend",
    "ResendProvider",
]
