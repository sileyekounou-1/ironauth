from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class EmailMessage:
    to: str
    subject: str
    html: str
    from_email: str = "noreply@ironauth.dev"
    from_name: str = "IronAuth"


class EmailProvider(ABC):
    @abstractmethod
    async def send(self, message: EmailMessage) -> None:
        """Envoie un email. Lève une exception en cas d'échec."""
        ...
