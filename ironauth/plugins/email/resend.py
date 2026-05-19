import httpx

from ironauth.plugins.email.base import EmailMessage, EmailProvider


class ResendProvider(EmailProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._base_url = "https://api.resend.com"

    async def send(self, message: EmailMessage) -> None:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self._base_url}/emails",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": f"{message.from_name} <{message.from_email}>",
                    "to": [message.to],
                    "subject": message.subject,
                    "html": message.html,
                },
            )
            if response.status_code not in (200, 201):
                raise RuntimeError(
                    f"Resend API error {response.status_code}: {response.text}"
                )


def resend(api_key: str) -> ResendProvider:
    return ResendProvider(api_key)
