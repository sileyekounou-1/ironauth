import aiosmtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from ironauth.plugins.email.base import EmailMessage, EmailProvider


class SMTPProvider(EmailProvider):
    def __init__(
        self,
        host: str,
        port: int = 587,
        username: str = "",
        password: str = "",
        use_tls: bool = True,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls

    async def send(self, message: EmailMessage) -> None:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = message.subject
        msg["From"] = f"{message.from_name} <{message.from_email}>"
        msg["To"] = message.to
        msg.attach(MIMEText(message.html, "html"))

        await aiosmtplib.send(
            msg,
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            start_tls=self.use_tls,
        )


def smtp(
    host: str,
    port: int = 587,
    username: str = "",
    password: str = "",
    use_tls: bool = True,
) -> SMTPProvider:
    return SMTPProvider(host, port, username, password, use_tls)
