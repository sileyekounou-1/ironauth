from typing import Optional

from pydantic import BaseModel, Field, SecretStr


class CookieConfig(BaseModel):
    http_only: bool = True
    secure: bool = True
    same_site: str = "lax"
    access_token_name: str = "af_access_token"
    refresh_token_name: str = "af_refresh_token"


class TokenConfig(BaseModel):
    access_token_expiry: int = 900  # 15 min
    refresh_token_expiry: int = 604800  # 7 jours
    algorithm: str = "HS256"


class OAuthProviderConfig(BaseModel):
    client_id: str
    client_secret: SecretStr
    redirect_uri: str


class OAuthConfig(BaseModel):
    google: Optional[OAuthProviderConfig] = None
    github: Optional[OAuthProviderConfig] = None


class EmailConfig(BaseModel):
    base_url: str = "http://localhost:8000"
    app_name: str = "IronAuth"
    from_email: str = "noreply@ironauth.dev"
    from_name: str = "IronAuth"


class ironauthConfig(BaseModel):
    secret_key: SecretStr
    cookie: CookieConfig = Field(default_factory=CookieConfig)
    token: TokenConfig = Field(default_factory=TokenConfig)
    oauth: Optional[OAuthConfig] = None
    email: Optional[EmailConfig] = None
