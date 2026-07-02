from typing import Literal, Optional

from pydantic import BaseModel, Field, SecretStr, field_validator


class CookieConfig(BaseModel):
    http_only: bool = True
    secure: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"
    access_token_name: str = "af_access_token"
    refresh_token_name: str = "af_refresh_token"


class TokenConfig(BaseModel):
    access_token_expiry: int = 900  # 15 min
    refresh_token_expiry: int = 604800  # 7 jours
    # Seuls les algorithmes HMAC symétrique sont autorisés — "none" est rejeté
    algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"


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
    # Derrière un reverse proxy fiable : lire l'IP client depuis X-Forwarded-For
    trust_proxy: bool = False

    @field_validator("secret_key")
    @classmethod
    def _secret_key_min_length(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError(
                "secret_key doit faire au moins 32 caractères "
                "(un secret HMAC court est vulnérable au brute-force)"
            )
        return v
