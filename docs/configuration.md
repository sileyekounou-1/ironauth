# Configuration

## Full reference

```python
auth = ironauth(
    database=sqlalchemy_adapter("postgresql+asyncpg://..."),
    adapter=fastapi_adapter(),
    plugins=[...],
    config={
        # Required
        "secret_key": "your-secret-key",

        # Token settings (optional)
        "token": {
            "access_token_expiry": 900,       # 15 minutes
            "refresh_token_expiry": 604800,   # 7 days
            "algorithm": "HS256",
        },

        # Cookie settings (optional)
        "cookie": {
            "http_only": True,
            "secure": True,
            "same_site": "lax",
            "access_token_name": "af_access_token",
            "refresh_token_name": "af_refresh_token",
        },

        # OAuth (required if using oauth plugin)
        "oauth": {
            "google": {
                "client_id": "...",
                "client_secret": "...",
                "redirect_uri": "http://localhost:8000/auth/oauth/google/callback",
            },
            "github": {
                "client_id": "...",
                "client_secret": "...",
                "redirect_uri": "http://localhost:8000/auth/oauth/github/callback",
            },
        },
    },
)
```

## Security defaults

ironauth ships with secure defaults out of the box.

| Setting                | Default | Why                                    |
| ---------------------- | ------- | -------------------------------------- |
| Password hashing       | Argon2  | Winner of Password Hashing Competition |
| Cookie `HttpOnly`      | `True`  | Prevents XSS token theft               |
| Cookie `Secure`        | `True`  | HTTPS only                             |
| Cookie `SameSite`      | `lax`   | CSRF protection                        |
| Access token expiry    | 15 min  | Limits exposure window                 |
| Refresh token rotation | Always  | Detects token theft                    |

!!! warning "Secret key"
Always use a long random secret key in production.

```bash
    python -c "import secrets; print(secrets.token_urlsafe(64))"
```
