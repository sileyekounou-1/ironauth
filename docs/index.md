# ironauth

**ironauth** is a framework-agnostic authentication library for Python — simple to use, secure by default, and extensible via plugins.

## Why ironauth?

The Python ecosystem has authentication solutions, but none that feel like a single cohesive tool across frameworks. ironauth changes that.

- **Framework-agnostic** — FastAPI today, Django and Flask coming soon
- **Secure by default** — Argon2 hashing, HTTP-only cookies, JWT rotation
- **Plugin system** — OAuth, 2FA, and more
- **Fully async** — built for modern Python

## Quick example

```python
from ironauth import ironauth
from ironauth.adapters.database import sqlalchemy_adapter
from ironauth.adapters.frameworks import fastapi_adapter
from ironauth.plugins import oauth, two_factor

auth = ironauth(
    database=sqlalchemy_adapter("postgresql+asyncpg://user:pass@localhost/db"),
    adapter=fastapi_adapter(),
    plugins=[
        oauth(providers=["google", "github"]),
        two_factor(),
    ],
    config={"secret_key": "your-secret-key"},
)

app.include_router(auth.router)
```

## Installation

```bash
pip install ironauth
```

[Get started →](getting-started.md)
