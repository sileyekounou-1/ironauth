# IronAuth

Bibliothèque d'authentification agnostique du framework pour Python. Cœur sécurisé (Argon2id, JWT en cookies httpOnly, rotation des refresh tokens, CSRF double-submit, blacklist de révocation) et adaptateur FastAPI prêt à monter.

## Installation

```bash
uv add ironauth          # ou : pip install ironauth
uv add "ironauth[redis]" # stores distribués (blacklist + rate-limit)
```

## Démarrage rapide (FastAPI)

```python
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from ironauth import IronAuth, sqlalchemy_adapter, User

db = sqlalchemy_adapter("sqlite+aiosqlite:///./app.db")

auth = IronAuth(
    database=db,
    config={
        # >= 32 caractères ; à charger depuis l'environnement en production
        "secret_key": "change-me-super-long-secret-key-32-chars-min",
        # En développement local (HTTP), passer secure à False pour que les cookies partent
        "cookie": {"secure": False},
    },
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await auth.init()  # crée les tables (dev). En prod : migrations Alembic.
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(auth.router)  # expose /auth/*


@app.get("/profile")
async def profile(user: User = Depends(auth.current_user())):
    return {"email": user.email}
```

## Flux côté client

Toutes les mutations exigent un token CSRF : appeler `GET /auth/csrf-token`, réémettre
la valeur reçue dans l'en-tête `X-CSRF-Token` (le cookie brut est posé automatiquement).

```
POST /auth/register           {email, password}
POST /auth/login              {email, password}        -> cookies de session
POST /auth/logout
POST /auth/refresh                                     -> rotation des tokens
GET  /auth/me                                          -> utilisateur courant
POST /auth/change-password    {current_password, new_password}
```

Le mot de passe doit faire au moins 12 caractères avec majuscule, minuscule, chiffre et caractère spécial.

## Plugins (optionnels)

```python
from ironauth import (
    IronAuth, sqlalchemy_adapter,
    oauth, two_factor, rate_limit, smtp, resend,
)

auth = IronAuth(
    database=sqlalchemy_adapter("postgresql+asyncpg://.../app"),
    config={
        "secret_key": "...",
        "require_verified_email": True,       # bloque le login tant que non vérifié
        "trust_proxy": True,                  # lit X-Forwarded-For derrière un proxy fiable
        "oauth": {
            "google": {
                "client_id": "...",
                "client_secret": "...",
                "redirect_uri": "https://app.example.com/auth/oauth/google/callback",
            },
        },
        "email": {"base_url": "https://app.example.com", "app_name": "MonApp"},
    },
    plugins=[
        oauth(["google"]),
        two_factor(),
        rate_limit(max_attempts=5, window=300, block_duration=900),
        resend(api_key="re_..."),             # ou smtp(host=..., port=587, ...)
    ],
)
```

Routes ajoutées selon les plugins actifs :

```
GET  /auth/oauth/{provider}                 (google | github)
GET  /auth/oauth/{provider}/callback
POST /auth/2fa/enable                        -> secret + QR code base64
POST /auth/2fa/confirm      {code}
POST /auth/2fa/validate     {two_factor_token, code}   # après un login avec 2FA
POST /auth/2fa/disable      {code}
POST /auth/send-verification-email
POST /auth/verify-email     {token}
POST /auth/forgot-password  {email}
POST /auth/reset-password   {token, password}
```

Avec la 2FA activée, `POST /auth/login` renvoie `{two_factor_required: true, two_factor_token}`
au lieu d'une session : échanger ce token (usage unique, 5 min) sur `/auth/2fa/validate`
avec le code TOTP pour obtenir la session.

## Sécurité

Mots de passe hashés en Argon2id (rehash transparent). Tokens de vérification et de reset
stockés hashés en SHA-256 avec expiration. Un changement ou une réinitialisation de mot de
passe invalide toutes les sessions existantes. `logout` révoque immédiatement les tokens
access et refresh via la blacklist.

En production : servir en HTTPS (cookies `secure` par défaut), charger `secret_key` depuis
l'environnement, utiliser Redis (`redis_url`) pour la blacklist et le rate-limit sur
plusieurs workers, et gérer le schéma avec Alembic plutôt que `auth.init()`.

## Développement

```bash
uv sync
uv run pytest
```

## Licence

MIT
