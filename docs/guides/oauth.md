# OAuth

ironauth supports OAuth2 with Google and GitHub out of the box.

## Setup

### 1. Get your credentials

=== "Google" 1. Go to [Google Cloud Console](https://console.cloud.google.com) 2. Create a project → APIs & Services → Credentials 3. Create OAuth 2.0 Client ID 4. Add `http://localhost:8000/auth/oauth/google/callback` to authorized redirect URIs

=== "GitHub" 1. Go to GitHub → Settings → Developer settings → OAuth Apps 2. Create a new OAuth App 3. Set callback URL to `http://localhost:8000/auth/oauth/github/callback`

### 2. Configure ironauth

```python
from ironauth.plugins.oauth import oauth

auth = ironauth(
    ...
    plugins=[oauth(providers=["google", "github"])],
    config={
        "secret_key": "...",
        "oauth": {
            "google": {
                "client_id": "YOUR_CLIENT_ID",
                "client_secret": "YOUR_CLIENT_SECRET",
                "redirect_uri": "http://localhost:8000/auth/oauth/google/callback",
            },
        },
    },
)
```

### 3. Redirect your users

```python
# Frontend: redirect to this URL to start OAuth flow
GET /auth/oauth/google
GET /auth/oauth/github
```

ironauth handles the callback automatically and sets session cookies.

## Account linking

If a user signs in with OAuth using an email that already exists in your database, ironauth automatically links the OAuth account to the existing user — no duplicate accounts.
