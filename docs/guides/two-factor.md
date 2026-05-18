# Two-Factor Authentication (TOTP)

ironauth supports TOTP-based 2FA compatible with Google Authenticator, Authy, and any TOTP app.

## Setup

```python
from ironauth.plugins.two_factor import two_factor

auth = ironauth(
    ...
    plugins=[two_factor()],
)
```

## Flow

### Enable 2FA

```python
# 1. Request setup — returns QR code + secret
POST /auth/2fa/enable
# Response:
{
    "secret": "BASE32SECRET",
    "qr_code": "<base64 PNG>"
}
```

Display the QR code to your user so they can scan it with their TOTP app.

```python
# 2. Confirm with first code
POST /auth/2fa/confirm
{ "code": "123456" }
```

### Validate at login

```python
POST /auth/2fa/validate
{
    "user_id": "...",
    "code": "123456"
}
```

### Disable 2FA

```python
POST /auth/2fa/disable
{ "code": "123456" }
```

!!! info "TOTP window"
ironauth accepts codes valid within a 30-second window before and after the current time to account for clock drift.
