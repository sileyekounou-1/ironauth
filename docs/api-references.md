# API Reference

## ironauth

```python
ironauth(
    database: SQLAlchemyAdapter,
    config: dict,
    plugins: list = [],
    adapter: dict | None = None,
)
```

| Parameter  | Type                | Description                                                |
| ---------- | ------------------- | ---------------------------------------------------------- |
| `database` | `SQLAlchemyAdapter` | Database adapter                                           |
| `config`   | `dict`              | Configuration dict (see [Configuration](configuration.md)) |
| `plugins`  | `list`              | List of plugins                                            |
| `adapter`  | `dict`              | Framework adapter                                          |

### Methods

| Method                             | Description                |
| ---------------------------------- | -------------------------- |
| `await auth.init()`                | Initialize database tables |
| `auth.router`                      | FastAPI router to mount    |
| `auth.current_user(required=True)` | FastAPI dependency         |

## Routes

### Email / Password

| Method | Route            | Body                | Description     |
| ------ | ---------------- | ------------------- | --------------- |
| `POST` | `/auth/register` | `{email, password}` | Register        |
| `POST` | `/auth/login`    | `{email, password}` | Login           |
| `POST` | `/auth/logout`   | —                   | Logout          |
| `POST` | `/auth/refresh`  | —                   | Refresh session |

### OAuth

| Method | Route                             | Description      |
| ------ | --------------------------------- | ---------------- |
| `GET`  | `/auth/oauth/{provider}`          | Start OAuth flow |
| `GET`  | `/auth/oauth/{provider}/callback` | OAuth callback   |

### 2FA

| Method | Route                | Body              | Description      |
| ------ | -------------------- | ----------------- | ---------------- |
| `POST` | `/auth/2fa/enable`   | —                 | Generate QR code |
| `POST` | `/auth/2fa/confirm`  | `{code}`          | Activate 2FA     |
| `POST` | `/auth/2fa/validate` | `{user_id, code}` | Validate code    |
| `POST` | `/auth/2fa/disable`  | `{code}`          | Disable 2FA      |
