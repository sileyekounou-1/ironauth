# Getting Started

## Installation

```bash
pip install ironauth

# With uv
uv add ironauth
```

## Minimal setup

### 1. Create your ironauth instance

```python
# auth.py
from ironauth import ironauth
from ironauth.adapters.database.sqlalchemy import sqlalchemy_adapter
from ironauth.adapters.frameworks.fastapi import fastapi_adapter

auth = ironauth(
    database=sqlalchemy_adapter("sqlite+aiosqlite:///./db.sqlite3"),
    adapter=fastapi_adapter(),
    config={"secret_key": "change-me-in-production"},
)
```

### 2. Mount on your FastAPI app

```python
# main.py
from fastapi import FastAPI, Depends
from auth import auth

app = FastAPI()

@app.on_event("startup")
async def startup():
    await auth.init()  # Creates tables automatically

app.include_router(auth.router)
```

### 3. Protect a route

```python
@app.get("/profile")
async def profile(user=Depends(auth.current_user())):
    return {"email": user.email}
```

That's it. You now have the following routes available:

| Method | Route            | Description                    |
| ------ | ---------------- | ------------------------------ |
| `POST` | `/auth/register` | Register with email + password |
| `POST` | `/auth/login`    | Login                          |
| `POST` | `/auth/logout`   | Logout                         |
| `POST` | `/auth/refresh`  | Refresh session                |

## Optional routes

```python
# Unprotected route (user may or may not be logged in)
@app.get("/public")
async def public(user=Depends(auth.current_user(required=False))):
    if user:
        return {"message": f"Hello {user.email}"}
    return {"message": "Hello stranger"}
```
