import time
from threading import Lock
from typing import Optional


class InMemoryBlacklist:
    def __init__(self):
        self._store: dict[str, float] = {}
        self._lock = Lock()

    def add(self, token: str, expires_at: float) -> None:
        with self._lock:
            self._store[token] = expires_at

    def is_blacklisted(self, token: str) -> bool:
        with self._lock:
            self._purge()
            return token in self._store

    def _purge(self) -> None:
        """Nettoie les tokens expirés pour éviter les fuites mémoire."""
        now = time.time()
        self._store = {token: exp for token, exp in self._store.items() if exp > now}


class RedisBlacklist:
    def __init__(self, redis_url: str):
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(redis_url)
        except ImportError:
            raise ImportError("Installe redis : uv add redis")

    async def add(self, token: str, expires_at: float) -> None:
        ttl = int(expires_at - time.time())
        if ttl > 0:
            await self._redis.setex(f"ironauth:blacklist:{token}", ttl, "1")

    async def is_blacklisted(self, token: str) -> bool:
        result = await self._redis.exists(f"ironauth:blacklist:{token}")
        return bool(result)


class TokenBlacklist:
    def __init__(self, redis_url: Optional[str] = None):
        self._store = RedisBlacklist(redis_url) if redis_url else InMemoryBlacklist()

    async def add(self, token: str, expires_at: float) -> None:
        if isinstance(self._store, InMemoryBlacklist):
            self._store.add(token, expires_at)
        else:
            await self._store.add(token, expires_at)

    async def is_blacklisted(self, token: str) -> bool:
        if isinstance(self._store, InMemoryBlacklist):
            return self._store.is_blacklisted(token)
        return await self._store.is_blacklisted(token)
