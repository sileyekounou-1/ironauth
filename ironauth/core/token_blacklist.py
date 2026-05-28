import asyncio
import heapq
import time
from typing import Optional


class InMemoryBlacklist:
    """
    Blacklist in-memory async-safe.
    - asyncio.Lock au lieu de threading.Lock (compatible event loop).
    - Heap min pour la purge O(log n) au lieu de reconstruire tout le dict.
    """

    def __init__(self):
        self._store: dict[str, float] = {}
        self._heap: list[tuple[float, str]] = []  # (expires_at, token)
        self._lock = asyncio.Lock()

    async def add(self, token: str, expires_at: float) -> None:
        async with self._lock:
            self._store[token] = expires_at
            heapq.heappush(self._heap, (expires_at, token))

    async def is_blacklisted(self, token: str) -> bool:
        async with self._lock:
            self._purge()
            return token in self._store

    def _purge(self) -> None:
        """Retire les tokens expires via le heap -- O(k log n) ou k = expires."""
        now = time.time()
        while self._heap and self._heap[0][0] <= now:
            _, token = heapq.heappop(self._heap)
            self._store.pop(token, None)


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
        await self._store.add(token, expires_at)

    async def is_blacklisted(self, token: str) -> bool:
        return await self._store.is_blacklisted(token)
