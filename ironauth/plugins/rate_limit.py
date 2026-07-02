import time
from collections import defaultdict
from threading import Lock
from typing import Optional

from fastapi import HTTPException, Request


class InMemoryStore:
    def __init__(self):
        self._store: dict = defaultdict(list)
        self._blocks: dict[str, float] = {}  # key -> blocked_until (epoch)
        self._lock = Lock()

    def get_attempts(self, key: str, window: int) -> int:
        now = time.time()
        with self._lock:
            # Nettoie les tentatives hors fenêtre
            self._store[key] = [t for t in self._store[key] if now - t < window]
            return len(self._store[key])

    def add_attempt(self, key: str) -> None:
        with self._lock:
            self._store[key].append(time.time())

    def reset(self, key: str) -> None:
        with self._lock:
            self._store[key] = []
            self._blocks.pop(key, None)

    def get_block(self, key: str) -> float:
        with self._lock:
            until = self._blocks.get(key, 0.0)
            if until and until <= time.time():
                del self._blocks[key]
                return 0.0
            return until

    def set_block(self, key: str, until: float) -> None:
        with self._lock:
            self._blocks[key] = until


class RedisStore:
    def __init__(self, redis_url: str):
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(redis_url)
        except ImportError:
            raise ImportError("Installe redis : uv add redis")

    async def get_attempts(self, key: str, window: int) -> int:
        now = time.time()
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zcard(key)
        _, count = await pipe.execute()
        return count

    async def add_attempt(self, key: str) -> None:
        now = time.time()
        pipe = self._redis.pipeline()
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, 3600)
        await pipe.execute()

    async def reset(self, key: str) -> None:
        await self._redis.delete(key, f"{key}:blocked")

    async def get_block(self, key: str) -> float:
        val = await self._redis.get(f"{key}:blocked")
        return float(val) if val else 0.0

    async def set_block(self, key: str, until: float) -> None:
        ttl = max(1, int(until - time.time()))
        await self._redis.setex(f"{key}:blocked", ttl, str(until))


class RateLimiter:
    def __init__(
        self,
        max_attempts: int = 5,
        window: int = 300,  # 5 minutes
        block_duration: int = 900,  # 15 minutes
        redis_url: Optional[str] = None,
        trust_proxy: bool = False,
    ):
        self.max_attempts = max_attempts
        self.window = window
        self.block_duration = block_duration
        # Positionné par l'adaptateur depuis la config si non fourni explicitement
        self.trust_proxy = trust_proxy
        self._store = RedisStore(redis_url) if redis_url else InMemoryStore()

    def _client_ip(self, request: Request) -> str:
        if self.trust_proxy:
            # Premier IP de la chaîne X-Forwarded-For = client d'origine.
            # N'activer que derrière un proxy fiable, sinon l'en-tête est spoofable.
            fwd = request.headers.get("x-forwarded-for")
            if fwd:
                return fwd.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _get_key(self, request: Request, route: str) -> str:
        return f"ironauth:ratelimit:{route}:{self._client_ip(request)}"

    async def _get_attempts(self, key: str) -> int:
        if isinstance(self._store, InMemoryStore):
            return self._store.get_attempts(key, self.window)
        return await self._store.get_attempts(key, self.window)

    async def _add_attempt(self, key: str) -> None:
        if isinstance(self._store, InMemoryStore):
            self._store.add_attempt(key)
        else:
            await self._store.add_attempt(key)

    async def _reset(self, key: str) -> None:
        if isinstance(self._store, InMemoryStore):
            self._store.reset(key)
        else:
            await self._store.reset(key)

    async def _get_block(self, key: str) -> float:
        if isinstance(self._store, InMemoryStore):
            return self._store.get_block(key)
        return await self._store.get_block(key)

    async def _set_block(self, key: str, until: float) -> None:
        if isinstance(self._store, InMemoryStore):
            self._store.set_block(key, until)
        else:
            await self._store.set_block(key, until)

    def _raise(self, seconds: int) -> None:
        raise HTTPException(
            status_code=429,
            detail=f"Trop de tentatives. Réessaie dans {max(1, seconds // 60)} minutes.",
            headers={"Retry-After": str(seconds)},
        )

    async def check(self, request: Request, route: str) -> None:
        key = self._get_key(request, route)
        now = time.time()
        # Verrou réel : reste bloqué block_duration même si la fenêtre expire
        blocked_until = await self._get_block(key)
        if blocked_until and now < blocked_until:
            self._raise(int(blocked_until - now))
        if await self._get_attempts(key) >= self.max_attempts:
            await self._set_block(key, now + self.block_duration)
            self._raise(self.block_duration)

    async def record_failure(self, request: Request, route: str) -> None:
        key = self._get_key(request, route)
        await self._add_attempt(key)
        if await self._get_attempts(key) >= self.max_attempts:
            await self._set_block(key, time.time() + self.block_duration)

    async def record_success(self, request: Request, route: str) -> None:
        key = self._get_key(request, route)
        await self._reset(key)


def rate_limit(
    max_attempts: int = 5,
    window: int = 300,
    block_duration: int = 900,
    redis_url: Optional[str] = None,
    trust_proxy: bool = False,
) -> RateLimiter:
    return RateLimiter(max_attempts, window, block_duration, redis_url, trust_proxy)
