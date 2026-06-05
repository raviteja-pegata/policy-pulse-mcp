"""Dependency-free TTL cache decorator for async methods."""
import functools
import time
from typing import Any, Callable


def ttl_cache(ttl_seconds: int = 300) -> Callable:
    def decorator(func: Callable) -> Callable:
        _cache: dict[tuple, tuple[Any, float]] = {}

        @functools.wraps(func)
        async def wrapper(obj: Any, *args: Any, **kwargs: Any) -> Any:
            key = (id(obj), args, tuple(sorted(kwargs.items())))
            if key in _cache:
                value, expiry = _cache[key]
                if time.monotonic() < expiry:
                    return value
            result = await func(obj, *args, **kwargs)
            _cache[key] = (result, time.monotonic() + ttl_seconds)
            return result

        wrapper._cache = _cache  # type: ignore[attr-defined]
        return wrapper

    return decorator
