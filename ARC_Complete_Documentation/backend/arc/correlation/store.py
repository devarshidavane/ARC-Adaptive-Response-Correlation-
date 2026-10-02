import redis
import os
import json

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.from_url(REDIS_URL)

def store_context(key: str, value: dict, expire_seconds: int = 3600):
    """Store context for correlation sequences."""
    redis_client.setex(key, expire_seconds, json.dumps(value))

def get_context(key: str) -> dict:
    """Retrieve context."""
    val = redis_client.get(key)
    return json.loads(val) if val else None
