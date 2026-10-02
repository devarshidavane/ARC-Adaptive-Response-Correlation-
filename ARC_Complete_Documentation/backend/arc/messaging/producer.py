import os
import json
import logging
import redis
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create a singleton producer instance
try:
    # Use decode_responses=True so we don't have to deal with bytes everywhere
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
except Exception as e:
    logger.error(f"Failed to initialize Redis producer: {e}")
    redis_client = None

def publish_event(topic: str, payload: dict):
    """Publish a validated event to the Redis Stream (acting as message bus)."""
    if not redis_client:
        logger.warning("Redis client not initialized. Skipping publish.")
        return
        
    try:
        # xadd appends the message to the stream `topic`
        msg_id = redis_client.xadd(topic, {"payload": json.dumps(payload)})
        logger.debug(f"Message delivered to stream {topic} with ID {msg_id}")
    except Exception as e:
        logger.error(f"Error publishing event to stream {topic}: {e}")

def publish_deadletter(payload: dict, error_detail: str):
    """Publish a malformed event to the dead-letter stream."""
    deadletter_payload = {
        "original_payload": payload,
        "error": error_detail
    }
    publish_event("arc.deadletter", deadletter_payload)
