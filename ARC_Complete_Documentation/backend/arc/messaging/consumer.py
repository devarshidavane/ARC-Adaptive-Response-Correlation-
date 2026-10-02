import os
import json
import logging
import redis
import time
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

try:
    redis_client = redis.from_url(
        REDIS_URL, 
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5,
        socket_keepalive=True,
        retry_on_timeout=True
    )
except Exception as e:
    logger.error(f"Failed to initialize Redis consumer: {e}")
    redis_client = None

def consume_events(topic: str, group_id: str, handler_callback):
    """
    Consume events from a Redis stream (topic) and process them using the provided callback.
    """
    if not redis_client:
        logger.error("Redis client not initialized. Cannot consume.")
        return
        
    consumer_name = f"consumer-{os.getpid()}"
    
    # Ensure consumer group exists
    try:
        redis_client.xgroup_create(topic, group_id, id='0', mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            logger.error(f"Error creating consumer group: {e}")
            return
            
    logger.info(f"Started consuming stream '{topic}' with group '{group_id}'")

    try:
        while True:
            try:
                # Use non-blocking read to avoid Upstash serverless TCP drop issues
                messages = redis_client.xreadgroup(group_id, consumer_name, {topic: '>'}, count=1)
                
                if not messages:
                    time.sleep(1.0)
                    continue
                    
                for stream, msgs in messages:
                    for msg_id, msg_data in msgs:
                        try:
                            payload = json.loads(msg_data['payload'])
                            success = handler_callback(payload)
                            
                            if success:
                                redis_client.xack(topic, group_id, msg_id)
                            else:
                                logger.error(f"Handler returned failure for msg {msg_id}. Not ACKing.")
                                
                        except json.JSONDecodeError:
                            logger.error("Failed to decode message as JSON")
                            redis_client.xack(topic, group_id, msg_id)
                        except Exception as e:
                            logger.error(f"Error processing message: {e}")
            except redis.exceptions.ConnectionError as e:
                logger.error(f"Redis connection error, retrying... {e}")
                time.sleep(2.0)
            except redis.exceptions.TimeoutError:
                logger.debug("Redis socket timeout. Re-polling...")
                time.sleep(1.0)
                        
    except KeyboardInterrupt:
        logger.info("Consumption interrupted by user.")

