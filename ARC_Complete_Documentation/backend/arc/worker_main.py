import logging
import sys

from arc.database import engine, Base
from arc.messaging.consumer import consume_events
from arc.workers.raw_event_worker import process_raw_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables verified in worker.")
    except Exception as e:
        logger.error(f"Could not initialize database tables: {e}")
        sys.exit(1)

def main():
    logger.info("Starting ARC Worker Process...")
    init_db()
    
    # In a real environment, you might use threading/multiprocessing or asyncio 
    # to run multiple consumers for different topics.
    # For now, we block and consume arc.raw.events
    
    topic = "arc.raw.events"
    group_id = "arc-raw-event-saver"
    
    logger.info(f"Subscribing to {topic}...")
    consume_events(topic=topic, group_id=group_id, handler_callback=process_raw_event)

if __name__ == "__main__":
    main()
