import logging
from sqlalchemy.orm import Session
from datetime import datetime

from arc.database import SessionLocal
from arc.models.events import RawEvent

logger = logging.getLogger(__name__)

def process_raw_event(payload: dict) -> bool:
    """
    Handler for 'arc.raw.events'.
    Persists the incoming raw event to the PostgreSQL database.
    """
    # Extract metadata we added during ingestion
    source = payload.get("source", "unknown")
    
    # We might have _received_at from ingestion API
    received_at_str = payload.get("_received_at")
    if received_at_str:
        try:
            received_at = datetime.fromisoformat(received_at_str)
        except ValueError:
            received_at = datetime.utcnow()
    else:
        received_at = datetime.utcnow()

    db: Session = SessionLocal()
    try:
        raw_event = RawEvent(
            source=source,
            received_at=received_at,
            payload=payload
        )
        db.add(raw_event)
        db.commit()
        logger.info(f"Persisted RawEvent from source '{source}'")
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist RawEvent to DB: {e}")
        return False
    finally:
        db.close()
