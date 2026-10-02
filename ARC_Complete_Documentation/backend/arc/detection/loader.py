import json
import logging
from sqlalchemy.orm import Session
from arc.models.rules import DetectionRule
from arc.database import SessionLocal

logger = logging.getLogger(__name__)

def load_initial_rules():
    db: Session = SessionLocal()
    try:
        if db.query(DetectionRule).count() == 0:
            logger.info("Loading initial detection rules...")
            rule1 = DetectionRule(
                name="Repeated Auth Failure",
                description="Detects repeated authentication failures",
                severity="High",
                logic=[{"field": "event_type", "operator": "==", "value": "auth_failed"}]
            )
            db.add(rule1)
            db.commit()
            logger.info("Initial rules loaded.")
    except Exception as e:
        logger.error(f"Failed to load initial rules: {e}")
    finally:
        db.close()
