import logging
from arc.messaging.consumer import consume_events
from arc.database import SessionLocal
from arc.models.alerts import Alert, AlertSeverity, AlertStatus
import uuid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def handle_event(payload: dict) -> bool:
    """Process an incoming event and generate an alert if suspicious."""
    logger.info(f"Processing event: {payload.get('event_type')}")
    
    # Very simple mock detection logic for the demonstration
    is_suspicious = False
    title = "Suspicious Activity"
    severity = AlertSeverity.LOW
    
    if payload.get("event_type") == "failed_login":
        is_suspicious = True
        title = "Failed Login Detected"
        severity = AlertSeverity.MEDIUM
    elif "powershell" in str(payload.get("process_name", "")).lower():
        is_suspicious = True
        title = "Suspicious PowerShell Execution"
        severity = AlertSeverity.HIGH
    elif payload.get("event_type") == "brute_force":
        is_suspicious = True
        title = "Brute Force Attack Detected"
        severity = AlertSeverity.CRITICAL

    if is_suspicious:
        db = SessionLocal()
        try:
            new_alert = Alert(
                title=title,
                description=f"Generated from event: {payload}",
                severity=severity,
                status=AlertStatus.NEW,
                risk_score=75.0,
                host=payload.get("host", "Unknown"),
                user=payload.get("user", "Unknown"),
                source_ip=payload.get("source_ip", "Unknown"),
            )
            db.add(new_alert)
            db.commit()
            logger.info(f"Generated alert: {title}")
        except Exception as e:
            logger.error(f"Failed to insert alert: {e}")
            db.rollback()
            return False
        finally:
            db.close()
            
    return True

if __name__ == "__main__":
    logger.info("Starting Detection Worker...")
    consume_events("arc.events.validated", "detection_group", handle_event)
