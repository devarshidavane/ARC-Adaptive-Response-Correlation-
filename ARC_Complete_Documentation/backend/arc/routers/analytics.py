from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from arc.database import get_db
from arc.models.alerts import Alert, AlertSeverity
from arc.models.cases import Case, CaseStatus

router = APIRouter(prefix="/api/v1", tags=["analytics"])

@router.get("/analytics/overview")
def get_dashboard_metrics(db: Session = Depends(get_db)):
    # Calculate real metrics from the database
    critical_alerts = db.query(Alert).filter(Alert.severity == AlertSeverity.CRITICAL).count()
    high_alerts = db.query(Alert).filter(Alert.severity == AlertSeverity.HIGH).count()
    total_alerts = db.query(Alert).count()
    
    open_cases = db.query(Case).filter(Case.status == CaseStatus.OPEN).count()
    
    # Placeholder for events/sec which would typically be fetched from Redis or Prometheus
    events_per_sec = 0
    
    # Health check for Postgres (if we reached here, DB is up)
    system_health_pct = 100
    
    return {
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "total_alerts": total_alerts,
        "events_per_sec": events_per_sec,
        "open_cases": open_cases,
        "system_health_pct": system_health_pct
    }
