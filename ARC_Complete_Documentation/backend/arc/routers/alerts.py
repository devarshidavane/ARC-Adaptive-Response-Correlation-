from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from arc.database import get_db
from arc.models.alerts import Alert

router = APIRouter(prefix="/api/v1", tags=["alerts"])

@router.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    # In the future, add pagination, filtering, and authorization here
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(100).all()
    return alerts
