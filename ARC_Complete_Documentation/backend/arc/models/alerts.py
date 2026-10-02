from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Enum, Float
from sqlalchemy import Uuid as UUID
from datetime import datetime
import uuid
import enum

from arc.database import Base

class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AlertStatus(str, enum.Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    description = Column(String)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.LOW)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW)
    risk_score = Column(Float, default=0.0)
    
    # Source context
    source_event_id = Column(UUID(), nullable=True) # References raw_events or normalized_events
    rule_id = Column(UUID(), ForeignKey("detection_rules.id"), nullable=True)
    
    # Entities
    host = Column(String, nullable=True)
    user = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    
    # Workflow
    assigned_to = Column(UUID(), ForeignKey("users.id"), nullable=True)
    case_id = Column(UUID(), ForeignKey("cases.id"), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
