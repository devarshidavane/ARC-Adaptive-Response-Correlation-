from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean
from sqlalchemy import Uuid as UUID
from datetime import datetime
import uuid

from arc.database import Base

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    severity = Column(String)
    logic = Column(JSON)
    is_active = Column(Boolean, default=True)
    version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
