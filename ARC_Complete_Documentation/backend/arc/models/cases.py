from sqlalchemy import Column, String, DateTime, Enum, ForeignKey
from sqlalchemy import Uuid as UUID
from datetime import datetime
import uuid
import enum

from arc.database import Base

class CaseStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    PENDING_RESPONSE = "PENDING_RESPONSE"
    CLOSED = "CLOSED"

class Case(Base):
    __tablename__ = "cases"
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    description = Column(String)
    status = Column(Enum(CaseStatus), default=CaseStatus.OPEN)
    
    assigned_to = Column(UUID(), ForeignKey("users.id"), nullable=True)
    created_by = Column(UUID(), ForeignKey("users.id"), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
