from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy import Uuid as UUID
from datetime import datetime
import uuid

from arc.database import Base

class RawEvent(Base):
    __tablename__ = "raw_events"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    received_at = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True)
    payload = Column(JSON, nullable=False)

class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    raw_event_id = Column(UUID(), index=True) # Reference to RawEvent
    timestamp = Column(DateTime, index=True)
    source = Column(String, index=True)
    host = Column(String, index=True)
    username = Column(String, index=True)
    src_ip = Column(String, index=True)
    event_type = Column(String, index=True)
    action = Column(String, index=True)
    status = Column(String, index=True)
    process_name = Column(String)
    parent_process = Column(String)
    tags = Column(JSON)
