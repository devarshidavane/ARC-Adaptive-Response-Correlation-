from sqlalchemy import Column, String, DateTime, Enum, Boolean
from sqlalchemy import Uuid as UUID
from datetime import datetime
import uuid
import enum

from arc.database import Base

class Role(str, enum.Enum):
    ANALYST = "ANALYST"
    SENIOR_ANALYST = "SENIOR_ANALYST"
    DETECTION_ENGINEER = "DETECTION_ENGINEER"
    ADMIN = "ADMIN"

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(Role), default=Role.ANALYST)
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
