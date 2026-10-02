from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid

class IncomingEventPayload(BaseModel):
    """Schema for raw events arriving from collectors."""
    source: str = Field(..., description="The source of the event, e.g., 'windows', 'linux', 'network'")
    payload: Dict[str, Any] = Field(..., description="The raw event data in JSON format")

class NormalizedEventSchema(BaseModel):
    """Schema representing a normalized event in ARC."""
    event_id: uuid.UUID
    timestamp: datetime
    source: str
    host: Optional[str] = None
    username: Optional[str] = None
    src_ip: Optional[str] = None
    event_type: str
    action: Optional[str] = None
    status: Optional[str] = None
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    raw_event: Dict[str, Any]
    tags: List[str] = []
