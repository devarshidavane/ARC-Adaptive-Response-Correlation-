from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import ValidationError
import logging
import uuid
from datetime import datetime

from arc.schemas.events import IncomingEventPayload
from arc.auth.dependencies import get_api_key
from arc.messaging.producer import publish_event, publish_deadletter

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/api/v1/events",
    tags=["events"],
    dependencies=[Depends(get_api_key)]
)

@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(request: Request):
    """
    Ingest a raw event from a collector.
    We parse the JSON manually first to catch malformed structure and route it to dead-letter.
    """
    try:
        body = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse JSON body: {e}")
        # Could not even parse JSON, minimal deadletter
        publish_deadletter({"raw_body": "unparseable"}, "JSON decode error")
        raise HTTPException(status_code=400, detail="Invalid JSON format")

    try:
        event = IncomingEventPayload(**body)
        
        # Add metadata before pushing to bus
        enriched_payload = event.model_dump()
        enriched_payload["_ingestion_id"] = str(uuid.uuid4())
        enriched_payload["_received_at"] = datetime.utcnow().isoformat()
        
        # Push to Kafka raw events topic
        publish_event("arc.raw.events", enriched_payload)
        
        return {"status": "accepted", "ingestion_id": enriched_payload["_ingestion_id"]}
        
    except ValidationError as ve:
        logger.warning(f"Schema validation failed for event: {ve}")
        publish_deadletter(body, str(ve))
        raise HTTPException(status_code=422, detail="Event schema validation failed")
