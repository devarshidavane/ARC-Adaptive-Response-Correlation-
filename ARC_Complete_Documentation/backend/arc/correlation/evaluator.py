import logging
from typing import Optional
from arc.correlation.store import get_context, store_context

logger = logging.getLogger(__name__)

def evaluate_sequence(event: dict, correlation_rule: dict) -> Optional[dict]:
    """
    Evaluates an event against a multi-step sequence rule.
    Example rule: Event A followed by Event B within 5 mins for the same IP.
    """
    sequence_id = correlation_rule.get("id")
    seq_steps = correlation_rule.get("steps", [])
    
    # Very basic placeholder logic for tracking sequence state
    # A real engine would map event fields to sequence steps
    key = f"corr:{sequence_id}:{event.get('src_ip', 'unknown')}"
    
    current_state = get_context(key) or {"step_index": 0}
    
    # If the event matches the expected next step
    expected_step = seq_steps[current_state["step_index"]]
    if event.get("event_type") == expected_step.get("event_type"):
        current_state["step_index"] += 1
        
        if current_state["step_index"] >= len(seq_steps):
            logger.info(f"Sequence {sequence_id} completed for IP {event.get('src_ip')}")
            # Sequence complete, clear context and return match
            store_context(key, {"step_index": 0}, 1) 
            return {"matched_sequence": sequence_id, "trigger_event": event}
        else:
            store_context(key, current_state, 300) # 5 min TTL
    
    return None
