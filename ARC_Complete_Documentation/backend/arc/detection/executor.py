import logging

logger = logging.getLogger(__name__)

def evaluate_condition(event: dict, condition: dict) -> bool:
    field = condition.get("field")
    operator = condition.get("operator")
    value = condition.get("value")
    
    event_val = event.get(field)
    if event_val is None:
        return False
        
    if operator == "==":
        return event_val == value
    elif operator == "!=":
        return event_val != value
    elif operator == "in":
        return event_val in value
    elif operator == "contains":
        return value in event_val
    return False

def evaluate_rule(event: dict, rule_logic: list) -> bool:
    """Evaluate an event against a rule's logic conditions (AND logic)."""
    if not rule_logic:
        return False
    for cond in rule_logic:
        if not evaluate_condition(event, cond):
            return False
    return True
