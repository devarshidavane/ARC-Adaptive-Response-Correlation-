from pydantic import BaseModel
from typing import Any, List

class RuleCondition(BaseModel):
    field: str
    operator: str
    value: Any

class DetectionRuleSchema(BaseModel):
    name: str
    description: str
    severity: str
    logic: List[RuleCondition]
    is_active: bool = True
