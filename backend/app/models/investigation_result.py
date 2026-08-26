from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from app.models.correlation import CorrelationResult

class TargetInfo(BaseModel):
    input: str
    normalized: str
    type: str

class InvestigationResult(BaseModel):
    investigation_id: str
    target: TargetInfo
    status: str
    started_at: str
    completed_at: str
    duration_ms: float
    collectors: Dict[str, Any] = Field(default_factory=dict)
    collector_status: Dict[str, str] = Field(default_factory=dict)
    correlation: Optional[CorrelationResult] = None
