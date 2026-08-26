from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict

class DNSRecordResult(BaseModel):
    status: str
    values: List[Any] = Field(default_factory=list)
    error: Optional[str] = None

class DNSIntelligenceResult(BaseModel):
    collector: str = "dns"
    domain: str
    status: str
    queried_at: str
    records: Dict[str, DNSRecordResult]
