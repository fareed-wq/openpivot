from pydantic import BaseModel, Field
from typing import List, Optional

class SPFIntelligence(BaseModel):
    status: str
    record: Optional[str] = None

class DMARCIntelligence(BaseModel):
    status: str
    record: Optional[str] = None

class MXRecord(BaseModel):
    priority: int
    host: str
    provider: Optional[str] = None

class MXIntelligence(BaseModel):
    status: str
    records: List[MXRecord] = Field(default_factory=list)

class EmailSecurityIntelligenceResult(BaseModel):
    collector: str = "email_security"
    domain: str
    status: str
    queried_at: str
    spf: SPFIntelligence
    dmarc: DMARCIntelligence
    mx: MXIntelligence
