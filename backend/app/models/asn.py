from pydantic import BaseModel, Field
from typing import List, Optional

class ASNEntity(BaseModel):
    name: Optional[str] = None
    handle: Optional[str] = None

class ASNOrigin(BaseModel):
    ip: str
    asns: List[int] = Field(default_factory=list)
    prefix: Optional[str] = None
    country: Optional[str] = None
    registry: Optional[str] = None
    allocated: Optional[str] = None

class ASNRDAPIntelligence(BaseModel):
    number: Optional[int] = None
    handle: Optional[str] = None
    name: Optional[str] = None
    start_autnum: Optional[int] = None
    end_autnum: Optional[int] = None
    country: Optional[str] = None
    type: Optional[str] = None
    statuses: List[str] = Field(default_factory=list)
    registration_date: Optional[str] = None
    last_changed_date: Optional[str] = None
    organization: Optional[ASNEntity] = None
    source: Optional[str] = None

class ASNIntelligenceResult(BaseModel):
    collector: str = "asn"
    status: str
    queried_at: str
    origin: Optional[ASNOrigin] = None
    asn: Optional[ASNRDAPIntelligence] = None
