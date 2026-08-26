from pydantic import BaseModel
from typing import List, Optional

class RDAPEntity(BaseModel):
    name: Optional[str] = None
    handle: Optional[str] = None

class RDAPIntelligenceResult(BaseModel):
    collector: str = "rdap"
    domain: str
    status: str
    queried_at: str
    source: Optional[str] = None
    handle: Optional[str] = None
    registrar: Optional[RDAPEntity] = None
    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None
    last_changed_date: Optional[str] = None
    nameservers: List[str] = []
    domain_statuses: List[str] = []
    organization: Optional[RDAPEntity] = None
