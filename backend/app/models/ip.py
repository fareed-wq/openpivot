from pydantic import BaseModel, Field
from typing import List, Optional

class IPEntity(BaseModel):
    name: Optional[str] = None
    handle: Optional[str] = None

class IPRDAPIntelligence(BaseModel):
    source: Optional[str] = None
    handle: Optional[str] = None
    name: Optional[str] = None
    start_address: Optional[str] = None
    end_address: Optional[str] = None
    ip_version: Optional[str] = None
    type: Optional[str] = None
    country: Optional[str] = None
    parent_handle: Optional[str] = None
    statuses: List[str] = Field(default_factory=list)
    network_prefixes: List[str] = Field(default_factory=list)
    registration_date: Optional[str] = None
    last_changed_date: Optional[str] = None
    organization: Optional[IPEntity] = None

class IPReverseDNS(BaseModel):
    status: str
    hostname: Optional[str] = None

class IPIntelligenceResult(BaseModel):
    collector: str = "ip"
    ip: str
    status: str
    queried_at: str
    rdap: Optional[IPRDAPIntelligence] = None
    reverse_dns: Optional[IPReverseDNS] = None
