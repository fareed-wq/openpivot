from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any

class RedirectRecord(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    status_code: int
    from_url: str = Field(alias="from")
    to_url: str = Field(alias="to")

class HTTPSContext(BaseModel):
    reachable: bool
    verified: bool

class HTTPMetadataResult(BaseModel):
    collector: str = "http_metadata"
    domain: str
    status: str
    queried_at: str
    initial_url: Optional[str] = None
    final_url: Optional[str] = None
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    peer_ip: Optional[str] = None
    status_code: Optional[int] = None
    https: Optional[HTTPSContext] = None
    redirects: List[RedirectRecord] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    title: Optional[str] = None
    web_footprint: Optional[Dict[str, Any]] = None
