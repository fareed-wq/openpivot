from pydantic import BaseModel, Field
from typing import List, Optional

class TLSVerification(BaseModel):
    status: str
    reason: Optional[str] = None

class TLSCertificate(BaseModel):
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    version: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    currently_valid: Optional[bool] = None
    days_until_expiry: Optional[int] = None
    sha256_fingerprint: Optional[str] = None
    san_dns: List[str] = Field(default_factory=list)
    san_ip: List[str] = Field(default_factory=list)

class TLSIntelligenceResult(BaseModel):
    collector: str = "tls"
    domain: str
    status: str
    queried_at: str
    peer_ip: Optional[str] = None
    port: int = 443
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    verification: Optional[TLSVerification] = None
    certificate: Optional[TLSCertificate] = None
