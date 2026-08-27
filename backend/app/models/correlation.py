from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class Entity(BaseModel):
    id: str
    type: str
    value: str
    attributes: Dict[str, Any] = Field(default_factory=dict)

class Relationship(BaseModel):
    source: str
    target: str
    type: str
    source_collectors: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

class CorrelationResult(BaseModel):
    entities: List[Entity] = Field(default_factory=list)
    relationships: List[Relationship] = Field(default_factory=list)
