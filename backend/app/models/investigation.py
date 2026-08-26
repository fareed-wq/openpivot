from pydantic import BaseModel

class ValidateRequest(BaseModel):
    target: str

class ValidateResponse(BaseModel):
    input: str
    normalized: str
    type: str
    valid: bool
