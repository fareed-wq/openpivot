from fastapi import APIRouter, HTTPException
from app.models.investigation import ValidateRequest, ValidateResponse
from app.core.target_validation import validate_and_normalize_target
from app.intelligence.investigation import run_investigation

router = APIRouter()

@router.post("/validate", response_model=ValidateResponse)
async def validate_target(request: ValidateRequest):
    try:
        result = validate_and_normalize_target(request.target)
        return ValidateResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

@router.post("/investigate")
async def investigate_target(request: ValidateRequest):
    try:
        result = run_investigation(request.target)
        return result
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
