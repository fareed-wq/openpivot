from fastapi import FastAPI
from app.api import investigation

app = FastAPI(
    title="OpenPivot API",
    description="Public infrastructure intelligence API for OpenPivot.",
    version="0.1.0",
)

app.include_router(investigation.router)

@app.get("/")
async def root():
    return {
        "name": "OpenPivot API",
        "status": "running"
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }
