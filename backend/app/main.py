from fastapi import FastAPI

app = FastAPI(
    title="OpenPivot API",
    description="Public infrastructure intelligence API for OpenPivot.",
    version="0.1.0",
)

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
