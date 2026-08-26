import sys
import os
backend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'backend')
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
from fastapi import FastAPI
from app.main import app as backend_app
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount('/api', backend_app)
