from fastapi import FastAPI
import logging

from arc.routers import ingestion
from arc.database import engine, Base

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize DB tables (for a real app, use Alembic migrations)
# Base.metadata.create_all(bind=engine) is removed in favor of Alembic migrations


app = FastAPI(
    title="ARC Platform API",
    description="Adaptive Response & Correlation System",
    version="0.1.0",
)

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
from arc.routers import alerts, analytics
app.include_router(ingestion.router)
app.include_router(alerts.router)
app.include_router(analytics.router)

@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "arc-api"}
