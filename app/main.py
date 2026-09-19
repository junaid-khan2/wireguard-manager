from pathlib import Path

from fastapi import FastAPI

from app.config import settings
from app.database import Base, engine
from app.routers.clients import router as clients_router


Path("data").mkdir(exist_ok=True)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
)

app.include_router(clients_router)


@app.get("/")
def root():
    return {
        "application": settings.app_name,
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }