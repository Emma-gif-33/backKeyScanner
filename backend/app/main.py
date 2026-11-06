from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import api_v1_router
from app.core.config import settings
from app.core.database import get_db

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="API RESTful de análisis para escáner de claves secretas y dependencias vulnerables",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration for Frontend (React + Vite)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["Health"])
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check endpoint that verifies DB connectivity."""
    try:
        result = await db.execute(text("SELECT 1"))
        db_status = "connected" if result.scalar() == 1 else "unexpected_result"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "status": "online",
        "app": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "database": db_status
    }


# Mount API V1 routes
app.include_router(api_v1_router, prefix=settings.API_V1_STR)
