from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.scans import router as scans_router

api_v1_router = APIRouter()
api_v1_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_v1_router.include_router(scans_router, prefix="/scans", tags=["Scans"])
