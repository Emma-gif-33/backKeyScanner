import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict


class ScanBase(BaseModel):
    project_name: str


class ScanCreate(ScanBase):
    pass


class ScanResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    project_name: str
    source_filename: str
    file_hash_sha256: str
    status: str
    total_secrets: int
    total_vulnerabilities: int
    risk_level: str
    summary_metrics: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanListResponse(BaseModel):
    total: int
    scans: List[ScanResponse]
