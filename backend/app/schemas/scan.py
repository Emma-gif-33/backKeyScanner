import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict
from app.schemas.finding import DependencyFindingResponse, SecretFindingResponse


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


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class CategoryBreakdown(BaseModel):
    secrets: int = 0
    dependencies: int = 0


class ReportSummary(BaseModel):
    total_findings: int
    risk_level: str
    by_severity: SeverityBreakdown
    by_category: CategoryBreakdown
    duration_seconds: Optional[float] = None
    files_extracted: int = 0


class ScanReportResponse(BaseModel):
    scan_id: uuid.UUID
    project_name: str
    source_filename: str
    file_hash_sha256: str
    status: str
    risk_level: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    summary: ReportSummary
    secrets: List[SecretFindingResponse]
    dependencies: List[DependencyFindingResponse]
