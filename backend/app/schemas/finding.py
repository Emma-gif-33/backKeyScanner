import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class SecretFindingResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    rule_id: str
    secret_type: str
    file_path: str
    line_number: int
    masked_snippet: str
    entropy_score: Optional[float] = None
    severity: str
    remediation_tip: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DependencyFindingResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    package_name: str
    installed_version: str
    ecosystem: str
    manifest_file: str
    osv_id: str
    severity: str
    fixed_version: Optional[str] = None
    summary: Optional[str] = None
    advisory_url: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
