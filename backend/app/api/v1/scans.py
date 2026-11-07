import os
import uuid
from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.finding import SecretFinding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import SecretFindingResponse
from app.schemas.scan import ScanListResponse, ScanResponse
from app.services.ingestion import (
    cleanup_directory,
    compute_sha256,
    extract_zip_safely,
    validate_and_inspect_zip,
)
from app.services.secret_scanner import scan_directory_for_secrets

router = APIRouter()

TEMP_SCANS_BASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "temp_scans"
)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def calculate_risk_level(findings_severities: List[str]) -> str:
    """Determine highest risk level from a list of finding severities."""
    highest_score = 0
    highest_severity = "NONE"
    for sev in findings_severities:
        score = SEVERITY_ORDER.get(sev.upper(), 0)
        if score > highest_score:
            highest_score = score
            highest_severity = sev.upper()
    return highest_severity


@router.post(
    "/upload",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest a zip archive for auditing"
)
async def upload_scan_archive(
    file: Annotated[UploadFile, File(description="Zip archive containing project source code")],
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    project_name: Annotated[Optional[str], Form(description="Custom project name")] = None,
):
    """Upload a project in .zip format, perform security validation and register in queue."""
    filename = file.filename or "project.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a .zip extension."
        )

    content = await file.read()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded archive is empty."
        )

    # 1. Validate archive integrity and security limits
    uncompressed_bytes = validate_and_inspect_zip(content)
    file_hash = compute_sha256(content)

    resolved_project_name = project_name.strip() if project_name and project_name.strip() else os.path.splitext(filename)[0]

    # 2. Allocate isolated temporary workspace for this scan
    scan_id = uuid.uuid4()
    scan_workspace = os.path.join(TEMP_SCANS_BASE_DIR, str(scan_id), "extracted")

    try:
        extracted_files = extract_zip_safely(content, scan_workspace)
    except Exception as e:
        cleanup_directory(os.path.join(TEMP_SCANS_BASE_DIR, str(scan_id)))
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to safely extract archive: {str(e)}"
        )

    # 3. Create persistent record in PostgreSQL
    new_scan = Scan(
        id=scan_id,
        user_id=current_user.id,
        project_name=resolved_project_name,
        source_filename=filename,
        file_hash_sha256=file_hash,
        status="QUEUED",
        total_secrets=0,
        total_vulnerabilities=0,
        risk_level="NONE",
        summary_metrics={
            "files_extracted": len(extracted_files),
            "uncompressed_bytes": uncompressed_bytes,
        }
    )

    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    return new_scan


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List all scans belonging to the current user"
)
async def list_user_scans(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Retrieve audit history for the authenticated user ordered by creation date."""
    query = select(Scan).where(Scan.user_id == current_user.id).order_by(Scan.created_at.desc())
    result = await db.execute(query)
    scans = list(result.scalars().all())
    return ScanListResponse(total=len(scans), scans=scans)


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get status and details of a specific scan"
)
async def get_scan_detail(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Retrieve metadata and progress of an individual scan."""
    query = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found or access denied."
        )

    return scan


@router.post(
    "/{scan_id}/scan-secrets",
    response_model=List[SecretFindingResponse],
    summary="Run secret analysis engine on uploaded scan files"
)
async def execute_secret_scan(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Execute regex & Shannon entropy secret analysis and persist findings in PostgreSQL."""
    query = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found or access denied."
        )

    scan_workspace = os.path.join(TEMP_SCANS_BASE_DIR, str(scan_id), "extracted")
    if not os.path.exists(scan_workspace):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Extracted workspace files not found for this scan."
        )

    # Run the secret detection engine
    raw_findings = scan_directory_for_secrets(scan_workspace)

    # Purge any previous secret findings for clean update
    await db.execute(delete(SecretFinding).where(SecretFinding.scan_id == scan_id))

    db_findings: List[SecretFinding] = []
    severities: List[str] = []

    for item in raw_findings:
        severities.append(item.severity)
        finding_record = SecretFinding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            rule_id=item.rule_id,
            secret_type=item.secret_type,
            file_path=item.file_path,
            line_number=item.line_number,
            masked_snippet=item.masked_snippet,
            entropy_score=item.entropy_score,
            severity=item.severity,
            remediation_tip=item.remediation_tip
        )
        db_findings.append(finding_record)
        db.add(finding_record)

    # Update scan metrics
    scan.total_secrets = len(db_findings)
    scan.risk_level = calculate_risk_level(severities)
    await db.commit()

    return db_findings


@router.get(
    "/{scan_id}/secrets",
    response_model=List[SecretFindingResponse],
    summary="Get all secret findings detected in a scan"
)
async def get_scan_secret_findings(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Retrieve all secret findings discovered during the scan."""
    query = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found or access denied."
        )

    findings_query = select(SecretFinding).where(SecretFinding.scan_id == scan_id).order_by(SecretFinding.created_at.asc())
    findings_result = await db.execute(findings_query)
    return list(findings_result.scalars().all())


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan and purge its temporary files"
)
async def delete_scan(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Remove a scan from database and delete isolated workspace from disk."""
    query = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found or access denied."
        )

    # Delete workspace directory
    scan_dir = os.path.join(TEMP_SCANS_BASE_DIR, str(scan_id))
    cleanup_directory(scan_dir)

    await db.delete(scan)
    await db.commit()
    return None
