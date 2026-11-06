import os
import uuid
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import ScanListResponse, ScanResponse
from app.services.ingestion import (
    cleanup_directory,
    compute_sha256,
    extract_zip_safely,
    validate_and_inspect_zip,
)

router = APIRouter()

TEMP_SCANS_BASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "temp_scans"
)


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

    # 1. Validate archive integrity and security limits (Zip Bomb / Zip Slip)
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
