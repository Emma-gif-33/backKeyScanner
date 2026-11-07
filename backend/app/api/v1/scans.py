import os
import uuid
from typing import Annotated, List, Optional
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models.finding import DependencyFinding, SecretFinding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import DependencyFindingResponse, SecretFindingResponse
from app.schemas.scan import (
    CategoryBreakdown,
    ReportSummary,
    ScanListResponse,
    ScanReportResponse,
    ScanResponse,
    SeverityBreakdown,
)
from app.services.dependency_scanner import scan_directory_for_vulnerabilities
from app.services.ingestion import (
    cleanup_directory,
    compute_sha256,
    extract_zip_safely,
    validate_and_inspect_zip,
)
from app.services.scanner_pipeline import calculate_risk_level, run_full_scan_pipeline
from app.services.secret_scanner import scan_directory_for_secrets

router = APIRouter()

TEMP_SCANS_BASE_DIR = settings.TEMP_SCANS_BASE_DIR


@router.post(
    "/upload",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest a zip archive, launching automated audit in background"
)
async def upload_scan_archive(
    file: Annotated[UploadFile, File(description="Zip archive containing project source code")],
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    project_name: Annotated[Optional[str], Form(description="Custom project name")] = None,
):
    """Upload project archive, extract safely, register in queue and trigger background scan pipeline."""
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

    # 4. Trigger full automated pipeline in background
    background_tasks.add_task(run_full_scan_pipeline, scan_id)

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


@router.get(
    "/{scan_id}/report",
    response_model=ScanReportResponse,
    summary="Get consolidated audit report for a completed scan"
)
async def get_scan_consolidated_report(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Return consolidated report including executive summary, metrics, secrets and CVEs."""
    query = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found or access denied."
        )

    # Fetch secrets
    secrets_query = (
        select(SecretFinding)
        .where(SecretFinding.scan_id == scan_id)
        .order_by(SecretFinding.severity.desc(), SecretFinding.created_at.asc())
    )
    secrets_res = await db.execute(secrets_query)
    secrets = list(secrets_res.scalars().all())

    # Fetch dependencies
    deps_query = (
        select(DependencyFinding)
        .where(DependencyFinding.scan_id == scan_id)
        .order_by(DependencyFinding.severity.desc(), DependencyFinding.created_at.asc())
    )
    deps_res = await db.execute(deps_query)
    dependencies = list(deps_res.scalars().all())

    metrics = scan.summary_metrics or {}
    by_sev_raw = metrics.get("by_severity", {})
    by_cat_raw = metrics.get("by_category", {})

    summary = ReportSummary(
        total_findings=len(secrets) + len(dependencies),
        risk_level=scan.risk_level,
        by_severity=SeverityBreakdown(
            critical=by_sev_raw.get("critical", 0),
            high=by_sev_raw.get("high", 0),
            medium=by_sev_raw.get("medium", 0),
            low=by_sev_raw.get("low", 0),
        ),
        by_category=CategoryBreakdown(
            secrets=by_cat_raw.get("secrets", len(secrets)),
            dependencies=by_cat_raw.get("dependencies", len(dependencies)),
        ),
        duration_seconds=metrics.get("duration_seconds"),
        files_extracted=metrics.get("files_extracted", 0),
    )

    return ScanReportResponse(
        scan_id=scan.id,
        project_name=scan.project_name,
        source_filename=scan.source_filename,
        file_hash_sha256=scan.file_hash_sha256,
        status=scan.status,
        risk_level=scan.risk_level,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error_message=scan.error_message,
        summary=summary,
        secrets=secrets,
        dependencies=dependencies,
    )


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

    # Run secret detection engine
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

    # Re-evaluate global risk combining secrets and dependencies
    dep_sev_res = await db.execute(select(DependencyFinding.severity).where(DependencyFinding.scan_id == scan_id))
    all_sevs = severities + list(dep_sev_res.scalars().all())
    scan.risk_level = calculate_risk_level(all_sevs)

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


@router.post(
    "/{scan_id}/scan-dependencies",
    response_model=List[DependencyFindingResponse],
    summary="Run dependency vulnerability audit via OSV.dev"
)
async def execute_dependency_scan(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Audit project packages against OSV database and persist CVEs in PostgreSQL."""
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

    # Run dependency scanner (query OSV API)
    raw_findings = await scan_directory_for_vulnerabilities(scan_workspace)

    # Purge any previous dependency findings for clean update
    await db.execute(delete(DependencyFinding).where(DependencyFinding.scan_id == scan_id))

    db_findings: List[DependencyFinding] = []
    severities: List[str] = []

    for item in raw_findings:
        severities.append(item.severity)
        finding_record = DependencyFinding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            package_name=item.package_name,
            installed_version=item.installed_version,
            ecosystem=item.ecosystem,
            manifest_file=item.manifest_file,
            osv_id=item.osv_id,
            severity=item.severity,
            fixed_version=item.fixed_version,
            summary=item.summary,
            advisory_url=item.advisory_url
        )
        db_findings.append(finding_record)
        db.add(finding_record)

    # Update scan metrics
    scan.total_vulnerabilities = len(db_findings)

    # Re-evaluate global risk combining secrets and dependencies
    sec_sev_res = await db.execute(select(SecretFinding.severity).where(SecretFinding.scan_id == scan_id))
    all_sevs = severities + list(sec_sev_res.scalars().all())
    scan.risk_level = calculate_risk_level(all_sevs)

    await db.commit()
    return db_findings


@router.get(
    "/{scan_id}/dependencies",
    response_model=List[DependencyFindingResponse],
    summary="Get all dependency vulnerabilities detected in a scan"
)
async def get_scan_dependency_findings(
    scan_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Retrieve all dependency vulnerabilities discovered during the scan."""
    query = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found or access denied."
        )

    findings_query = select(DependencyFinding).where(DependencyFinding.scan_id == scan_id).order_by(DependencyFinding.created_at.asc())
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
