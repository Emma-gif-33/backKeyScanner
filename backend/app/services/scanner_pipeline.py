import os
import uuid
from datetime import datetime, timezone
from typing import List
from sqlalchemy import delete, select

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.finding import DependencyFinding, SecretFinding
from app.models.scan import Scan
from app.services.dependency_scanner import scan_directory_for_vulnerabilities
from app.services.secret_scanner import scan_directory_for_secrets

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

TEMP_SCANS_BASE_DIR = settings.TEMP_SCANS_BASE_DIR


def calculate_risk_level(findings_severities: List[str]) -> str:
    """Determine highest risk level from a list of severities."""
    highest_score = 0
    highest_severity = "NONE"
    for sev in findings_severities:
        score = SEVERITY_ORDER.get(sev.upper(), 0)
        if score > highest_score:
            highest_score = score
            highest_severity = sev.upper()
    return highest_severity


async def run_full_scan_pipeline(scan_id: uuid.UUID) -> None:
    """Orchestrate background execution of the full audit pipeline for a scan."""
    async with AsyncSessionLocal() as db:
        try:
            query = select(Scan).where(Scan.id == scan_id)
            result = await db.execute(query)
            scan = result.scalar_one_or_none()
            if not scan:
                return

            scan.status = "PROCESSING"
            scan.started_at = datetime.now(timezone.utc)
            scan.error_message = None
            await db.commit()

            workspace_dir = os.path.join(TEMP_SCANS_BASE_DIR, str(scan_id), "extracted")
            if not os.path.exists(workspace_dir):
                scan.status = "FAILED"
                scan.error_message = f"Workspace directory for scan {scan_id} does not exist."
                scan.finished_at = datetime.now(timezone.utc)
                await db.commit()
                return

            raw_secrets = scan_directory_for_secrets(workspace_dir)

            await db.execute(delete(SecretFinding).where(SecretFinding.scan_id == scan_id))
            secret_entities: List[SecretFinding] = []
            for s in raw_secrets:
                secret_entities.append(SecretFinding(
                    id=uuid.uuid4(),
                    scan_id=scan_id,
                    rule_id=s.rule_id,
                    secret_type=s.secret_type,
                    file_path=s.file_path,
                    line_number=s.line_number,
                    masked_snippet=s.masked_snippet,
                    entropy_score=s.entropy_score,
                    severity=s.severity,
                    remediation_tip=s.remediation_tip
                ))
            db.add_all(secret_entities)

            raw_deps = await scan_directory_for_vulnerabilities(workspace_dir)

            await db.execute(delete(DependencyFinding).where(DependencyFinding.scan_id == scan_id))
            dep_entities: List[DependencyFinding] = []
            for d in raw_deps:
                dep_entities.append(DependencyFinding(
                    id=uuid.uuid4(),
                    scan_id=scan_id,
                    package_name=d.package_name,
                    installed_version=d.installed_version,
                    ecosystem=d.ecosystem,
                    manifest_file=d.manifest_file,
                    osv_id=d.osv_id,
                    severity=d.severity,
                    fixed_version=d.fixed_version,
                    summary=d.summary,
                    advisory_url=d.advisory_url
                ))
            db.add_all(dep_entities)

            finished_at = datetime.now(timezone.utc)
            duration_sec = (finished_at - scan.started_at).total_seconds()

            all_severities = [s.severity for s in secret_entities] + [d.severity for d in dep_entities]
            risk_level = calculate_risk_level(all_severities)

            critical_count = sum(1 for s in all_severities if s.upper() == "CRITICAL")
            high_count = sum(1 for s in all_severities if s.upper() == "HIGH")
            medium_count = sum(1 for s in all_severities if s.upper() == "MEDIUM")
            low_count = sum(1 for s in all_severities if s.upper() == "LOW")

            prev_metrics = scan.summary_metrics or {}
            updated_metrics = {
                **prev_metrics,
                "duration_seconds": round(duration_sec, 2),
                "by_severity": {
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "low": low_count
                },
                "by_category": {
                    "secrets": len(secret_entities),
                    "dependencies": len(dep_entities)
                }
            }

            scan.status = "COMPLETED"
            scan.total_secrets = len(secret_entities)
            scan.total_vulnerabilities = len(dep_entities)
            scan.risk_level = risk_level
            scan.summary_metrics = updated_metrics
            scan.finished_at = finished_at

            await db.commit()

        except Exception as e:
            await db.rollback()
            try:
                query = select(Scan).where(Scan.id == scan_id)
                res = await db.execute(query)
                scan = res.scalar_one_or_none()
                if scan:
                    scan.status = "FAILED"
                    scan.error_message = str(e)
                    scan.finished_at = datetime.now(timezone.utc)
                    await db.commit()
            except Exception:
                pass
