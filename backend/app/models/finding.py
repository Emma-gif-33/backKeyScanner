import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.scan import Scan


class SecretFinding(Base):
    __tablename__ = "secret_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    rule_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True
    )
    secret_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False
    )
    file_path: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )
    line_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False
    )
    masked_snippet: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )
    entropy_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True
    )
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True
    )  # LOW, MEDIUM, HIGH, CRITICAL
    remediation_tip: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="secret_findings"
    )

    def __repr__(self) -> str:
        return f"<SecretFinding {self.rule_id} in {self.file_path}:{self.line_number}>"


class DependencyFinding(Base):
    __tablename__ = "dependency_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    package_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True
    )
    installed_version: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )
    ecosystem: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True
    )  # PyPI, npm
    manifest_file: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    osv_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True
    )  # GHSA-..., CVE-...
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True
    )  # LOW, MEDIUM, HIGH, CRITICAL
    fixed_version: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True
    )
    summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    advisory_url: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="dependency_findings"
    )

    def __repr__(self) -> str:
        return f"<DependencyFinding {self.package_name}@{self.installed_version} [{self.osv_id}]>"
