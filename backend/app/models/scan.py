import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.finding import DependencyFinding, SecretFinding


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    project_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True
    )
    source_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    file_hash_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="QUEUED",
        nullable=False,
        index=True
    )  # QUEUED, PROCESSING, COMPLETED, FAILED
    total_secrets: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )
    total_vulnerabilities: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )
    risk_level: Mapped[str] = mapped_column(
        String(16),
        default="NONE",
        nullable=False
    )  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    summary_metrics: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="scans"
    )
    secret_findings: Mapped[List["SecretFinding"]] = relationship(
        "SecretFinding",
        back_populates="scan",
        cascade="all, delete-orphan"
    )
    dependency_findings: Mapped[List["DependencyFinding"]] = relationship(
        "DependencyFinding",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Scan {self.id} project={self.project_name} status={self.status}>"
