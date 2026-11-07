import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.scan import Scan


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    full_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"
