"""TRACE-X canonical event schema — Phase 1.

Every parser MUST output this shape. Every downstream module reads/writes
only this schema plus its own derived tables, never raw sources directly.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class EventSource(str, Enum):
    WINDOWS_EVENTLOG = "WINDOWS_EVENTLOG"
    FILESYSTEM_NTFS = "FILESYSTEM_NTFS"
    BROWSER = "BROWSER"
    USB = "USB"


class EventType(str, Enum):
    LOGIN = "LOGIN"
    LOGOFF = "LOGOFF"
    FILE_ACCESSED = "FILE_ACCESSED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_COPIED = "FILE_COPIED"
    FILE_DELETED = "FILE_DELETED"
    FILE_CREATED = "FILE_CREATED"
    PAGE_VISIT = "PAGE_VISIT"
    FILE_DOWNLOAD = "FILE_DOWNLOAD"
    DEVICE_CONNECTED = "DEVICE_CONNECTED"
    DEVICE_DISCONNECTED = "DEVICE_DISCONNECTED"
    LOG_CLEARED = "LOG_CLEARED"
    TIMESTAMP_ANOMALY = "TIMESTAMP_ANOMALY"
    PROCESS_CREATED = "PROCESS_CREATED"


class Provenance(BaseModel):
    source_file: str
    parser_name: str
    parser_version: str
    original_record_offset_or_id: str


class CanonicalEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    event_type: EventType
    source: EventSource
    user: Optional[str] = None
    object: Optional[str] = None  # file path / URL / device id
    process: Optional[str] = None
    device_id: Optional[str] = None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance
    hash: str = ""

    @field_validator("timestamp", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            dt = v
        else:
            s = str(v).replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def compute_hash(self) -> str:
        blob = json.dumps(
            {"ts": self.timestamp.isoformat(), "type": self.event_type.value,
             "src": self.source.value, "raw": self.raw_metadata},
            sort_keys=True, default=str,
        ).encode()
        return hashlib.sha256(blob).hexdigest()

    def model_post_init(self, _ctx: Any) -> None:
        if not self.hash:
            object.__setattr__(self, "hash", self.compute_hash())


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    """SQLite mirror of CanonicalEvent."""

    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[str] = mapped_column(String(32), index=True)  # ISO-8601 UTC
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    user: Mapped[Optional[str]] = mapped_column(String(256), nullable=True, index=True)
    object: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    process: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True, index=True)
    raw_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    @classmethod
    def from_event(cls, e: CanonicalEvent) -> "EventRow":
        return cls(
            event_id=e.event_id,
            timestamp=e.timestamp.isoformat(),
            event_type=e.event_type.value,
            source=e.source.value,
            user=e.user,
            object=e.object,
            process=e.process,
            device_id=e.device_id,
            raw_metadata=e.raw_metadata,
            provenance=e.provenance.model_dump(),
            hash=e.hash,
        )

    def to_event(self) -> CanonicalEvent:
        return CanonicalEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            event_type=EventType(self.event_type),
            source=EventSource(self.source),
            user=self.user,
            object=self.object,
            process=self.process,
            device_id=self.device_id,
            raw_metadata=self.raw_metadata or {},
            provenance=Provenance(**(self.provenance or {})),
            hash=self.hash,
        )
