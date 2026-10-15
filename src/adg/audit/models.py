import json
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, mapped_column

from adg.control_plane.models.base import Base
from adg.shared.ids import uuidv7


# MySQL TEXT holds 64 KB; a statement is recorded twice (original and rewritten) in the metadata,
# so the columns that grow with the statement are MEDIUMTEXT (16 MB) there. Other dialects: TEXT.
LargeText = Text().with_variant(mysql.MEDIUMTEXT(), "mysql")


class AuditEvent(Base):
    """Append-only audit record for admin, runtime, masking, and decrypt events."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuidv7)
    user_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    api_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    datasource_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    resource_ids_json: Mapped[str] = mapped_column(LargeText, nullable=False, default="[]")
    # `qry_<uuid4>` is 40 characters (was String(36): MySQL refused the row with "Data too long")
    query_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    sql_text: Mapped[str | None] = mapped_column(LargeText, nullable=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str] = mapped_column(LargeText, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )

    @property
    def resource_ids(self) -> list[str]:
        """Decode stored resource ids for summary/detail serializers."""

        decoded = json.loads(self.resource_ids_json)
        if not isinstance(decoded, list) or not all(isinstance(item, str) for item in decoded):
            raise ValueError("AuditEvent.resource_ids_json must decode to list[str]")
        return decoded

    @property
    def audit_metadata(self) -> dict[str, Any]:
        """Decode stored metadata for summary/detail serializers."""

        decoded = json.loads(self.metadata_json)
        if not isinstance(decoded, dict) or not all(
            isinstance(key, str) for key in decoded
        ):
            raise ValueError("AuditEvent.metadata_json must decode to dict[str, Any]")
        return cast(dict[str, Any], decoded)
