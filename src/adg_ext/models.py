"""Extension tables (all prefixed ``ext_``); they hang off the upstream declarative base."""

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from adg.control_plane.models.base import Base
from adg.shared.ids import uuidv7


def _now() -> datetime:
    return datetime.now(UTC)


class ExtSyncObject(Base):
    """One object pushed by the management service, with the hash it was last synced at."""

    __tablename__ = "ext_sync_objects"
    __table_args__ = (UniqueConstraint("object_type", "name", name="uq_ext_sync_type_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuidv7)
    object_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)
    spec_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    # id of the native ADG object the spec was materialized into (datasource, role, user, key)
    external_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )


class ExtRoleSpec(Base):
    """Operation limits and quotas of a role (from the synced role spec)."""

    __tablename__ = "ext_role_specs"

    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    operations_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    limits_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class ExtRoleTable(Base):
    """Closed column scope of a role on one table: allowed columns, denied columns, masks."""

    __tablename__ = "ext_role_tables"
    __table_args__ = (UniqueConstraint("role_id", "resource_id", name="uq_ext_role_table"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuidv7)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    allow_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    deny_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    mask_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class ExtRowFilterPolicy(Base):
    """Row-filter predicate template for one role on one table (PA-1)."""

    __tablename__ = "ext_row_filter_policies"
    __table_args__ = (UniqueConstraint("role_id", "resource_id", name="uq_ext_row_filter"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuidv7)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    where_text: Mapped[str] = mapped_column(Text, nullable=False)
    params_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")


class ExtUserAttribute(Base):
    """Grant parameters (e.g. ``tenant_id``) bound to a user, rendered into row filters."""

    __tablename__ = "ext_user_attributes"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    params_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
