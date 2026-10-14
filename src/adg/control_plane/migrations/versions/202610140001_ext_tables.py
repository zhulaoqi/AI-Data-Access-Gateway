"""sql gateway extension tables

Revision ID: 202610140001
Revises: 202606110001
Create Date: 2026-10-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "202610140001"
down_revision: str | None = "202606110001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the ext_ tables used by the adg_ext patches (harmless when the patches are off)."""

    op.create_table(
        "ext_sync_objects",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("object_type", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.Column("spec_json", sa.Text(), nullable=False),
        sa.Column("external_id", sa.String(length=64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("object_type", "name", name="uq_ext_sync_type_name"),
    )
    op.create_index("ix_ext_sync_objects_object_type", "ext_sync_objects", ["object_type"])
    op.create_index("ix_ext_sync_objects_name", "ext_sync_objects", ["name"])
    op.create_table(
        "ext_role_specs",
        sa.Column("role_id", sa.String(length=36), sa.ForeignKey("roles.id"), primary_key=True),
        sa.Column("operations_json", sa.Text(), nullable=False),
        sa.Column("limits_json", sa.Text(), nullable=False),
    )
    op.create_table(
        "ext_role_tables",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("role_id", sa.String(length=36), sa.ForeignKey("roles.id"), nullable=False),
        sa.Column("resource_id", sa.String(length=36), nullable=False),
        sa.Column("allow_json", sa.Text(), nullable=False),
        sa.Column("deny_json", sa.Text(), nullable=False),
        sa.Column("mask_json", sa.Text(), nullable=False),
        sa.UniqueConstraint("role_id", "resource_id", name="uq_ext_role_table"),
    )
    op.create_index("ix_ext_role_tables_role_id", "ext_role_tables", ["role_id"])
    op.create_index("ix_ext_role_tables_resource_id", "ext_role_tables", ["resource_id"])
    op.create_table(
        "ext_row_filter_policies",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("role_id", sa.String(length=36), sa.ForeignKey("roles.id"), nullable=False),
        sa.Column("resource_id", sa.String(length=36), nullable=False),
        sa.Column("where_text", sa.Text(), nullable=False),
        sa.Column("params_json", sa.Text(), nullable=False),
        sa.UniqueConstraint("role_id", "resource_id", name="uq_ext_row_filter"),
    )
    op.create_index("ix_ext_row_filter_policies_role_id", "ext_row_filter_policies", ["role_id"])
    op.create_index(
        "ix_ext_row_filter_policies_resource_id", "ext_row_filter_policies", ["resource_id"]
    )
    op.create_table(
        "ext_user_attributes",
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("params_json", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    """Drop the ext_ tables."""

    for table in (
        "ext_user_attributes",
        "ext_row_filter_policies",
        "ext_role_tables",
        "ext_role_specs",
        "ext_sync_objects",
    ):
        op.drop_table(table)
