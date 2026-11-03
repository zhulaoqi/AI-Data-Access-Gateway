"""business descriptions shown by MCP

Revision ID: 202611030001
Revises: 202610290001
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "202611030001"
down_revision: str | None = "202610290001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Store business meanings separately from scanned table and column comments."""

    op.create_table(
        "ext_catalog_notes",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("datasource_id", sa.String(length=36), nullable=False),
        sa.Column("database_name", sa.String(length=200), nullable=False),
        sa.Column("table_name", sa.String(length=200), nullable=False),
        sa.Column("column_name", sa.String(length=200), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.UniqueConstraint(
            "datasource_id",
            "database_name",
            "table_name",
            "column_name",
            name="uq_ext_catalog_note",
        ),
    )
    op.create_index(
        "ix_ext_catalog_notes_datasource_id", "ext_catalog_notes", ["datasource_id"]
    )


def downgrade() -> None:
    """Remove business-meaning overlays."""

    op.drop_index("ix_ext_catalog_notes_datasource_id", table_name="ext_catalog_notes")
    op.drop_table("ext_catalog_notes")
