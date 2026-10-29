"""persist executor user limits and datasource capacity

Revision ID: 202610290001
Revises: 202610150001
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "202610290001"
down_revision: str | None = "202610150001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add backward-compatible user limits and per-datasource capacity."""

    with op.batch_alter_table("ext_user_attributes") as batch:
        batch.add_column(sa.Column("limits_json", sa.Text(), nullable=False, server_default="{}"))
    op.create_table(
        "ext_datasource_capacities",
        sa.Column(
            "datasource_id",
            sa.String(length=36),
            sa.ForeignKey("datasources.id"),
            primary_key=True,
        ),
        sa.Column("tier", sa.String(length=64), nullable=False),
        sa.Column("connection_budget", sa.Integer(), nullable=False),
        sa.Column("max_query_concurrency", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    """Remove executor capacity state."""

    op.drop_table("ext_datasource_capacities")
    with op.batch_alter_table("ext_user_attributes") as batch:
        batch.drop_column("limits_json")
