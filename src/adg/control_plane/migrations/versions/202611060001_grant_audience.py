"""store the MCP directory allowlist on the synced user

Revision ID: 202611060001
Revises: 202611030001
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "202611060001"
down_revision: str | None = "202611030001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Null means the grant does not restrict MCP callers."""

    with op.batch_alter_table("ext_user_attributes") as batch:
        batch.add_column(sa.Column("audience_json", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ext_user_attributes") as batch:
        batch.drop_column("audience_json")
