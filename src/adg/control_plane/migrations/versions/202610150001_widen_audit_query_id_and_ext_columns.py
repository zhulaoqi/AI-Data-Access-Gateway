"""widen audit_events.query_id and the columns that outgrow their type on MySQL

``audit_events.query_id`` was ``VARCHAR(36)`` but a query id is ``qry_<uuid4>`` (40 characters):
SQLite ignores column lengths, MySQL (strict mode) answers ``Data too long``, the audit row could
not be written and the fail-closed pipeline refused every query (``audit_unavailable``).

* ``audit_events.query_id``          VARCHAR(36)  -> VARCHAR(64)   (same width as ``decrypt_contexts``)
* ``ext_sync_objects.external_id``   VARCHAR(64)  -> VARCHAR(256)  (a row filter's external id is its
  object name, up to 200 characters)
* MySQL only: the TEXT columns that grow with the statement or the synced spec (audit SQL and
  metadata, role specs, allow/deny/mask lists, row-filter templates) -> MEDIUMTEXT (64 KB -> 16 MB).

Safe on existing data: ``MODIFY`` only enlarges, nothing is rewritten by value. SQLite has no
ALTER COLUMN, so Alembic's batch mode rebuilds the table there (indexes and constraints are
reflected and recreated). MySQL rebuilds ``audit_events`` for the VARCHAR change (a utf8mb4
VARCHAR growing past 255 bytes changes its length prefix, so ``ALGORITHM=INPLACE`` is not
possible); the Helm chart runs ``alembic upgrade head`` in an init container, so for a big
audit table run it once ahead of the rollout. Re-running after a manual
``ALTER TABLE audit_events MODIFY query_id VARCHAR(64) NULL`` (the kind workaround) is a no-op.

Revision ID: 202610150001
Revises: 202610140001
Create Date: 2026-10-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "202610150001"
down_revision: str | None = "202610140001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (table, column, nullable) of the TEXT columns promoted to MEDIUMTEXT on MySQL
_LARGE_TEXT: tuple[tuple[str, str, bool], ...] = (
    ("audit_events", "resource_ids_json", False),
    ("audit_events", "sql_text", True),
    ("audit_events", "metadata_json", False),
    ("ext_sync_objects", "spec_json", False),
    ("ext_role_tables", "allow_json", False),
    ("ext_role_tables", "deny_json", False),
    ("ext_role_tables", "mask_json", False),
    ("ext_row_filter_policies", "where_text", False),
    ("ext_row_filter_policies", "params_json", False),
    ("ext_user_attributes", "params_json", False),
)


def _is_mysql() -> bool:
    return op.get_bind().dialect.name in ("mysql", "mariadb")


def upgrade() -> None:
    """Enlarge the columns (data is kept)."""

    with op.batch_alter_table("audit_events") as batch:
        batch.alter_column(
            "query_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=64),
            existing_nullable=True,
        )
    with op.batch_alter_table("ext_sync_objects") as batch:
        batch.alter_column(
            "external_id",
            existing_type=sa.String(length=64),
            type_=sa.String(length=256),
            existing_nullable=True,
        )
    if _is_mysql():
        for table, column, nullable in _LARGE_TEXT:
            op.alter_column(
                table,
                column,
                existing_type=sa.Text(),
                type_=mysql.MEDIUMTEXT(),
                existing_nullable=nullable,
            )


def downgrade() -> None:
    """Narrow the columns again; MySQL refuses (strict mode) when a longer value exists."""

    if _is_mysql():
        for table, column, nullable in reversed(_LARGE_TEXT):
            op.alter_column(
                table,
                column,
                existing_type=mysql.MEDIUMTEXT(),
                type_=sa.Text(),
                existing_nullable=nullable,
            )
    with op.batch_alter_table("ext_sync_objects") as batch:
        batch.alter_column(
            "external_id",
            existing_type=sa.String(length=256),
            type_=sa.String(length=64),
            existing_nullable=True,
        )
    with op.batch_alter_table("audit_events") as batch:
        batch.alter_column(
            "query_id",
            existing_type=sa.String(length=64),
            type_=sa.String(length=36),
            existing_nullable=True,
        )
