"""Business meanings synced for MCP, kept apart from column permissions and scanned comments."""

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from adg.control_plane.models.resource import Resource
from adg_ext.models import ExtCatalogNote

_EMPTY = ""
_MAX_TEXT = 4000
_MAX_NAME = 200


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return text[:_MAX_TEXT]


def _name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > _MAX_NAME:
        return None
    return name


def replace_notes(session: Session, datasource_id: str, spec: dict[str, object]) -> None:
    """Replace every business meaning stored for one executor datasource."""

    session.execute(delete(ExtCatalogNote).where(ExtCatalogNote.datasource_id == datasource_id))
    rows: list[ExtCatalogNote] = []
    for item in _items(spec.get("databases")):
        database = _name(item.get("name"))
        text = _text(item.get("text"))
        if database and text:
            rows.append(_row(datasource_id, database, _EMPTY, _EMPTY, text))
    for item in _items(spec.get("tables")):
        database = _name(item.get("database"))
        table = _name(item.get("name"))
        text = _text(item.get("text"))
        if database and table and text:
            rows.append(_row(datasource_id, database, table, _EMPTY, text))
    for item in _items(spec.get("columns")):
        database = _name(item.get("database"))
        table = _name(item.get("table"))
        column = _name(item.get("name"))
        text = _text(item.get("text"))
        if database and table and column and text:
            rows.append(_row(datasource_id, database, table, column, text))
    session.add_all(rows)
    session.flush()


def delete_notes(session: Session, datasource_id: str | None) -> None:
    if not datasource_id:
        return
    session.execute(delete(ExtCatalogNote).where(ExtCatalogNote.datasource_id == datasource_id))
    session.flush()


def _items(value: object) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("catalog note lists must be arrays")
    out: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("catalog note entries must be objects")
        out.append(item)
    return out


def _row(datasource_id: str, database: str, table: str, column: str, text: str) -> ExtCatalogNote:
    return ExtCatalogNote(
        datasource_id=datasource_id,
        database_name=database,
        table_name=table,
        column_name=column,
        text=text,
    )


class NoteIndex:
    """Business meanings for the datasources a single MCP response touches."""

    def __init__(self, rows: list[ExtCatalogNote]) -> None:
        self._database: dict[tuple[str, str], str] = {}
        self._table: dict[tuple[str, str, str], str] = {}
        self._column: dict[tuple[str, str, str, str], str] = {}
        for row in rows:
            if row.table_name == _EMPTY and row.column_name == _EMPTY:
                self._database[(row.datasource_id, row.database_name)] = row.text
            elif row.column_name == _EMPTY:
                self._table[(row.datasource_id, row.database_name, row.table_name)] = row.text
            else:
                self._column[
                    (row.datasource_id, row.database_name, row.table_name, row.column_name)
                ] = row.text

    @staticmethod
    def load(session: Session, datasource_ids: set[str]) -> "NoteIndex":
        if not datasource_ids:
            return NoteIndex([])
        rows = list(
            session.execute(
                select(ExtCatalogNote).where(
                    ExtCatalogNote.datasource_id.in_(sorted(datasource_ids))
                )
            ).scalars()
        )
        return NoteIndex(rows)

    def database(self, datasource_id: str, database: str) -> str | None:
        return self._database.get((datasource_id, database))

    def table(self, datasource_id: str, database: str, table: str) -> str | None:
        return self._table.get((datasource_id, database, table))

    def column(self, datasource_id: str, database: str, table: str, column: str) -> str | None:
        return self._column.get((datasource_id, database, table, column))


def prefer(business: str | None, scanned: str | None) -> str | None:
    """Business text wins. A blank business meaning leaves the scanned comment in place."""

    if business and business.strip():
        return business
    return scanned


def table_address(resource: Resource) -> tuple[str, str]:
    """Database and table names as the management service addresses them.

    A MySQL-style path is ``database.table``. A schema path is ``database.schema.table``;
    the parent path (everything before the table name) is the address the note was stored under
    when the catalog database itself is that parent. Callers also try the first path segment.
    """

    name = resource.name
    suffix = "." + name
    if resource.path.endswith(suffix):
        return resource.path[: -len(suffix)], name
    return resource.path, name
