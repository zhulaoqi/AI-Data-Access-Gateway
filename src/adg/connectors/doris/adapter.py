from typing import Any

from sqlalchemy import create_engine, text

from adg.app.settings import get_settings
from adg.connectors.base import MetadataSnapshot
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError
from adg.connectors.relational import RelationalConnector, pinned_scan_databases


class DorisConnector(RelationalConnector):
    """Doris connector that reuses the MySQL wire-protocol driver path."""

    connector_type = "doris"
    sqlalchemy_drivername = "mysql+pymysql"
    dependency_name = "pymysql"
    install_extra = "doris"

    def scan_metadata(self, config: dict[str, object]) -> MetadataSnapshot:
        """Scan Doris metadata without SQLAlchemy's MySQL DDL parser."""

        self._require_dependency()
        connection_config = self._validated_connection_config(config)
        pinned = pinned_scan_databases(connection_config)
        database_name = str(connection_config.get("database", "")).strip()

        try:
            engine = create_engine(
                self._build_url(connection_config),
                connect_args=self._doris_one_shot_connect_args(),
            )
            with engine.connect() as connection:
                if pinned is not None:
                    if not pinned:
                        raise ConnectorOperationError("metadata_scan_databases_empty")
                    database_names = pinned
                elif database_name:
                    database_names = [database_name]
                else:
                    database_names = self._list_database_names(connection)
                    if len(database_names) > get_settings().metadata_scan_max_databases:
                        raise ConnectorOperationError("metadata_scan_database_limit_exceeded")
                databases = [
                    self._scan_database(connection, scanned_database_name)
                    for scanned_database_name in database_names
                ]
        except ConnectorDependencyError:
            raise
        except ConnectorOperationError:
            raise
        except Exception as error:
            raise ConnectorOperationError(str(error)) from error

        return {"databases": databases}

    def _doris_one_shot_connect_args(self) -> dict[str, object]:
        """Return MySQL wire-protocol timeout options for Doris scan connections."""

        settings = get_settings()
        return {
            "connect_timeout": settings.runtime_datasource_connect_timeout_seconds,
            "read_timeout": settings.runtime_datasource_read_timeout_seconds,
            "write_timeout": settings.runtime_datasource_write_timeout_seconds,
        }

    def _list_database_names(self, connection: Any) -> list[str]:
        """Discover user-accessible Doris databases from information_schema."""

        rows = connection.execute(
            text(
                """
                SELECT SCHEMA_NAME AS schema_name
                FROM information_schema.SCHEMATA
                WHERE SCHEMA_NAME NOT IN (
                    'information_schema',
                    'mysql',
                    'performance_schema',
                    'sys'
                )
                ORDER BY SCHEMA_NAME
                """
            )
        ).mappings().all()
        return [str(row["schema_name"]) for row in rows if str(row["schema_name"]).strip()]

    def _scan_database(self, connection: Any, database_name: str) -> dict[str, object]:
        """Read Doris table and column metadata for one database."""

        relations = connection.execute(
            text(
                """
                SELECT
                    TABLE_NAME AS table_name,
                    TABLE_TYPE AS table_type,
                    TABLE_COMMENT AS table_comment
                FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = :schema
                ORDER BY TABLE_NAME
                """
            ),
            {"schema": database_name},
        ).mappings().all()
        columns = connection.execute(
            text(
                """
                SELECT
                    TABLE_NAME AS table_name,
                    COLUMN_NAME AS column_name,
                    DATA_TYPE AS data_type,
                    IS_NULLABLE AS is_nullable,
                    ORDINAL_POSITION AS ordinal_position,
                    COLUMN_COMMENT AS column_comment
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = :schema
                ORDER BY TABLE_NAME, ORDINAL_POSITION
                """
            ),
            {"schema": database_name},
        ).mappings().all()

        columns_by_relation: dict[str, list[dict[str, object]]] = {}
        for column in columns:
            relation_name = str(column["table_name"])
            columns_by_relation.setdefault(relation_name, []).append(
                {
                    "name": str(column["column_name"]),
                    "data_type": str(column["data_type"]),
                    "nullable": str(column["is_nullable"]).upper() == "YES",
                    "ordinal_position": int(column["ordinal_position"]),
                    "description": column["column_comment"] or None,
                }
            )

        tables: list[dict[str, object]] = []
        views: list[dict[str, object]] = []
        for relation in relations:
            relation_name = str(relation["table_name"])
            relation_payload: dict[str, object] = {
                "name": relation_name,
                "kind": "view" if str(relation["table_type"]).upper() == "VIEW" else "table",
                "description": self._normalize_comment(relation["table_comment"]),
                "columns": columns_by_relation.get(relation_name, []),
            }
            if relation_payload["kind"] == "view":
                views.append(relation_payload)
            else:
                tables.append(relation_payload)

        return {
            "name": database_name,
            "tables": tables,
            "views": views,
        }

    def _normalize_comment(self, value: object) -> str | None:
        """Convert empty database comments to null descriptions."""

        text_value = str(value).strip() if value is not None else ""
        return text_value or None
