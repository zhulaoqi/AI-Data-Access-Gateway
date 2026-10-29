import json

from sqlalchemy import select

from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.directory import Role, User
from adg_ext import context, pipeline
from adg_ext.models import ExtDatasourceCapacity, ExtRoleSpec, ExtUserAttribute
from adg_ext.sync import SyncService


class FakeRegistry:
    class Connector:
        def scan_metadata(self, config: dict[str, object]) -> dict[str, object]:
            return {"databases": []}

    def create(self, connector_type: str) -> Connector:
        assert connector_type == "mysql"
        return self.Connector()


def test_user_limits_are_synced_and_narrow_role_limits(db_session) -> None:
    role = Role(name="gw:role:analyst")
    db_session.add(role)
    db_session.flush()
    db_session.add(
        ExtRoleSpec(
            role_id=role.id,
            operations_json="{}",
            limits_json=json.dumps(
                {"maxConcurrency": 8, "queueSize": 20, "queryTimeoutSeconds": 45}
            ),
        )
    )
    db_session.flush()

    service = SyncService(db_session)
    service.put(
        "role",
        role.name,
        "a" * 64,
        {
            "limits": {"maxConcurrency": 8, "queueSize": 20, "queryTimeoutSeconds": 45},
            "tables": [],
        },
    )
    user_id = service.put(
        "user",
        "gw:user:alice",
        "b" * 64,
        {
            "role": role.name,
            "params": {"tenant_id": 7},
            "limits": {"maxJdbcConnections": 12, "maxConcurrency": 3, "queueSize": 5},
        },
    )

    attribute = db_session.get(ExtUserAttribute, user_id)
    assert json.loads(attribute.limits_json) == {
        "maxJdbcConnections": 12,
        "maxConcurrency": 3,
        "queueSize": 5,
    }
    loaded = context.load(db_session, user_id=user_id, role_ids=[role.id])
    assert loaded.limits["maxConcurrency"] == 3
    assert loaded.limits["queueSize"] == 5
    assert loaded.limits["queryTimeoutSeconds"] == 45


def test_historical_user_without_limits_keeps_role_limits(db_session) -> None:
    role = Role(name="gw:role:legacy")
    user = User(name="legacy", external_ref="gw:user:legacy")
    db_session.add_all((role, user))
    db_session.flush()
    db_session.add(
        ExtRoleSpec(
            role_id=role.id,
            operations_json="{}",
            limits_json='{"maxConcurrency":6,"queueSize":9}',
        )
    )
    db_session.add(ExtUserAttribute(user_id=user.id, params_json="{}", limits_json="{}"))
    db_session.flush()

    loaded = context.load(db_session, user_id=user.id, role_ids=[role.id])
    assert loaded.limits["maxConcurrency"] == 6
    assert loaded.limits["queueSize"] == 9


def test_datasource_capacity_is_persisted_and_updated(db_session) -> None:
    service = SyncService(db_session, registry=FakeRegistry())  # type: ignore[arg-type]
    spec = {
        "engine": "mysql",
        "host": "db.example",
        "username": "reader",
        "password": "secret",
        "capacity": {
            "tier": "large",
            "connectionBudget": 12,
            "maxQueryConcurrency": 7,
        },
    }
    datasource_id = service.put("datasource_account", "gw:ds:orders", "c" * 64, spec)
    capacity = db_session.get(ExtDatasourceCapacity, datasource_id)
    assert (capacity.tier, capacity.connection_budget, capacity.max_query_concurrency) == (
        "large",
        12,
        7,
    )

    spec["capacity"] = {
        "tier": "small",
        "connectionBudget": 4,
        "maxQueryConcurrency": 2,
    }
    service.put("datasource_account", "gw:ds:orders", "d" * 64, spec)
    db_session.expire_all()
    updated = db_session.get(ExtDatasourceCapacity, datasource_id)
    assert (updated.tier, updated.connection_budget, updated.max_query_concurrency) == (
        "small",
        4,
        2,
    )
    assert db_session.get(Datasource, datasource_id) is not None
    assert (
        db_session.execute(
            select(ExtDatasourceCapacity).where(
                ExtDatasourceCapacity.datasource_id == datasource_id
            )
        ).scalar_one()
        is updated
    )


def test_datasource_capacity_rejection_has_distinct_audit_category() -> None:
    assert pipeline.admission_rejection_kind("queue_full") == "permission_rejected"
    assert pipeline.admission_rejection_kind("datasource_busy") == "datasource_capacity_rejected"
