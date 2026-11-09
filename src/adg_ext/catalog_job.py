"""Background catalog scans.

The remote database is read with no control-plane connection checked out. Each database is then
committed on its own. ``POST .../rescan`` returns the current job; the management service polls.
A datasource-account PUT still waits for its own scan so the role synced next can see the tables.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from adg.app.log_config import kv
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError
from adg.connectors.registry import ConnectorRegistry
from adg.control_plane.services.metadata_scan_service import CatalogGone, persist_snapshot
from adg.runtime_cache import refresh_catalog
from adg_ext.sync import (
    ExtSyncError,
    SyncService,
    connector_target,
    fit_snapshot,
)

logger = logging.getLogger(__name__)

_STALE_SECONDS = 2 * 60 * 60


class ScanSuperseded(Exception):
    """This worker lost the single-flight slot to a newer scan."""


@dataclass
class _Job:
    generation: int
    status: str
    pending: bool
    database: str | None
    databases_done: int
    databases_total: int
    resources: int
    fields: int
    error: str | None
    updated_at: float


class CatalogJobs:
    """One running scan per datasource account. A second request runs after the current one."""

    def __init__(
        self, session_factory: sessionmaker[Session], registry: ConnectorRegistry
    ) -> None:
        self._factory = session_factory
        self._registry = registry
        self._lock = threading.Lock()
        self._jobs: dict[str, _Job] = {}
        self._running: set[str] = set()

    def kick(self, name: str) -> dict[str, object]:
        with self._lock:
            self._expire(name)
            job = self._jobs.get(name)
            if name in self._running and job is not None:
                job.pending = True
                job.updated_at = time.time()
                return _view(job)
            generation = 1 if job is None else job.generation + 1
            job = _Job(
                generation=generation,
                status="queued",
                pending=False,
                database=None,
                databases_done=0,
                databases_total=0,
                resources=0,
                fields=0,
                error=None,
                updated_at=time.time(),
            )
            self._jobs[name] = job
            self._running.add(name)
            threading.Thread(
                target=self._run,
                args=(name, generation),
                name=f"catalog-scan-{name}",
                daemon=True,
            ).start()
            return _view(job)

    def get(self, name: str) -> dict[str, object] | None:
        with self._lock:
            self._expire(name)
            job = self._jobs.get(name)
            return None if job is None else _view(job)

    def _expire(self, name: str) -> None:
        job = self._jobs.get(name)
        if job is None or name not in self._running:
            return
        if time.time() - job.updated_at <= _STALE_SECONDS:
            return
        job.generation += 1
        job.status = "failed"
        job.error = "scan timed out"
        job.updated_at = time.time()
        self._running.discard(name)

    def _owns(self, name: str, generation: int) -> bool:
        with self._lock:
            job = self._jobs.get(name)
            return job is not None and job.generation == generation and name in self._running

    def _run(self, name: str, generation: int) -> None:
        while self._owns(name, generation):
            try:
                with self._lock:
                    job = self._jobs[name]
                    job.pending = False
                    job.status = "reading"
                    job.error = None
                    job.database = None
                    job.databases_done = 0
                    job.databases_total = 0
                    job.updated_at = time.time()
                self._execute(name, generation)
            except ScanSuperseded:
                return
            except Exception as error:
                logger.warning(
                    kv(
                        event="catalog_scan_failed",
                        datasource=name,
                        error=type(error).__name__,
                    )
                )
                with self._lock:
                    current = self._jobs.get(name)
                    if current is None or current.generation != generation:
                        return
                    if current.pending:
                        continue
                    current.status = "failed"
                    current.error = "cannot scan datasource"
                    current.updated_at = time.time()
                    self._running.discard(name)
                    return
            else:
                with self._lock:
                    current = self._jobs.get(name)
                    if current is None or current.generation != generation:
                        return
                    if current.pending:
                        continue
                    current.status = "completed"
                    current.database = None
                    current.updated_at = time.time()
                    self._running.discard(name)
                    return

    def _execute(self, name: str, generation: int) -> None:
        started = time.perf_counter()
        with self._factory() as session:
            service = SyncService(session, self._registry)
            datasource = service._datasource_for(service._find("datasource_account", name))
            if datasource is None:
                raise ExtSyncError(404, f"datasource_account {name} has not been synced")
            config = datasource.config()
            connector_type = datasource.type
            datasource_id = datasource.id
        connector = self._registry.create(connector_type)
        try:
            snapshot = fit_snapshot(connector.scan_metadata(config), name)
        except (ConnectorDependencyError, ConnectorOperationError):
            raise
        databases = snapshot.get("databases") or []
        total = len(databases) if isinstance(databases, list) else 0

        def progress(index: int, count: int, database: str) -> None:
            if not self._owns(name, generation):
                raise ScanSuperseded()
            with self._lock:
                job = self._jobs[name]
                job.status = "writing"
                job.database = database
                job.databases_done = index
                job.databases_total = count
                job.updated_at = time.time()

        try:
            counts = persist_snapshot(self._factory, datasource_id, snapshot, progress)
        except CatalogGone:
            logger.info(kv(event="catalog_scan_skipped", datasource=name, reason="deleted"))
            return
        with self._factory() as session:
            refresh_catalog(session, datasource_id)
        with self._lock:
            job = self._jobs.get(name)
            if job is not None and job.generation == generation:
                job.resources = int(counts["resources"])
                job.fields = int(counts["fields"])
                job.databases_done = total
                job.databases_total = total
                job.updated_at = time.time()
        logger.info(
            kv(
                event="catalog_scanned",
                datasource=name,
                engine=connector_type,
                ms=int((time.perf_counter() - started) * 1000),
                resources=counts["resources"],
                fields=counts["fields"],
            )
        )


def scan_account_spec(
    spec: dict[str, Any], name: str, registry: ConnectorRegistry
) -> dict[str, Any]:
    """Read the live catalog for a PUT without holding a control-plane connection."""

    connector_type, config = connector_target(spec)
    connector = registry.create(connector_type)
    try:
        snapshot = connector.scan_metadata(config)
    except (ConnectorDependencyError, ConnectorOperationError) as error:
        raise ExtSyncError(409, f"cannot scan datasource {name}: {error}") from error
    return fit_snapshot(snapshot, name)


def _view(job: _Job) -> dict[str, object]:
    body: dict[str, object] = {
        "status": job.status,
        "pending": job.pending,
        "databasesDone": job.databases_done,
        "databasesTotal": job.databases_total,
        "resources": job.resources,
        "fields": job.fields,
    }
    if job.database is not None:
        body["database"] = job.database
    if job.error is not None:
        body["error"] = job.error
    return body
