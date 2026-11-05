# SPDX-License-Identifier: GPL-3.0-or-later

"""Batch and persist asynchronous database writer commands.

Consume typed queue messages and commit them through the database wrapper.
"""

import asyncio
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from db_manager.constants import DATABASE_WRITE_BATCH
from db_manager.domain.models import (
    AffectedRecord,
    ConditionRecord,
    CveRecord,
    DatabaseCommand,
    DeleteCveRecord,
    ExploitRecord,
    FlushMarker,
    MetasploitRecord,
    MultiAffectedRecord,
    NvdPageBatch,
    ProductRecord,
    ReferencedExploitRecord,
    ReferencedMetasploitRecord,
    WorkerCommand,
)

from .storage import CveModel, Database


async def flush_database_commands(
    database: Database,
    commands: list[DatabaseCommand],
    *,
    page: NvdPageBatch | None = None,
) -> None:
    """Apply one queued batch through asynchronous SQLAlchemy operations.

    Args:
        database: Active asynchronous database session.
        commands: Typed database commands collected from API tasks.
        page: Optional page checkpoint committed with these commands.

    Raises:
        LookupError: If an association references a missing database record.
    """
    products = [
        command.identity
        for command in commands
        if isinstance(command, ProductRecord)
    ]
    cves = [
        CveModel(
            cve_id=command.cve_id,
            cvss_v2=command.cvss_v2,
            cvss_v3=command.cvss_v3,
            cvss_v4=command.cvss_v4,
            published=command.published,
        )
        for command in commands
        if isinstance(command, CveRecord)
    ]
    deleted_cves = [
        command.cve_id
        for command in commands
        if isinstance(command, DeleteCveRecord)
    ]
    exploits = [
        command.exploit_id
        for command in commands
        if isinstance(command, ExploitRecord)
    ]
    metasploit_names = [
        command.name
        for command in commands
        if isinstance(command, MetasploitRecord)
    ]
    affected = [
        (command.cve_id, command.identity)
        for command in commands
        if isinstance(command, AffectedRecord)
    ]
    multiaffected = [
        (command.cve_id, command.identity, command.bounds)
        for command in commands
        if isinstance(command, MultiAffectedRecord)
    ]
    conditions = [
        (
            command.cve_id,
            command.identity,
            command.config_idx,
            command.platform,
        )
        for command in commands
        if isinstance(command, ConditionRecord)
    ]
    referenced_exploits = [
        (command.cve_id, command.exploit_id)
        for command in commands
        if isinstance(command, ReferencedExploitRecord)
    ]
    referenced_metasploit = [
        (command.cve_id, command.module_name)
        for command in commands
        if isinstance(command, ReferencedMetasploitRecord)
    ]
    await database.insert_products(products)
    await database.remove_cves(deleted_cves)
    await database.insert_cves(cves)
    await database.insert_exploits(exploits)
    await database.insert_metasploits(metasploit_names)
    await database.insert_affected(affected)
    await database.insert_multiaffected(multiaffected)
    await database.insert_conditions(conditions)
    await database.insert_referenced_exploits(referenced_exploits)
    await database.insert_referenced_metasploits(referenced_metasploit)
    if page is not None:
        await database.mark_nvd_page(page.collection, page.start_index)
    await database.commit()


async def populate_database_worker(
    path: Path,
    queue: asyncio.Queue[WorkerCommand],
) -> None:
    """Consume producer commands and persist them asynchronously.

    Args:
        path: SQLite database file path.
        queue: Database write, flush, or stop commands.

    Raises:
        RuntimeError: If a SQLAlchemy write fails.
        LookupError: If an association references a missing database record.
    """
    pending: list[DatabaseCommand] = []
    try:
        async with Database(path) as database:
            await database.setup()
            while True:
                command = await queue.get()
                try:
                    if command is None:
                        if pending:
                            await flush_database_commands(database, pending)
                            pending.clear()
                        break
                    if isinstance(command, FlushMarker):
                        if pending:
                            await flush_database_commands(database, pending)
                            pending.clear()
                        command.event.set()
                        continue
                    if isinstance(command, NvdPageBatch):
                        if pending:
                            await flush_database_commands(database, pending)
                            pending.clear()
                        await flush_database_commands(
                            database, command.commands, page=command
                        )
                        continue
                    pending.append(command)
                    if len(pending) >= DATABASE_WRITE_BATCH:
                        await flush_database_commands(database, pending)
                        pending.clear()
                finally:
                    queue.task_done()
    except SQLAlchemyError as error:
        message = "The database writer failed"
        raise RuntimeError(message) from error


async def wait_for_writer_flush(
    queue: asyncio.Queue[WorkerCommand],
    writer_task: asyncio.Task[None],
) -> None:
    """Wait for the writer to commit commands preceding a flush marker.

    Args:
        queue: Asynchronous database write queue.
        writer_task: Asynchronous database writer task.

    Raises:
        RuntimeError: If the writer stops before committing the marker.
    """
    flush_event = asyncio.Event()
    await queue.put(FlushMarker(event=flush_event))
    flush_wait = asyncio.ensure_future(flush_event.wait())
    try:
        await asyncio.wait(
            {flush_wait, writer_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        flush_wait.cancel()
    if not flush_event.is_set():
        await writer_task
        message = "The database writer stopped before flushing"
        raise RuntimeError(message)
