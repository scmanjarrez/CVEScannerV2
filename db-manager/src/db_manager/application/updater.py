# SPDX-License-Identifier: GPL-3.0-or-later

"""Coordinate the NVD, reference, and database writer update stages.

Manage shared resources and run the complete database update workflow.
"""

import asyncio
import os
from pathlib import Path

import httpx2
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from db_manager.constants import (
    COPYRIGHT,
    EXPLOITDB_MAX_CONCURRENT_REQUESTS,
    EXPLOITDB_REQUEST_INTERVAL,
    HTTP_TIMEOUT_SECONDS,
    METASPLOIT_REQUEST_INTERVAL,
    NVD_REQUEST_INTERVAL,
)
from db_manager.domain.models import DatabaseArguments, WorkerCommand
from db_manager.infrastructure.network import AsyncRateLimiter
from db_manager.infrastructure.nvd import (
    NvdRequestContext,
    update_db,
    update_db_offline,
)
from db_manager.infrastructure.references import (
    update_exploitdb,
    update_metasploit,
)
from db_manager.infrastructure.storage import Database
from db_manager.infrastructure.writer import (
    populate_database_worker,
    wait_for_writer_flush,
)

console = Console()


def _read_api_key() -> str:
    """Read the NVD API key from the current directory or environment.

    Returns:
        The configured NVD API key.

    Raises:
        RuntimeError: If no API key is configured.
    """
    api_file = Path(".api")
    nvd_key = api_file.read_text().strip() if api_file.is_file() else ""
    if not nvd_key:
        nvd_key = os.getenv("NVD_KEY", "").strip()
    if not nvd_key:
        message = "NVD API key required; see README.md for configuration"
        raise RuntimeError(message)
    return nvd_key


async def _ensure_raw_dir(raw_dir: Path) -> None:
    """Verify that the raw NVD directory exists.

    Args:
        raw_dir: Directory with raw NVD pages to import offline.

    Raises:
        RuntimeError: If the directory does not exist.
    """
    is_dir = await asyncio.to_thread(raw_dir.is_dir)
    if not is_dir:
        message = f"NVD raw directory not found: {raw_dir}"
        raise RuntimeError(message)


async def run_database(args: DatabaseArguments) -> None:
    """Create or update the CVE scanner database.

    Args:
        args: Database path and scraping configuration.

    Raises:
        RuntimeError: If an NVD, Metasploit, or database operation fails.
    """
    console.print(
        Panel.fit(
            Text(COPYRIGHT, justify="center"),
            title="CVEScannerV2 database updater",
            border_style="cyan",
        )
    )
    console.print(Text(f"Database path: {args.database}", style="dim"))

    if args.nvd_raw is None:
        api_key = await asyncio.to_thread(_read_api_key)
    else:
        await _ensure_raw_dir(args.nvd_raw)
        api_key = ""
        console.print(Text(f"Raw NVD directory: {args.nvd_raw}", style="dim"))

    await asyncio.to_thread(
        args.database.parent.mkdir, parents=True, exist_ok=True
    )
    database_exists = await asyncio.to_thread(args.database.is_file)
    populate = not database_exists
    async with Database(args.database) as database:
        await database.setup()

    async with httpx2.AsyncClient(
        timeout=HTTP_TIMEOUT_SECONDS,
        limits=httpx2.Limits(
            max_connections=EXPLOITDB_MAX_CONCURRENT_REQUESTS + 1,
            max_keepalive_connections=EXPLOITDB_MAX_CONCURRENT_REQUESTS + 1,
        ),
    ) as client:
        worker_queue: asyncio.Queue[WorkerCommand] = asyncio.Queue()
        writer_task = asyncio.create_task(
            populate_database_worker(args.database, worker_queue)
        )
        nvd_rate_limiter = AsyncRateLimiter(NVD_REQUEST_INTERVAL)
        metasploit_rate_limiter = AsyncRateLimiter(METASPLOIT_REQUEST_INTERVAL)
        exploitdb_rate_limiter = AsyncRateLimiter(EXPLOITDB_REQUEST_INTERVAL)
        try:
            if args.nvd_raw is None:
                nvd_context = NvdRequestContext(
                    client=client,
                    api_key=api_key,
                    rate_limiter=nvd_rate_limiter,
                    queue=worker_queue,
                    writer_task=writer_task,
                    database=args.database,
                )
                sync_time = await update_db(
                    args,
                    nvd_context,
                    populate=populate,
                )
            else:
                sync_time = await update_db_offline(
                    args,
                    args.nvd_raw,
                    worker_queue,
                    writer_task,
                    populate=populate,
                )
            await wait_for_writer_flush(worker_queue, writer_task)
            with console.status(
                "Fetching Metasploit reference data…",
                spinner="dots",
            ):
                await update_metasploit(
                    args,
                    worker_queue,
                    client,
                    metasploit_rate_limiter,
                )
        finally:
            if not writer_task.done():
                await worker_queue.put(None)
            await writer_task

        await update_exploitdb(args, client, exploitdb_rate_limiter)
    async with Database(args.database) as database:
        await database.update_metadata(sync_time)
        await database.clear_nvd_sync()
    console.print(
        Text.assemble(
            ("Database update completed.", "bold green"),
            (f" {args.database}", "dim"),
        )
    )
