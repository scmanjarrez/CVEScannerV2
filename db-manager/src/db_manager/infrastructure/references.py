# SPDX-License-Identifier: GPL-3.0-or-later

"""Synchronize Metasploit and Exploit-DB reference data.

Fetch module references and optionally refresh Exploit-DB titles.
"""

import asyncio
import html
from collections.abc import Iterator
from http import HTTPStatus
from typing import NamedTuple

import httpx2
from fake_useragent import UserAgent
from pydantic import ValidationError
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)

from db_manager.constants import (
    EXPLOITDB_BATCH_SIZE,
    EXPLOITDB_GENERIC_TITLES,
    EXPLOITDB_MAX_CONCURRENT_REQUESTS,
    EXPLOITDB_TITLE_PATTERN,
    EXPLOITDB_URL,
    METASPLOIT_CVE_PATTERN,
    METASPLOIT_METADATA_URL,
)
from db_manager.domain.models import (
    DatabaseArguments,
    MetasploitCache,
    MetasploitRecord,
    ReferencedMetasploitRecord,
    WorkerCommand,
)

from .network import AsyncRateLimiter, get_with_retries
from .storage import Database

console = Console()
user_agent = UserAgent()


class ScrapedTitle(NamedTuple):
    """Result of one Exploit-DB title request.

    Attributes:
        exploit_id: Exploit-DB numeric identifier.
        title: Usable title, or None when missing or generic.
        gone: Whether Exploit-DB answered 404 for the exploit.
    """

    exploit_id: int
    title: str | None
    gone: bool


async def update_metasploit(
    args: DatabaseArguments,
    queue: asyncio.Queue[WorkerCommand],
    client: httpx2.AsyncClient,
    rate_limiter: AsyncRateLimiter,
) -> None:
    """Queue Metasploit modules and references using async database queries.

    Args:
        args: Database configuration containing the destination path.
        queue: Asynchronous database write queue.
        client: Shared asynchronous HTTP client.
        rate_limiter: Metasploit request-start limiter.

    Raises:
        RuntimeError: If Metasploit metadata is invalid or incomplete.
        httpx2.HTTPError: If the metadata request fails.
    """
    page = await get_with_retries(
        client,
        METASPLOIT_METADATA_URL,
        rate_limiter,
    )
    page.raise_for_status()
    try:
        cache = MetasploitCache.model_validate_json(
            page.content,
            strict=True,
        )
    except ValidationError as error:
        message = "Metasploit returned invalid JSON data"
        raise RuntimeError(message) from error

    module_references: list[tuple[str, str]] = []
    cve_ids: set[str] = set()
    for module in cache.root.values():
        await queue.put(MetasploitRecord(name=module.fullname))
        for reference in module.references:
            if METASPLOIT_CVE_PATTERN.fullmatch(reference) is not None:
                module_references.append((reference, module.fullname))
                cve_ids.add(reference)

    async with Database(args.database) as database:
        existing_cves = await database.cached_cves(cve_ids)
    for cve_id, module_name in module_references:
        if cve_id in existing_cves:
            await queue.put(
                ReferencedMetasploitRecord(
                    cve_id=cve_id,
                    module_name=module_name,
                )
            )


async def scrape_title(
    exploit: int,
    client: httpx2.AsyncClient,
    rate_limiter: AsyncRateLimiter,
    semaphore: asyncio.Semaphore,
) -> ScrapedTitle:
    """Fetch an Exploit-DB title asynchronously.

    A 404 response marks the exploit as gone. Generic site titles are
    returned as None so they are not stored as exploit names.

    Args:
        exploit: Exploit-DB numeric identifier.
        client: Shared asynchronous HTTP client.
        rate_limiter: Shared Exploit-DB request-start limiter.
        semaphore: Maximum number of active Exploit-DB requests.

    Returns:
        The scraped result with the usable title and the gone flag.

    Raises:
        RuntimeError: If the Exploit-DB request fails with another error.
    """
    try:
        async with semaphore:
            page = await get_with_retries(
                client,
                f"{EXPLOITDB_URL}/{exploit}",
                rate_limiter,
                headers={"User-Agent": user_agent.random},
            )
            if page.status_code == HTTPStatus.NOT_FOUND:
                return ScrapedTitle(exploit, None, gone=True)
            page.raise_for_status()
            decoded = html.unescape(page.text)
            title_match = EXPLOITDB_TITLE_PATTERN.search(decoded)
            title = title_match.group(3) if title_match is not None else None
            if title in EXPLOITDB_GENERIC_TITLES:
                title = None
    except httpx2.HTTPError as error:
        message = f"Exploit-DB request failed for exploit {exploit}"
        raise RuntimeError(message) from error
    return ScrapedTitle(exploit, title, gone=False)


def exploit_batch(exploits: list[int]) -> Iterator[list[int]]:
    """Yield fixed-size batches of Exploit-DB identifiers.

    Args:
        exploits: Exploit-DB identifiers to split into batches.

    Returns:
        Iterator yielding consecutive slices of the identifier list.
    """
    for i in range(0, len(exploits), EXPLOITDB_BATCH_SIZE):
        yield exploits[i : i + EXPLOITDB_BATCH_SIZE]


async def update_exploitdb(
    args: DatabaseArguments,
    client: httpx2.AsyncClient,
    rate_limiter: AsyncRateLimiter,
) -> None:
    """Refresh Exploit-DB titles with asynchronous HTTP and database calls.

    Args:
        args: Database path and scraping configuration.
        client: Shared asynchronous HTTP client.
        rate_limiter: Shared Exploit-DB request-start limiter.

    Raises:
        RuntimeError: If an Exploit-DB request fails.
        SQLAlchemyError: If a database operation fails.
    """
    async with Database(args.database) as database:
        await database.clean()
        if not args.skip_scrape:
            exploits = await database.cached_exploits()
        else:
            exploits = []

    if not exploits:
        if args.skip_scrape:
            console.print("[dim]Exploit-DB title scraping skipped.[/]")
        else:
            console.print("[dim]No Exploit-DB titles need refreshing.[/]")
        return

    semaphore = asyncio.Semaphore(EXPLOITDB_MAX_CONCURRENT_REQUESTS)
    removed_total = 0
    total_batches = (
        len(exploits) + EXPLOITDB_BATCH_SIZE - 1
    ) // EXPLOITDB_BATCH_SIZE
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Exploit-DB titles", total=total_batches)
        for batch in exploit_batch(exploits):
            results = await asyncio.gather(
                *(
                    scrape_title(
                        exploit_id,
                        client,
                        rate_limiter,
                        semaphore,
                    )
                    for exploit_id in batch
                )
            )
            gone_ids = [result.exploit_id for result in results if result.gone]
            updates = [
                (result.exploit_id, result.title)
                for result in results
                if result.title is not None
            ]
            async with Database(args.database) as database:
                await database.remove_exploits(gone_ids)
                await database.update_exploits(updates)
            removed_total += len(gone_ids)
            progress.update(task_id, advance=1)
    if removed_total > 0:
        console.print(
            f"Removed {removed_total} Exploit-DB records",
            "that no longer exist.",
            style="yellow",
        )
