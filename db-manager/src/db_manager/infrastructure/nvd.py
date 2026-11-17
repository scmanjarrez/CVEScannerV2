# SPDX-License-Identifier: GPL-3.0-or-later

"""Fetch and synchronize NVD catalogue and vulnerability records.

Validate paginated responses and queue their database records for writing.
"""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal

import httpx2
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from db_manager.constants import (
    CVSS_V3_METRIC_PATTERN,
    CVSS_V4_METRIC_KEY,
    EXPLOITDB_REFERENCE_PATTERN,
    HTTP_OK,
    NVD_API_URL,
    NVD_CPE_PAGE_SIZE,
    NVD_CVE_PAGE_SIZE,
    NVD_INCREMENTAL_WINDOW_DAYS,
    NVD_MAX_CONCURRENT_REQUESTS,
)
from db_manager.domain.cpe import parse_conditions, parse_node, split
from db_manager.domain.models import (
    AffectedRecord,
    AliasRecord,
    ConditionRecord,
    CpeIdentity,
    CveRecord,
    DatabaseArguments,
    DatabaseCommand,
    DeleteCveRecord,
    ExploitRecord,
    ImmutableModel,
    MultiAffectedRecord,
    NvdConfiguration,
    NvdCpe,
    NvdCpeResponse,
    NvdCve,
    NvdCveResponse,
    NvdMetadataResponse,
    NvdMetric,
    NvdPageBatch,
    NvdPageMetadataResponse,
    NvdReference,
    NvdSyncState,
    ProductRecord,
    ReferencedExploitRecord,
    WorkerCommand,
)

from .network import AsyncRateLimiter, get_with_retries
from .storage import Database
from .writer import wait_for_writer_flush

console = Console()

type RawEndpoint = Literal["cpes", "cves"]

RAW_ENDPOINTS: Final[tuple[RawEndpoint, ...]] = ("cpes", "cves")
RAW_COMPLETE_MARKER: Final[str] = "complete.json"
RAW_PAGE_NAME: Final[str] = "page-{start_index:08d}.json"


class RawScopeMarker(BaseModel):
    """Describe the completion marker of one raw NVD scope.

    Attributes:
        total_results: Number of NVD results stored in the scope.
        completed_at: UTC timestamp when the scope finished downloading.
    """

    total_results: int = Field(description="Number of NVD results stored.")
    completed_at: str = Field(
        description="UTC timestamp when the scope finished downloading.",
    )


@dataclass(frozen=True, slots=True)
class OfflineScope:
    """Locate one complete raw NVD scope on disk.

    Attributes:
        directory: Directory holding the scope's raw page files.
        name: Scope name, either 'full' or a 'modified-' window.
        marker: Completion marker that certifies the scope.
    """

    directory: Path
    name: str
    marker: RawScopeMarker


@dataclass(frozen=True, slots=True)
class RawScopeJob:
    """Describe how one raw NVD scope is written to the database.

    Attributes:
        endpoint: NVD collection endpoint of the scope.
        directory: Directory holding the scope's raw page files.
        total: Number of NVD results stored in the scope.
        page_size: Number of results stored per page file.
        collection: Stable key identifying the scope in the database.
        incremental: Whether the scope is a modified-date window.
        populate: Whether this scope builds the database from scratch.
    """

    endpoint: RawEndpoint
    directory: Path
    total: int
    page_size: int
    collection: str
    incremental: bool
    populate: bool


class NvdRequestContext(BaseModel):
    """Hold shared network and queue dependencies for one NVD update.

    Attributes:
        client: Shared asynchronous HTTP client.
        api_key: NVD API key sent in request headers.
        rate_limiter: Shared NVD request-start limiter.
        queue: Asynchronous database write queue.
        writer_task: Writer task monitored while waiting for durable pages.
        database: SQLite database holding imported data and checkpoints.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="forbid",
        frozen=True,
        strict=True,
    )

    client: httpx2.AsyncClient = Field(
        description="Shared asynchronous HTTP client."
    )
    api_key: str = Field(description="NVD API key sent in request headers.")
    rate_limiter: AsyncRateLimiter = Field(
        description="Shared NVD request-start limiter."
    )
    queue: asyncio.Queue[WorkerCommand] = Field(
        description="Asynchronous database write queue."
    )
    writer_task: asyncio.Task[None] = Field(
        description="Writer task monitored while waiting for page commits."
    )
    database: Path = Field(description="SQLite data and checkpoint file.")


class NvdCollectionRequest(ImmutableModel):
    """Describe one paginated NVD collection retrieval.

    Attributes:
        endpoint: NVD collection endpoint.
        total_results: Number of matching NVD results.
        page_size: Maximum number of results requested per page.
        extra: Additional query parameters.
        populate: Whether to build a database from scratch.
    """

    endpoint: Literal["cpes", "cves"] = Field(
        description="NVD collection endpoint."
    )
    total_results: int = Field(description="Number of matching NVD results.")
    page_size: int = Field(
        description="Maximum number of results requested per page."
    )
    extra: str = Field(description="Additional query parameters.")
    populate: bool = Field(
        description="Whether to build a database from scratch."
    )


class NvdPageRequest(ImmutableModel):
    """Describe one paginated NVD request.

    Attributes:
        url: Complete URL for the NVD page request.
        batch: Number of records expected from this page.
        endpoint: NVD collection endpoint.
        populate: Whether to build a database from scratch.
        collection: Stable endpoint, page size, and date filter query key.
        start_index: Page offset used to record durable completion.
    """

    url: str = Field(description="Complete URL for the NVD page request.")
    batch: int = Field(
        description="Number of records expected from this page."
    )
    endpoint: Literal["cpes", "cves"] = Field(
        description="NVD collection endpoint."
    )
    populate: bool = Field(
        description="Whether to build a database from scratch."
    )

    collection: str = Field(description="Stable NVD collection query key.")
    start_index: int = Field(ge=0, description="Zero-based NVD page offset.")


def now() -> str:
    """Return a UTC timestamp with millisecond precision for NVD.

    Returns:
        ISO 8601 timestamp ending in Z.
    """
    return (
        datetime.now(UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _alias_commands(
    identity: CpeIdentity,
    cpe: NvdCpe,
) -> list[DatabaseCommand]:
    """Build the rename records of one deprecated application CPE.

    Args:
        identity: Identity of the CPE catalog entry.
        cpe: Validated CPE catalog entry with its replacing names.

    Returns:
        One record per replacing application product whose vendor or
        product differs from the deprecated one.

    Raises:
        ValueError: If a replacing CPE name is unsupported or incomplete.
    """
    if not cpe.deprecated:
        return []
    aliases: dict[tuple[str, str], DatabaseCommand] = {}
    for replacement in cpe.deprecated_by:
        new = split(replacement.cpe_name)
        if new[0] != "a" or new[1:3] == identity[1:3]:
            continue
        aliases[(new[1], new[2])] = AliasRecord(
            old_vendor=identity[1],
            old_product=identity[2],
            old_version=identity[3],
            old_update=identity[4],
            new_vendor=new[1],
            new_product=new[2],
        )
    return list(aliases.values())


def cpe_commands(
    content: bytes,
    url: str,
) -> tuple[int, list[DatabaseCommand]]:
    """Validate one NVD CPE page and build its application product commands.

    Args:
        content: Response body returned by NVD.
        url: Requested page, used in validation errors.

    Returns:
        Number of records in the validated page, including non-applications,
        and the database commands for its application products.

    Raises:
        RuntimeError: If NVD returns invalid CPE data.
        ValueError: If a CPE name is unsupported or incomplete.
    """
    try:
        cpe_data = NvdCpeResponse.model_validate_json(content, strict=True)
    except ValidationError as error:
        message = f"NVD returned invalid CPE data: {url}"
        raise RuntimeError(message) from error

    commands: list[DatabaseCommand] = []
    for product_record in cpe_data.products:
        identity = split(product_record.cpe.cpe_name)
        if identity[0] == "a":
            commands.append(ProductRecord(identity=identity))
            commands.extend(_alias_commands(identity, product_record.cpe))
    return len(cpe_data.products), commands


def _cvss_metric_score(metrics: list[NvdMetric]) -> str | None:
    """Return the first CVSS score in a metric list.

    SSVC metrics share the NVD metrics object but have no cvssData field.

    Args:
        metrics: Validated metric entries for one metric family.

    Returns:
        First CVSS base score, or None when no CVSS entry exists.
    """
    for metric in metrics:
        if metric.cvss_data is not None:
            return str(metric.cvss_data.base_score)
    return None


def cvss_scores(
    cve: NvdCve,
) -> tuple[str | None, str | None, str | None]:
    """Return the first CVSS v2, v3 and v4 scores as database text values.

    NVD lists the Primary metric before the Secondary one, so the first
    entry with cvssData is used for each version.

    Args:
        cve: Validated CVE fields returned by NVD.

    Returns:
        CVSS v2, v3 and v4 scores, or None when a score is absent.
    """
    cvss_v2 = _cvss_metric_score(cve.metrics.get("cvssMetricV2", []))
    cvss_v3: str | None = None
    for key, metric_list in cve.metrics.items():
        if CVSS_V3_METRIC_PATTERN.match(key) is None:
            continue
        cvss_v3 = _cvss_metric_score(metric_list)
        if cvss_v3 is not None:
            break
    cvss_v4 = _cvss_metric_score(cve.metrics.get(CVSS_V4_METRIC_KEY, []))
    return cvss_v2, cvss_v3, cvss_v4


def _append_conditions(
    cve_id: str,
    config_idx: int,
    configuration: NvdConfiguration,
    commands: list[DatabaseCommand],
) -> None:
    """Append AND-condition pairs of one root configuration.

    Args:
        cve_id: CVE identifier owning the configuration.
        config_idx: Zero-based index of the root configuration.
        configuration: NVD product configuration to inspect.
        commands: Database commands receiving the new records.

    Raises:
        ValueError: If a CPE criteria string is unsupported or incomplete.
    """
    for product, platform in parse_conditions(configuration):
        if product[0] != "a":
            continue
        commands.append(ProductRecord(identity=product))
        commands.append(
            ConditionRecord(
                cve_id=cve_id,
                identity=product,
                config_idx=config_idx,
                platform=platform,
            )
        )


def _append_affected_products(
    cve_id: str,
    configurations: list[NvdConfiguration],
    commands: list[DatabaseCommand],
) -> None:
    """Append application products, CVE matches, and AND conditions.

    Args:
        cve_id: CVE identifier for the affected-product records.
        configurations: NVD product configurations attached to the CVE.
        commands: Database commands receiving the new records.

    Raises:
        ValueError: If a CPE criteria string is unsupported or incomplete.
    """
    for config_idx, configuration in enumerate(configurations):
        for node in configuration.nodes:
            for identity, bounds in parse_node(node):
                if identity[0] != "a":
                    continue
                commands.append(ProductRecord(identity=identity))
                if (
                    all(bound is None for bound in bounds)
                    and identity[3] != "*"
                ):
                    commands.append(
                        AffectedRecord(cve_id=cve_id, identity=identity)
                    )
                else:
                    commands.append(
                        MultiAffectedRecord(
                            cve_id=cve_id,
                            identity=identity,
                            bounds=bounds,
                        )
                    )
        _append_conditions(cve_id, config_idx, configuration, commands)


def _append_exploit_references(
    cve_id: str,
    references: list[NvdReference],
    commands: list[DatabaseCommand],
) -> None:
    """Append valid Exploit-DB identifiers and their CVE references.

    Args:
        cve_id: CVE identifier referencing the exploits.
        references: External references attached to the CVE.
        commands: Database commands receiving the new records.
    """
    for reference in references:
        if "exploit-db" not in reference.url:
            continue
        if "Broken Link" in reference.tags:
            continue
        match = EXPLOITDB_REFERENCE_PATTERN.match(reference.url)
        if match is not None:
            exploit_id = int(match.group(1))
            commands.append(ExploitRecord(exploit_id=exploit_id))
            commands.append(
                ReferencedExploitRecord(
                    cve_id=cve_id,
                    exploit_id=exploit_id,
                )
            )


def _append_cve_record(
    cve: NvdCve,
    commands: list[DatabaseCommand],
    *,
    populate: bool,
) -> None:
    """Append one CVE and its scores, affected products, and references.

    Args:
        cve: Validated CVE fields returned by NVD.
        commands: Database commands receiving the new records.
        populate: Whether a new database is being built.

    Raises:
        ValueError: If a CPE criteria string is unsupported or incomplete.
    """
    cve_id = cve.id
    if not populate:
        # NVD's modified feed also contains existing CVEs. Clear old
        # associations before rebuilding each CVE.
        commands.append(DeleteCveRecord(cve_id=cve_id))
    if cve.vuln_status.lower() in ("deferred", "rejected"):
        return

    cvss_v2, cvss_v3, cvss_v4 = cvss_scores(cve)
    commands.append(
        CveRecord(
            cve_id=cve_id,
            cvss_v2=cvss_v2,
            cvss_v3=cvss_v3,
            cvss_v4=cvss_v4,
            published=int(cve.published[:4]),
        )
    )
    _append_affected_products(cve_id, cve.configurations, commands)
    _append_exploit_references(cve_id, cve.references, commands)


def _cve_commands(
    content: bytes,
    url: str,
    *,
    populate: bool,
) -> tuple[int, list[DatabaseCommand]]:
    """Validate one NVD CVE page and build its vulnerability commands.

    Args:
        content: Response body returned by NVD.
        url: Requested page, used in validation errors.
        populate: Whether a new database is being built.

    Returns:
        Number of CVEs in the validated page, including skipped records,
        and the database commands for its vulnerability records.

    Raises:
        RuntimeError: If NVD returns invalid CVE data.
        ValueError: If a CPE criteria string is unsupported or incomplete.
    """
    try:
        cve_data = NvdCveResponse.model_validate_json(content, strict=True)
    except ValidationError as error:
        message = f"NVD returned invalid CVE data: {url}"
        raise RuntimeError(message) from error

    commands: list[DatabaseCommand] = []
    for vulnerability in cve_data.vulnerabilities:
        _append_cve_record(
            vulnerability.cve,
            commands,
            populate=populate,
        )
    return len(cve_data.vulnerabilities), commands


async def _query_api(
    request: NvdPageRequest,
    context: NvdRequestContext,
    semaphore: asyncio.Semaphore,
    progress: Progress,
    task_id: TaskID,
) -> None:
    """Fetch one NVD page asynchronously and queue its database rows.

    Args:
        request: NVD URL, page size, endpoint type, and population mode.
        context: Shared HTTP, rate-limit, and writer dependencies.
        semaphore: Maximum number of active NVD page requests.
        progress: Rich progress display for the current collection.
        task_id: Rich progress task tracking this collection.

    Raises:
        RuntimeError: If NVD times out, errors, or sends invalid JSON.
        ValueError: If NVD contains an unsupported CPE criteria string.
        httpx2.HTTPError: If the NVD request fails for another transport
            reason.
    """
    succeeded = False
    try:
        async with semaphore:
            try:
                response = await get_with_retries(
                    context.client,
                    request.url,
                    context.rate_limiter,
                    headers={"apiKey": context.api_key},
                )
            except httpx2.TimeoutException as error:
                message = f"NVD request timed out: {request.url}"
                raise RuntimeError(message) from error
            if response.status_code != HTTP_OK:
                message = (
                    f"NVD returned HTTP {response.status_code}: "
                    f"{response.text}"
                )
                raise RuntimeError(message)
            try:
                metadata = NvdPageMetadataResponse.model_validate_json(
                    response.content, strict=True
                )
            except ValidationError as error:
                message = f"NVD returned invalid page metadata: {request.url}"
                raise RuntimeError(message) from error
            if metadata.start_index != request.start_index:
                message = f"NVD returned a different page: {request.url}"
                raise RuntimeError(message)
            # Hand the writer a complete page, never half a CVE replacement.
            if request.endpoint == "cpes":
                count, commands = cpe_commands(
                    response.content,
                    request.url,
                )
            else:
                count, commands = _cve_commands(
                    response.content,
                    request.url,
                    populate=request.populate,
                )
            if count < request.batch:
                message = f"NVD returned an incomplete page: {request.url}"
                raise RuntimeError(message)
            await context.queue.put(
                NvdPageBatch(
                    collection=request.collection,
                    start_index=request.start_index,
                    commands=commands,
                )
            )
            await wait_for_writer_flush(context.queue, context.writer_task)
        succeeded = True
    finally:
        if succeeded:
            progress.update(task_id, advance=request.batch)


def _total_results(response: httpx2.Response, url: str) -> int:
    """Read and validate the total result count from an NVD response.

    Args:
        response: HTTP response containing NVD metadata.
        url: Request URL, included in error messages.

    Returns:
        Number of NVD results matching the request.

    Raises:
        RuntimeError: If NVD returns an error or invalid metadata.
    """
    if response.status_code != HTTP_OK:
        message = f"NVD returned HTTP {response.status_code}: {response.text}"
        raise RuntimeError(message)
    try:
        metadata = NvdMetadataResponse.model_validate_json(
            response.content,
            strict=True,
        )
    except ValidationError as error:
        message = f"NVD returned invalid metadata: {url}"
        raise RuntimeError(message) from error
    return metadata.total_results


async def _query_nvd_collection(
    request: NvdCollectionRequest,
    context: NvdRequestContext,
) -> None:
    """Fetch all pages for one NVD collection asynchronously.

    Args:
        request: Collection endpoint, paging, and population details.
        context: Shared HTTP, rate-limit, and writer dependencies.

    Raises:
        RuntimeError: If an NVD response is invalid or returns an error.
        httpx2.HTTPError: If an NVD request fails.
    """
    collection = (
        f"{NVD_API_URL.format(request.endpoint, 0)}"
        f"&resultsPerPage={request.page_size}{request.extra}"
    )
    async with Database(context.database) as database:
        completed = await database.prepare_nvd_collection(
            collection,
            request.total_results,
            request.page_size,
            incremental=bool(request.extra),
        )
    if completed:
        console.print(
            f"[cyan]Resuming {request.endpoint}: skipping "
            f"{len(completed)} committed pages.[/]"
        )
    if request.total_results == 0:
        return
    pages = [
        NvdPageRequest(
            url=(
                f"{NVD_API_URL.format(request.endpoint, start_index)}"
                f"&resultsPerPage={request.page_size}{request.extra}"
            ),
            batch=min(
                request.page_size,
                request.total_results - start_index,
            ),
            endpoint=request.endpoint,
            populate=request.populate,
            collection=collection,
            start_index=start_index,
        )
        for start_index in range(
            0,
            request.total_results,
            request.page_size,
        )
        if start_index not in completed
    ]
    description = (
        "CPEs from NVD" if request.endpoint == "cpes" else "CVEs from NVD"
    )
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(
            description,
            total=request.total_results,
            completed=sum(
                min(request.page_size, request.total_results - index)
                for index in completed
                if index < request.total_results
            ),
        )
        semaphore = asyncio.Semaphore(NVD_MAX_CONCURRENT_REQUESTS)
        async with asyncio.TaskGroup() as task_group:
            for page in pages:
                task_group.create_task(
                    _query_api(
                        page,
                        context,
                        semaphore,
                        progress,
                        task_id,
                    )
                )


async def _retrieve_nvd_pages(
    extra: str,
    context: NvdRequestContext,
    *,
    populate: bool,
) -> None:
    """Fetch NVD pages and queue their typed database records.

    Args:
        extra: Optional modified-date query parameters.
        context: Shared HTTP, rate-limit, and writer dependencies.
        populate: Whether to build a database from scratch.

    Raises:
        RuntimeError: If an NVD response is invalid or returns an error.
        httpx2.HTTPError: If an NVD request fails.
    """
    console.print("[bold cyan]Retrieving NVD catalogue metadata…[/]")
    cpe_metadata_url = (
        f"{NVD_API_URL.format('cpes', 0)}&resultsPerPage=1{extra}"
    )
    with console.status("Fetching NVD metadata…", spinner="dots"):
        cpe_metadata = await get_with_retries(
            context.client,
            cpe_metadata_url,
            context.rate_limiter,
            headers={"apiKey": context.api_key},
        )
        cpes = _total_results(cpe_metadata, cpe_metadata_url)
        cve_metadata_url = (
            f"{NVD_API_URL.format('cves', 0)}&resultsPerPage=1{extra}"
        )
        cve_metadata = await get_with_retries(
            context.client,
            cve_metadata_url,
            context.rate_limiter,
            headers={"apiKey": context.api_key},
        )
        cves = _total_results(cve_metadata, cve_metadata_url)
    metadata_table = Table(title="NVD catalogue size")
    metadata_table.add_column("Collection", style="cyan")
    metadata_table.add_column("Records", justify="right", style="green")
    metadata_table.add_row("CPEs", f"{cpes:,}")
    metadata_table.add_row("CVEs", f"{cves:,}")
    console.print(metadata_table)
    requests = [
        NvdCollectionRequest(
            endpoint="cpes",
            total_results=cpes,
            page_size=NVD_CPE_PAGE_SIZE,
            extra=extra,
            populate=populate,
        ),
        NvdCollectionRequest(
            endpoint="cves",
            total_results=cves,
            page_size=NVD_CVE_PAGE_SIZE,
            extra=extra,
            populate=populate,
        ),
    ]
    for request in requests:
        await _query_nvd_collection(request, context)


def _modified_date_queries(
    last: str,
    sync_time: str,
) -> list[str] | None:
    """Build bounded NVD update queries from a cached timestamp.

    Args:
        last: Timestamp from the database metadata.
        sync_time: Current UTC timestamp used as the query upper bound.

    Returns:
        Query parameters covering the interval, or None when the cached
        timestamp is invalid or later than the current synchronization time.
    """
    try:
        last_datetime = datetime.fromisoformat(last)
        sync_datetime = datetime.fromisoformat(sync_time)
    except ValueError:
        return None
    if last_datetime.tzinfo is None or sync_datetime.tzinfo is None:
        return None
    start_datetime = last_datetime.astimezone(UTC)
    end_datetime = sync_datetime.astimezone(UTC)
    if start_datetime > end_datetime:
        return None

    queries: list[str] = []
    window_start = start_datetime
    window_span = timedelta(days=NVD_INCREMENTAL_WINDOW_DAYS)
    while True:
        window_end = min(window_start + window_span, end_datetime)
        start_parameter = window_start.isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        end_parameter = window_end.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        queries.append(
            f"&lastModStartDate={start_parameter}"
            f"&lastModEndDate={end_parameter}"
        )
        if window_end == end_datetime:
            return queries
        window_start = window_end + timedelta(milliseconds=1)


async def update_db(
    args: DatabaseArguments,
    context: NvdRequestContext,
    *,
    populate: bool = False,
) -> str:
    """Fetch NVD pages and queue their database records asynchronously.

    Args:
        args: Database configuration containing the destination path.
        context: Shared HTTP, rate-limit, and writer dependencies.
        populate: Whether to build a database from scratch.

    Raises:
        RuntimeError: If an NVD response has an error or invalid metadata.
        httpx2.HTTPError: If an NVD request fails.

    Returns:
        UTC cutoff timestamp used for this synchronization.
    """
    async with Database(args.database) as database:
        pending = await database.pending_nvd_sync()
    extra_queries: list[str] = [""]
    sync_time = now()
    if pending is not None:
        sync_time = pending.sync_time
        extra_queries = pending.queries
        populate = False
        console.print(
            f"[bold cyan]Resuming NVD synchronization from {sync_time}…[/]"
        )
    elif not populate:
        console.print("[bold cyan]Checking for NVD updates…[/]")
        async with Database(args.database) as database:
            last = await database.cached_metadata()
        if last is None:
            console.print(
                "[yellow]No saved NVD timestamp; refreshing all records.[/]"
            )
        else:
            modified_queries = _modified_date_queries(last, sync_time)
            if modified_queries is None:
                console.print(
                    "[yellow]Cached timestamp cannot be used for an "
                    "incremental update; refreshing all records.[/]"
                )
            else:
                extra_queries = modified_queries
    else:
        console.print("[bold cyan]Creating a new database…[/]")

    if pending is None:
        async with Database(args.database) as database:
            await database.save_nvd_sync(
                NvdSyncState(sync_time=sync_time, queries=extra_queries)
            )

    for extra in extra_queries:
        await _retrieve_nvd_pages(
            extra=extra,
            context=context,
            populate=populate,
        )
    return sync_time


def _raw_page_size(endpoint: RawEndpoint) -> int:
    """Return the page size used when a raw scope was downloaded.

    Args:
        endpoint: NVD collection endpoint of the scope.

    Returns:
        Number of NVD results stored per page file.
    """
    if endpoint == "cpes":
        return NVD_CPE_PAGE_SIZE
    return NVD_CVE_PAGE_SIZE


def _scope_order(path: Path) -> tuple[bool, str]:
    """Sort key placing the 'full' scope before modified windows.

    Args:
        path: Scope directory to order.

    Returns:
        Tuple sorting 'full' first, then other scopes by name.
    """
    return (path.name != "full", path.name)


def _scope_directories(endpoint_dir: Path) -> list[Path]:
    """List the scope directories of one endpoint in import order.

    Args:
        endpoint_dir: Directory holding one endpoint's raw scopes.

    Returns:
        Subdirectories sorted with 'full' first, then by name.
    """
    directories = [path for path in endpoint_dir.iterdir() if path.is_dir()]
    return sorted(directories, key=_scope_order)


async def _load_scope(directory: Path) -> OfflineScope | None:
    """Read the completion marker of one raw scope directory.

    Args:
        directory: Scope directory that may hold a completion marker.

    Returns:
        The scope when its marker exists, or None when it is incomplete.

    Raises:
        RuntimeError: If the completion marker is malformed.
    """
    marker_path = directory / RAW_COMPLETE_MARKER
    if not await asyncio.to_thread(marker_path.is_file):
        console.print(f"[yellow]Skipping incomplete raw scope: {directory}[/]")
        return None
    content = await asyncio.to_thread(marker_path.read_bytes)
    try:
        marker = RawScopeMarker.model_validate_json(content, strict=True)
    except ValidationError as error:
        message = f"Invalid raw scope marker: {marker_path}"
        raise RuntimeError(message) from error
    return OfflineScope(
        directory=directory,
        name=directory.name,
        marker=marker,
    )


async def _complete_scopes(
    raw_dir: Path,
    endpoint: RawEndpoint,
) -> list[OfflineScope]:
    """List the complete raw scopes stored for one endpoint.

    Args:
        raw_dir: Root directory holding the raw NVD scopes.
        endpoint: NVD collection endpoint to inspect.

    Returns:
        Complete scopes in import order, empty when the endpoint is absent.
    """
    endpoint_dir = raw_dir / endpoint
    if not await asyncio.to_thread(endpoint_dir.is_dir):
        console.print(
            f"[yellow]Skipping missing raw endpoint: {endpoint_dir}[/]"
        )
        return []
    directories = await asyncio.to_thread(_scope_directories, endpoint_dir)
    scopes: list[OfflineScope] = []
    for directory in directories:
        scope = await _load_scope(directory)
        if scope is not None:
            scopes.append(scope)
    return scopes


def _scope_job(
    endpoint: RawEndpoint,
    scope: OfflineScope,
    *,
    populate: bool,
) -> RawScopeJob:
    """Build the import job for one complete raw scope.

    Args:
        endpoint: NVD collection endpoint of the scope.
        scope: Complete raw scope to import.
        populate: Whether the import builds the database from scratch.

    Returns:
        Import job describing the scope's pages and database key.
    """
    page_size = _raw_page_size(endpoint)
    return RawScopeJob(
        endpoint=endpoint,
        directory=scope.directory,
        total=scope.marker.total_results,
        page_size=page_size,
        collection=f"raw:{endpoint}/{scope.name}:{page_size}",
        incremental=scope.name != "full",
        populate=populate and scope.name == "full",
    )


def _validate_raw_page(content: bytes, start_index: int, url: str) -> None:
    """Check that a stored page describes the expected NVD offset.

    Args:
        content: Raw page bytes read from disk.
        start_index: Offset that the page file name promises.
        url: Page path, included in error messages.

    Raises:
        RuntimeError: If the page is invalid or describes another offset.
    """
    try:
        metadata = NvdPageMetadataResponse.model_validate_json(
            content,
            strict=True,
        )
    except ValidationError as error:
        message = f"NVD returned invalid page metadata: {url}"
        raise RuntimeError(message) from error
    if metadata.start_index != start_index:
        message = f"NVD returned a different page: {url}"
        raise RuntimeError(message)


def _raw_page_commands(
    job: RawScopeJob,
    content: bytes,
    url: str,
    start_index: int,
) -> list[DatabaseCommand]:
    """Convert one raw page into database commands.

    Args:
        job: Import job of the scope that holds the page.
        content: Validated raw page bytes.
        url: Page path, included in error messages.
        start_index: Offset of the page within the scope.

    Returns:
        Database commands produced by the page records.

    Raises:
        RuntimeError: If the page holds fewer records than expected.
        ValueError: If a CPE criteria string is unsupported or incomplete.
    """
    if job.endpoint == "cpes":
        count, commands = cpe_commands(content, url)
    else:
        count, commands = _cve_commands(
            content,
            url,
            populate=job.populate,
        )
    expected = min(job.page_size, job.total - start_index)
    if count < expected:
        message = f"NVD returned an incomplete page: {url}"
        raise RuntimeError(message)
    return commands


async def _read_raw_page(path: Path) -> bytes:
    """Read one stored raw page without blocking the event loop.

    Args:
        path: Location of the raw page file.

    Returns:
        Raw bytes of the stored page.

    Raises:
        RuntimeError: If the page file is missing.
    """
    if not await asyncio.to_thread(path.is_file):
        message = f"Raw NVD page is missing: {path}"
        raise RuntimeError(message)
    return await asyncio.to_thread(path.read_bytes)


async def _import_page(
    job: RawScopeJob,
    start_index: int,
    queue: asyncio.Queue[WorkerCommand],
    writer_task: asyncio.Task[None],
) -> None:
    """Import one raw page and wait until the writer commits it.

    Args:
        job: Import job of the scope that holds the page.
        start_index: Offset of the page within the scope.
        queue: Asynchronous database write queue.
        writer_task: Writer task monitored while waiting for the flush.
    """
    path = job.directory / RAW_PAGE_NAME.format(start_index=start_index)
    url = str(path)
    content = await _read_raw_page(path)
    _validate_raw_page(content, start_index, url)
    commands = _raw_page_commands(job, content, url, start_index)
    await queue.put(
        NvdPageBatch(
            collection=job.collection,
            start_index=start_index,
            commands=commands,
        )
    )
    await wait_for_writer_flush(queue, writer_task)


async def _import_scope(
    job: RawScopeJob,
    database: Path,
    queue: asyncio.Queue[WorkerCommand],
    writer_task: asyncio.Task[None],
) -> None:
    """Import every pending page of one raw scope with a progress bar.

    Args:
        job: Import job describing the scope.
        database: SQLite database receiving the imported records.
        queue: Asynchronous database write queue.
        writer_task: Writer task monitored while waiting for flushes.
    """
    async with Database(database) as storage:
        completed = await storage.prepare_nvd_collection(
            job.collection,
            job.total,
            job.page_size,
            incremental=job.incremental,
        )
    if completed:
        console.print(
            f"[cyan]Resuming {job.collection}: skipping "
            f"{len(completed)} committed pages.[/]"
        )
    starts = [
        start_index
        for start_index in range(0, job.total, job.page_size)
        if start_index not in completed
    ]
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(
            job.collection,
            total=job.total,
            completed=sum(
                min(job.page_size, job.total - index)
                for index in completed
                if index < job.total
            ),
        )
        for start_index in starts:
            await _import_page(job, start_index, queue, writer_task)
            progress.update(
                task_id,
                advance=min(job.page_size, job.total - start_index),
            )


async def update_db_offline(
    args: DatabaseArguments,
    raw_dir: Path,
    queue: asyncio.Queue[WorkerCommand],
    writer_task: asyncio.Task[None],
    *,
    populate: bool,
) -> str:
    """Import complete raw NVD scopes from disk into the database.

    Reads the scopes written by the raw download step without network
    access. Pages committed by an earlier run are skipped.

    Args:
        args: Database configuration containing the destination path.
        raw_dir: Root directory holding the raw NVD scopes.
        queue: Asynchronous database write queue.
        writer_task: Writer task monitored while waiting for flushes.
        populate: Whether to build a database from scratch.

    Raises:
        RuntimeError: If no complete scope exists or a page is invalid.

    Returns:
        Earliest completion timestamp among the imported scopes.
    """
    scopes: list[tuple[RawEndpoint, OfflineScope]] = []
    for endpoint in RAW_ENDPOINTS:
        found = await _complete_scopes(raw_dir, endpoint)
        scopes.extend((endpoint, scope) for scope in found)
    if not scopes:
        message = f"No complete raw NVD scope found: {raw_dir}"
        raise RuntimeError(message)
    for endpoint, scope in scopes:
        job = _scope_job(endpoint, scope, populate=populate)
        await _import_scope(job, args.database, queue, writer_task)
    return min(scope.marker.completed_at for _, scope in scopes)
