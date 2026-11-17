# SPDX-License-Identifier: GPL-3.0-or-later

"""Store raw NVD API pages in a local directory tree.

Save paginated CVE and CPE responses byte for byte. Pages already on disk
are not requested again, and a finished query window is marked complete so
later runs skip it, which lets interrupted downloads resume.
"""

import asyncio
import json
import math
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal

import httpx2
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
    HTTP_OK,
    HTTP_TIMEOUT_SECONDS,
    NVD_API_URL,
    NVD_CPE_PAGE_SIZE,
    NVD_CVE_PAGE_SIZE,
    NVD_INCREMENTAL_WINDOW_DAYS,
    NVD_REQUEST_INTERVAL,
    NVD_REQUEST_INTERVAL_WITHOUT_KEY,
)
from db_manager.domain.models import NvdPageMetadataResponse
from db_manager.infrastructure.network import (
    AsyncRateLimiter,
    get_with_retries,
)

NvdEndpoint = Literal["cves", "cpes"]

DEFAULT_ENDPOINTS: Final[tuple[NvdEndpoint, ...]] = ("cves", "cpes")
PAGE_SIZES: Final[dict[NvdEndpoint, int]] = {
    "cves": NVD_CVE_PAGE_SIZE,
    "cpes": NVD_CPE_PAGE_SIZE,
}
COMPLETE_MARKER: Final[str] = "complete.json"
API_KEY_FILE: Final[Path] = Path(".api")

console = Console()


@dataclass(frozen=True, slots=True)
class RawDownloadArguments:
    """Describe which NVD pages to store and where.

    Attributes:
        output: Root directory receiving the downloaded pages.
        since: UTC start of the modification window, or None for a full
            snapshot.
        endpoints: NVD endpoints to download, in order.
    """

    output: Path
    since: datetime | None
    endpoints: tuple[NvdEndpoint, ...]


@dataclass(frozen=True, slots=True)
class QueryScope:
    """Name one NVD query window and its storage directory.

    Attributes:
        name: Directory name holding the pages of this window.
        query: Extra NVD query parameters, empty or starting with '&'.
    """

    name: str
    query: str


@dataclass(frozen=True, slots=True)
class NvdSession:
    """Hold the shared HTTP dependencies for one download run.

    Attributes:
        client: Shared asynchronous HTTP client.
        limiter: Request-start limiter for NVD.
        api_key: Optional NVD API key sent in request headers.
    """

    client: httpx2.AsyncClient
    limiter: AsyncRateLimiter
    api_key: str | None


def _nvd_timestamp(value: datetime) -> str:
    """Format a datetime as the UTC timestamp expected by NVD.

    Args:
        value: Timezone-aware datetime.

    Returns:
        ISO 8601 timestamp with milliseconds and a 'Z' suffix.
    """
    return (
        value.astimezone(UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _file_stamp(value: datetime) -> str:
    """Format a datetime as a compact, filesystem-safe UTC stamp.

    Args:
        value: Timezone-aware datetime.

    Returns:
        Stamp such as '20240101T000000Z'.
    """
    return value.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def _query_scopes(since: datetime | None, until: datetime) -> list[QueryScope]:
    """Split the requested modification interval into NVD query windows.

    Args:
        since: UTC start of the interval, or None for a full snapshot.
        until: UTC end of the interval.

    Returns:
        A single unfiltered scope for a full snapshot, or consecutive
        windows of at most NVD_INCREMENTAL_WINDOW_DAYS days each.
    """
    if since is None:
        return [QueryScope(name="full", query="")]
    span = timedelta(days=NVD_INCREMENTAL_WINDOW_DAYS)
    scopes: list[QueryScope] = []
    start = since
    while True:
        end = min(start + span, until)
        scopes.append(
            QueryScope(
                name=f"modified-{_file_stamp(start)}-{_file_stamp(end)}",
                query=(
                    f"&lastModStartDate={_nvd_timestamp(start)}"
                    f"&lastModEndDate={_nvd_timestamp(end)}"
                ),
            )
        )
        if end == until:
            return scopes
        start = end + timedelta(milliseconds=1)


def _page_url(
    endpoint: NvdEndpoint,
    start_index: int,
    scope: QueryScope,
) -> str:
    """Build the NVD URL for one page of a query scope.

    Args:
        endpoint: NVD collection to query.
        start_index: Zero-based offset of the page.
        scope: Query window applied to the request.

    Returns:
        Complete request URL with page size and window parameters.
    """
    page_size = PAGE_SIZES[endpoint]
    return (
        f"{NVD_API_URL.format(endpoint, start_index)}"
        f"&resultsPerPage={page_size}{scope.query}"
    )


def _page_path(directory: Path, start_index: int) -> Path:
    """Return the file path that stores one raw NVD page.

    Args:
        directory: Storage directory of the query scope.
        start_index: Zero-based offset of the page.

    Returns:
        Path such as 'page-00002000.json'.
    """
    return directory / f"page-{start_index:08d}.json"


def _read_api_key() -> str | None:
    """Read the optional NVD API key from the working directory or environment.

    Returns:
        The configured key, or None when no key is available.
    """
    key = API_KEY_FILE.read_text().strip() if API_KEY_FILE.is_file() else ""
    return key or os.getenv("NVD_KEY", "").strip() or None


def _write_atomic(path: Path, content: bytes) -> None:
    """Write a file through a partial file so readers never see halves.

    Args:
        path: Destination file path.
        content: Bytes to store.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(".part")
    partial.write_bytes(content)
    partial.replace(path)


def _parse_page(
    content: bytes,
    start_index: int,
    url: str,
) -> NvdPageMetadataResponse:
    """Validate that a raw response is the NVD page that was requested.

    Args:
        content: Raw JSON body returned by NVD.
        start_index: Offset that the request asked for.
        url: Request URL, included in error messages.

    Returns:
        Validated page metadata.

    Raises:
        RuntimeError: If the body is invalid or describes another page.
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
    return metadata


async def _fetch_page(session: NvdSession, url: str) -> bytes:
    """Request one NVD page and return its raw body.

    Args:
        session: Shared HTTP client, limiter, and API key.
        url: Request URL for the page.

    Returns:
        Raw response body, not yet validated.

    Raises:
        RuntimeError: If NVD times out or returns a non-success status.
        httpx2.HTTPError: If the request fails for another transport reason.
    """
    headers = {"apiKey": session.api_key} if session.api_key else None
    try:
        response = await get_with_retries(
            session.client,
            url,
            session.limiter,
            headers=headers,
        )
    except httpx2.TimeoutException as error:
        message = f"NVD request timed out: {url}"
        raise RuntimeError(message) from error
    if response.status_code != HTTP_OK:
        message = f"NVD returned HTTP {response.status_code}: {response.text}"
        raise RuntimeError(message)
    return response.content


async def _is_file(path: Path) -> bool:
    """Check whether a path is a regular file without blocking the loop.

    Args:
        path: Path to inspect.

    Returns:
        True when the path exists and is a regular file.
    """
    return await asyncio.to_thread(path.is_file)


async def _store_page(
    path: Path,
    url: str,
    start_index: int,
    session: NvdSession,
) -> int:
    """Save one NVD page unless it is already stored locally.

    Args:
        path: File that stores the raw page.
        url: Request URL used when the page is missing.
        start_index: Offset of the page.
        session: Shared HTTP client, limiter, and API key.

    Returns:
        Total number of results reported by the stored page.
    """
    if await _is_file(path):
        content = await asyncio.to_thread(path.read_bytes)
        return _parse_page(content, start_index, url).total_results
    content = await _fetch_page(session, url)
    metadata = _parse_page(content, start_index, url)
    await asyncio.to_thread(_write_atomic, path, content)
    return metadata.total_results


async def _download_scope(
    session: NvdSession,
    endpoint: NvdEndpoint,
    scope: QueryScope,
    output: Path,
    progress: Progress,
) -> None:
    """Store every page of one query scope and mark it complete.

    Args:
        session: Shared HTTP client, limiter, and API key.
        endpoint: NVD collection to query.
        scope: Query window to download.
        output: Root directory receiving the downloaded pages.
        progress: Rich progress display shared by all scopes.
    """
    directory = output / endpoint / scope.name
    if await _is_file(directory / COMPLETE_MARKER):
        console.print(f"[dim]Skipping {endpoint}/{scope.name}: complete[/]")
        return
    page_size = PAGE_SIZES[endpoint]
    total = await _store_page(
        _page_path(directory, 0),
        _page_url(endpoint, 0, scope),
        0,
        session,
    )
    page_count = max(1, math.ceil(total / page_size))
    task = progress.add_task(
        f"{endpoint}/{scope.name}",
        total=page_count,
        completed=1,
    )
    for index in range(1, page_count):
        start_index = index * page_size
        path = _page_path(directory, start_index)
        if not await _is_file(path):
            await _store_page(
                path,
                _page_url(endpoint, start_index, scope),
                start_index,
                session,
            )
        progress.advance(task)
    marker = json.dumps(
        {
            "total_results": total,
            "completed_at": _nvd_timestamp(datetime.now(UTC)),
        }
    )
    await asyncio.to_thread(
        _write_atomic,
        directory / COMPLETE_MARKER,
        marker.encode(),
    )


async def run_raw_download(args: RawDownloadArguments) -> None:
    """Store the requested raw NVD pages in the output directory.

    Args:
        args: Output directory, modification window, and endpoints.
    """
    api_key = await asyncio.to_thread(_read_api_key)
    interval = (
        NVD_REQUEST_INTERVAL if api_key else NVD_REQUEST_INTERVAL_WITHOUT_KEY
    )
    scopes = _query_scopes(args.since, datetime.now(UTC))
    console.print(f"[dim]Output directory: {args.output}[/]")
    async with httpx2.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        session = NvdSession(
            client=client,
            limiter=AsyncRateLimiter(interval),
            api_key=api_key,
        )
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            for endpoint in args.endpoints:
                for scope in scopes:
                    await _download_scope(
                        session,
                        endpoint,
                        scope,
                        args.output,
                        progress,
                    )
