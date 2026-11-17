# SPDX-License-Identifier: GPL-3.0-or-later

"""Exercise durable NVD resumption with SQLite and simulated responses.

No test calls NVD or needs an API key. Each case uses an isolated database.
"""

import asyncio
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Self
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

import httpx2
from rich.console import Console
from sqlalchemy import func, select

from db_manager.application.updater import run_database
from db_manager.domain.models import (
    AffectedRecord,
    CveRecord,
    DatabaseArguments,
    NvdPageBatch,
    WorkerCommand,
)
from db_manager.infrastructure.network import AsyncRateLimiter
from db_manager.infrastructure.storage import (
    CveModel,
    Database,
    NvdPageModel,
    ProductModel,
)
from db_manager.infrastructure.writer import populate_database_worker


class SimulatedInterruptError(RuntimeError):
    """Stop a download after earlier pages have been committed.

    Raise from the fake transport to exercise the real failure path.
    """


class FakeNvd:
    """Provide small paginated responses and a controllable interruption.

    Attributes:
        fail_endpoint: Collection interrupted at its second page.
        page_requests: Requested collection names and offsets.
        invalid_page: Whether the response contains an incorrect offset.
        short_page: Whether a data page is truncated.
        pause_endpoint: Collection paused on its second page for cancellation.
        paused: Event announcing that the download can be cancelled.
        release: Event keeping the simulated request suspended.
        urls: Metadata and page URLs used to verify fixed query windows.
    """

    def __init__(self: Self, fail_endpoint: str | None = None) -> None:
        """Initialize the simulated transport.

        Args:
            fail_endpoint: Collection to interrupt, or None for success.
        """
        self.fail_endpoint = fail_endpoint
        self.page_requests: list[tuple[str, int]] = []
        self.invalid_page = False
        self.short_page = False
        self.pause_endpoint: str | None = None
        self.paused = asyncio.Event()
        self.release = asyncio.Event()
        self.urls: list[str] = []

    async def get(
        self: Self,
        client: httpx2.AsyncClient,
        url: str,
        rate_limiter: AsyncRateLimiter,
        headers: dict[str, str] | None = None,
    ) -> httpx2.Response:
        """Respond to metadata or page requests without using the network.

        Args:
            client: Unused production HTTP client.
            url: NVD metadata or data-page URL.
            rate_limiter: Unused production request limiter.
            headers: Unused request headers.

        Returns:
            A realistic NVD response containing synthetic records.

        Raises:
            SimulatedInterruptError: At the configured interruption point.
        """
        del client, rate_limiter, headers
        await asyncio.sleep(0)
        self.urls.append(url)
        parsed = urlsplit(url)
        parameters = parse_qs(parsed.query)
        endpoint = parsed.path.split("/")[-2]
        start = int(parameters["startIndex"][0])
        page_size = int(parameters["resultsPerPage"][0])
        total = 6 if endpoint == "cpes" else 4
        payload: dict[str, object] = {
            "totalResults": total,
            "startIndex": start,
        }
        if page_size != 1:
            self.page_requests.append((endpoint, start))
            if endpoint == self.fail_endpoint and start == page_size:
                raise SimulatedInterruptError
            if endpoint == self.pause_endpoint and start == page_size:
                self.paused.set()
                await self.release.wait()
            if self.invalid_page:
                payload["startIndex"] = start + 1
        stop = min(start + page_size, total)
        if self.short_page and page_size != 1:
            stop = start
        if endpoint == "cpes":
            payload["products"] = [
                {"cpe": {"cpeName": f"cpe:2.3:a:vendor:product:{i}:*"}}
                for i in range(start, stop)
            ]
        else:
            payload["vulnerabilities"] = [
                {
                    "cve": {
                        "id": f"CVE-2026-{1000 + i}",
                        "vulnStatus": "Analyzed",
                        "published": "2026-01-01T00:00:00.000",
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": (
                                                    "cpe:2.3:a:vendor:"
                                                    f"product:{i}:*"
                                                ),
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
                for i in range(start, stop)
            ]
        return httpx2.Response(200, content=json.dumps(payload).encode())


class ResumeTests(unittest.IsolatedAsyncioTestCase):
    """Check interruption, checkpoint durability, and changing catalogues.

    Use the real updater, queue consumer, and SQLite transaction boundaries.
    """

    async def asyncSetUp(self: Self) -> None:
        """Create a fresh SQLite schema for each scenario.

        Keep all downloaded records and checkpoints in a temporary file.
        """
        self.directory: tempfile.TemporaryDirectory[str] = (
            tempfile.TemporaryDirectory()
        )
        self.path = Path(self.directory.name) / "cve.db"
        self.args = DatabaseArguments(database=self.path, skip_scrape=True)
        async with Database(self.path) as database:
            await database.setup()

    async def asyncTearDown(self: Self) -> None:
        """Remove the temporary database after closing all connections.

        Run cleanup after the test's asynchronous workers have finished.
        """
        await asyncio.to_thread(self.directory.cleanup)

    async def run_update(
        self: Self, transport: FakeNvd, *, reference_error: bool = False
    ) -> None:
        """Run the complete workflow with external services replaced.

        Args:
            transport: Simulated NVD metadata and data-page provider.
            reference_error: Whether to fail after all NVD pages commit.
        """
        console = Console(file=io.StringIO())
        with (
            patch(
                "db_manager.application.updater._read_api_key",
                return_value="key",
            ),
            patch("db_manager.application.updater.console", console),
            patch("db_manager.infrastructure.nvd.console", console),
            patch("db_manager.infrastructure.nvd.NVD_CPE_PAGE_SIZE", 2),
            patch("db_manager.infrastructure.nvd.NVD_CVE_PAGE_SIZE", 2),
            patch(
                "db_manager.infrastructure.nvd.NVD_MAX_CONCURRENT_REQUESTS", 1
            ),
            patch(
                "db_manager.infrastructure.nvd.get_with_retries", transport.get
            ),
            patch(
                "db_manager.application.updater.update_metasploit",
                AsyncMock(
                    side_effect=(
                        SimulatedInterruptError if reference_error else None
                    )
                ),
            ),
            patch(
                "db_manager.application.updater.update_exploitdb", AsyncMock()
            ),
        ):
            await run_database(self.args)

    async def test_cancellation_preserves_completed_pages(self: Self) -> None:
        """Resume after task cancellation, as caused by pressing Ctrl-C.

        Suspend a later request only after the first page is durable.
        """
        transport = FakeNvd()
        transport.pause_endpoint = "cpes"
        update = asyncio.create_task(self.run_update(transport))
        try:
            await asyncio.wait_for(transport.paused.wait(), timeout=5)
        finally:
            update.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await update
        transport.pause_endpoint = None
        transport.page_requests.clear()
        await self.run_update(transport)
        self.assertNotIn(("cpes", 0), transport.page_requests)
        self.assertIn(("cpes", 2), transport.page_requests)

    async def test_reference_failure_does_not_redownload_nvd(
        self: Self,
    ) -> None:
        """Keep all NVD checkpoints until external references succeed.

        Restarting during the reference stage must skip every NVD data page.
        """
        transport = FakeNvd()
        with self.assertRaises(SimulatedInterruptError):
            await self.run_update(transport, reference_error=True)
        transport.page_requests.clear()
        await self.run_update(transport)
        self.assertEqual(transport.page_requests, [])
        async with Database(self.path) as database:
            self.assertIsNone(await database.pending_nvd_sync())

    async def test_incremental_resume_keeps_original_window(
        self: Self,
    ) -> None:
        """Reuse the original last-modified window after an interruption.

        Later changes remain covered by the next incremental update because
        the successful timestamp stays at the original run's cutoff.
        """
        start = "2026-10-01T00:00:00.000Z"
        cutoff = "2026-10-02T00:00:00.000Z"
        async with Database(self.path) as database:
            await database.update_metadata(start)
        transport = FakeNvd(fail_endpoint="cves")
        with (
            patch("db_manager.infrastructure.nvd.now", return_value=cutoff),
            self.assertRaises(ExceptionGroup),
        ):
            await self.run_update(transport)
        transport.fail_endpoint = None
        transport.urls.clear()
        with patch(
            "db_manager.infrastructure.nvd.now",
            return_value="2026-10-08T00:00:00.000Z",
        ):
            await self.run_update(transport)
        for url in transport.urls:
            parameters = parse_qs(urlsplit(url).query)
            self.assertEqual(parameters["lastModStartDate"], [start])
            self.assertEqual(parameters["lastModEndDate"], [cutoff])
        async with Database(self.path) as database:
            self.assertEqual(await database.cached_metadata(), cutoff)

    async def test_resume_skips_only_committed_pages(self: Self) -> None:
        """Resume either collection and retain the original cutoff.

        Check that completed CPE and CVE pages are never requested again.
        """
        for endpoint in ("cpes", "cves"):
            with self.subTest(endpoint=endpoint):
                transport = FakeNvd(fail_endpoint=endpoint)
                with self.assertRaises(ExceptionGroup):
                    await self.run_update(transport)
                async with Database(self.path) as database:
                    pending = await database.pending_nvd_sync()
                    self.assertIsNotNone(pending)
                    self.assertIsNone(await database.cached_metadata())
                self.assertIsNotNone(pending)
                if pending is None:
                    self.fail("The interrupted synchronization was not saved")
                transport.fail_endpoint = None
                transport.page_requests.clear()
                await self.run_update(transport)
                self.assertNotIn(("cpes", 0), transport.page_requests)
                if endpoint == "cves":
                    self.assertFalse(
                        any(
                            name == "cpes"
                            for name, _ in transport.page_requests
                        )
                    )
                    self.assertNotIn(("cves", 0), transport.page_requests)
                async with Database(self.path) as database:
                    self.assertEqual(
                        await database.cached_metadata(), pending.sync_time
                    )
                    self.assertIsNone(await database.pending_nvd_sync())
                    self.assertEqual(
                        await database.session.scalar(
                            select(func.count()).select_from(CveModel)
                        ),
                        4,
                    )
                    self.assertEqual(
                        await database.session.scalar(
                            select(func.count()).select_from(ProductModel)
                        ),
                        6,
                    )
                    self.assertEqual(
                        await database.session.scalar(
                            select(func.count()).select_from(NvdPageModel)
                        ),
                        0,
                    )
                # A separate file prevents the second subtest being an
                # incremental update of the first scenario's successful run.
                self.path = Path(self.directory.name) / "second.db"
                self.args = DatabaseArguments(
                    database=self.path, skip_scrape=True
                )

    async def test_invalid_pages_have_no_checkpoint(self: Self) -> None:
        """Reject wrong offsets and incomplete successful HTTP responses.

        An HTTP 200 alone must never make a page eligible for skipping.
        """
        for invalid_offset in (True, False):
            with self.subTest(invalid_offset=invalid_offset):
                transport = FakeNvd()
                transport.invalid_page = invalid_offset
                transport.short_page = not invalid_offset
                with self.assertRaises(ExceptionGroup):
                    await self.run_update(transport)
                async with Database(self.path) as database:
                    self.assertEqual(
                        await database.session.scalar(
                            select(func.count()).select_from(NvdPageModel)
                        ),
                        0,
                    )
                    self.assertEqual(
                        await database.session.scalar(
                            select(func.count()).select_from(ProductModel)
                        ),
                        0,
                    )

    async def test_page_failure_rolls_back_data_and_checkpoint(
        self: Self,
    ) -> None:
        """Roll back the entire page if an association cannot be written.

        The preceding CVE insert must not survive the failed transaction.
        """
        async with Database(self.path) as database:
            await database.prepare_nvd_collection(
                "query", 2, 2, incremental=False
            )
        queue: asyncio.Queue[WorkerCommand] = asyncio.Queue()
        await queue.put(
            NvdPageBatch(
                collection="query",
                start_index=0,
                commands=[
                    CveRecord(
                        cve_id="CVE-2026-1000",
                        cvss_v2=None,
                        cvss_v3=None,
                        cvss_v4=None,
                        published=2026,
                    ),
                    AffectedRecord(
                        cve_id="CVE-2026-1000",
                        identity=("a", "absent", "product", "1", "*"),
                    ),
                ],
            )
        )
        with self.assertRaises(LookupError):
            await populate_database_worker(self.path, queue)
        async with Database(self.path) as database:
            self.assertEqual(
                await database.session.scalar(
                    select(func.count()).select_from(CveModel)
                ),
                0,
            )
            self.assertEqual(
                await database.session.scalar(
                    select(func.count()).select_from(NvdPageModel)
                ),
                0,
            )

    async def test_writer_failure_does_not_hang_download(self: Self) -> None:
        """Surface writer errors while producers await durable completion.

        A failed consumer must not leave page tasks waiting indefinitely.
        """
        transport = FakeNvd()
        with (
            patch(
                "db_manager.infrastructure.writer.flush_database_commands",
                AsyncMock(side_effect=SimulatedInterruptError),
            ),
            self.assertRaises(SimulatedInterruptError),
        ):
            await asyncio.wait_for(self.run_update(transport), timeout=5)
        async with Database(self.path) as database:
            self.assertIsNotNone(await database.pending_nvd_sync())
            self.assertEqual(
                await database.session.scalar(
                    select(func.count()).select_from(NvdPageModel)
                ),
                0,
            )

    async def test_growth_replays_holes_and_partial_tail(self: Self) -> None:
        """Retain only a full contiguous prefix when a catalogue grows.

        Later pages and a previously partial final page must be downloaded.
        """
        async with Database(self.path) as database:
            await database.prepare_nvd_collection(
                "query", 7, 2, incremental=False
            )
            for index in (0, 2, 6):
                await database.mark_nvd_page("query", index)
        async with Database(self.path) as database:
            completed = await database.prepare_nvd_collection(
                "query", 9, 2, incremental=False
            )
            self.assertEqual(completed, {0, 2})
        async with Database(self.path) as database:
            await database.prepare_nvd_collection(
                "tail", 3, 2, incremental=False
            )
            for index in (0, 2):
                await database.mark_nvd_page("tail", index)
        async with Database(self.path) as database:
            self.assertEqual(
                await database.prepare_nvd_collection(
                    "tail", 4, 2, incremental=False
                ),
                {0},
            )

    async def test_shrinking_or_changed_filtered_query_restarts(
        self: Self,
    ) -> None:
        """Invalidate offsets if records can have moved before them.

        Full-catalog shrinkage and changed last-modified membership both
        require fetching that collection again rather than skipping pages.
        """
        for incremental, total in ((False, 3), (True, 5)):
            with self.subTest(incremental=incremental):
                collection = str(incremental)
                async with Database(self.path) as database:
                    await database.prepare_nvd_collection(
                        collection, 4, 2, incremental=incremental
                    )
                    await database.mark_nvd_page(collection, 0)
                async with Database(self.path) as database:
                    completed = await database.prepare_nvd_collection(
                        collection, total, 2, incremental=incremental
                    )
                    self.assertEqual(completed, set())
