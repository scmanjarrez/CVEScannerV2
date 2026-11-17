# SPDX-License-Identifier: GPL-3.0-or-later

"""Import raw NVD pages from disk without contacting NVD.

No test calls NVD or needs an API key. Each case uses an isolated database
and a temporary raw directory tree.
"""

import asyncio
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Self
from unittest.mock import AsyncMock, patch

from rich.console import Console
from sqlalchemy import func, select

from db_manager.application.updater import run_database
from db_manager.domain.models import DatabaseArguments
from db_manager.infrastructure.storage import (
    CveModel,
    Database,
    ProductModel,
)

COMPLETED_AT: str = "2026-10-02T00:00:00.000Z"
PAGE_SIZE: int = 2
TOTAL: int = 4


def _cve_page(start: int) -> dict[str, object]:
    """Build one raw CVE page with the fixture records of the resume tests.

    Args:
        start: Offset of the first record in the page.

    Returns:
        JSON-serializable NVD response for the CVE endpoint.
    """
    vulnerabilities = [
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
                                            f"cpe:2.3:a:vendor:product:{i}:*"
                                        ),
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
        for i in range(start, min(start + PAGE_SIZE, TOTAL))
    ]
    return {
        "totalResults": TOTAL,
        "startIndex": start,
        "vulnerabilities": vulnerabilities,
    }


def _cpe_page(start: int) -> dict[str, object]:
    """Build one raw CPE page with the fixture records of the resume tests.

    Args:
        start: Offset of the first record in the page.

    Returns:
        JSON-serializable NVD response for the CPE endpoint.
    """
    products = [
        {"cpe": {"cpeName": f"cpe:2.3:a:vendor:product:{i}:*"}}
        for i in range(start, min(start + PAGE_SIZE, TOTAL))
    ]
    return {"totalResults": TOTAL, "startIndex": start, "products": products}


def _write_scope(
    raw_dir: Path,
    endpoint: str,
    *,
    complete: bool = True,
) -> None:
    """Write every page of one 'full' scope, optionally with its marker.

    Args:
        raw_dir: Root directory of the raw NVD tree.
        endpoint: Either 'cves' or 'cpes'.
        complete: Whether to write the completion marker.
    """
    scope_dir = raw_dir / endpoint / "full"
    scope_dir.mkdir(parents=True, exist_ok=True)
    build = _cve_page if endpoint == "cves" else _cpe_page
    for start in range(0, TOTAL, PAGE_SIZE):
        page = scope_dir / f"page-{start:08d}.json"
        page.write_text(json.dumps(build(start)), encoding="utf-8")
    if complete:
        marker = {"total_results": TOTAL, "completed_at": COMPLETED_AT}
        (scope_dir / "complete.json").write_text(
            json.dumps(marker), encoding="utf-8"
        )


class OfflineImportTests(unittest.IsolatedAsyncioTestCase):
    """Check offline NVD import from raw pages stored on disk.

    Use the real updater and SQLite writer; only external services are
    replaced.
    """

    async def asyncSetUp(self: Self) -> None:
        """Create isolated temporary directories for each scenario.

        Keep the database and the raw NVD tree in a temporary directory.
        """
        self.directory: tempfile.TemporaryDirectory[str] = (
            tempfile.TemporaryDirectory()
        )
        self.root = Path(self.directory.name)
        self.raw_dir = self.root / "nvd-raw"
        self.path = self.root / "cve.db"

    async def asyncTearDown(self: Self) -> None:
        """Remove the temporary directory after the workers have finished.

        Run cleanup in a worker thread to avoid blocking the event loop.
        """
        await asyncio.to_thread(self.directory.cleanup)

    async def run_offline(self: Self) -> None:
        """Run the updater on the raw tree with network access forbidden.

        Any attempt to contact NVD fails the test through the patched
        request function.
        """
        console = Console(file=io.StringIO())
        args = DatabaseArguments(
            database=self.path,
            skip_scrape=True,
            nvd_raw=self.raw_dir,
        )
        with (
            patch("db_manager.application.updater.console", console),
            patch("db_manager.infrastructure.nvd.console", console),
            patch("db_manager.infrastructure.nvd.NVD_CPE_PAGE_SIZE", 2),
            patch("db_manager.infrastructure.nvd.NVD_CVE_PAGE_SIZE", 2),
            patch(
                "db_manager.infrastructure.nvd.get_with_retries",
                AsyncMock(side_effect=AssertionError("NVD was contacted")),
            ),
            patch(
                "db_manager.application.updater.update_metasploit",
                AsyncMock(),
            ),
            patch(
                "db_manager.application.updater.update_exploitdb",
                AsyncMock(),
            ),
        ):
            await run_database(args)

    async def test_offline_import_populates_database(self: Self) -> None:
        """Fill the database from raw pages without any network request.

        The NVD client is patched to fail, so success proves no request
        was made.
        """
        _write_scope(self.raw_dir, "cves")
        _write_scope(self.raw_dir, "cpes")
        await self.run_offline()
        async with Database(self.path) as database:
            cves = await database.session.scalar(
                select(func.count()).select_from(CveModel)
            )
            products = await database.session.scalar(
                select(func.count()).select_from(ProductModel)
            )
        self.assertEqual(cves, TOTAL)
        self.assertGreater(products or 0, 0)

    async def test_second_run_skips_committed_pages(self: Self) -> None:
        """Resume an interrupted import without reading committed pages.

        The first run fails on a missing CPE page after committing page 0.
        Page 0 is then deleted, so the resumed run succeeds only if that
        committed checkpoint is honoured.
        """
        _write_scope(self.raw_dir, "cves")
        _write_scope(self.raw_dir, "cpes")
        missing = self.raw_dir / "cpes" / "full" / "page-00000002.json"
        saved = missing.read_bytes()
        missing.unlink()
        with self.assertRaises(RuntimeError):
            await self.run_offline()
        committed = self.raw_dir / "cpes" / "full" / "page-00000000.json"
        committed.unlink()
        missing.write_bytes(saved)
        await self.run_offline()
        async with Database(self.path) as database:
            cves = await database.session.scalar(
                select(func.count()).select_from(CveModel)
            )
        self.assertEqual(cves, TOTAL)

    async def test_missing_complete_scopes_raise(self: Self) -> None:
        """Reject a raw tree whose scopes lack the completion marker.

        An incomplete download must never be imported silently.
        """
        _write_scope(self.raw_dir, "cves", complete=False)
        _write_scope(self.raw_dir, "cpes", complete=False)
        with self.assertRaises(RuntimeError):
            await self.run_offline()
