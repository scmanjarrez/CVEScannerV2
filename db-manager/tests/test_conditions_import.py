# SPDX-License-Identifier: GPL-3.0-or-later

"""Check that CVE import stores AND-condition rows from configurations.

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
from sqlalchemy import select

from db_manager.application.updater import run_database
from db_manager.domain.models import DatabaseArguments
from db_manager.infrastructure.storage import (
    AffectedModel,
    ConditionModel,
    Database,
    MultiAffectedModel,
)

COMPLETED_AT: str = "2026-10-02T00:00:00.000Z"
AND_CVE: str = "CVE-2026-2001"
OR_CVE: str = "CVE-2026-2002"
PHP_CPE: str = "cpe:2.3:a:php:php:5.2.4:*:*:*:*:*:*:*"
WINDOWS_CPE: str = "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"
APACHE_CPE: str = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def _cve_page() -> dict[str, object]:
    """Build the raw CVE page with one AND and one OR configuration.

    Returns:
        JSON-serializable NVD response for the CVE endpoint.
    """
    and_cve = {
        "id": AND_CVE,
        "vulnStatus": "Analyzed",
        "published": "2026-01-01T00:00:00.000",
        "configurations": [
            {
                "operator": "AND",
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {"vulnerable": True, "criteria": PHP_CPE}
                        ],
                    },
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {"vulnerable": False, "criteria": WINDOWS_CPE}
                        ],
                    },
                ],
            }
        ],
    }
    or_cve = {
        "id": OR_CVE,
        "vulnStatus": "Analyzed",
        "published": "2026-01-01T00:00:00.000",
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {"vulnerable": True, "criteria": APACHE_CPE}
                        ],
                    }
                ],
            }
        ],
    }
    return {
        "totalResults": 2,
        "startIndex": 0,
        "vulnerabilities": [{"cve": and_cve}, {"cve": or_cve}],
    }


def _cpe_page() -> dict[str, object]:
    """Build the raw CPE page listing every product used by the CVEs.

    Returns:
        JSON-serializable NVD response for the CPE endpoint.
    """
    names = [PHP_CPE, WINDOWS_CPE, APACHE_CPE]
    return {
        "totalResults": len(names),
        "startIndex": 0,
        "products": [{"cpe": {"cpeName": name}} for name in names],
    }


def _write_scope(
    raw_dir: Path, endpoint: str, page: dict[str, object]
) -> None:
    """Write one complete single-page scope of the raw NVD tree.

    Args:
        raw_dir: Root directory of the raw NVD tree.
        endpoint: Either 'cves' or 'cpes'.
        page: JSON-serializable page content, also used as the total.
    """
    scope_dir = raw_dir / endpoint / "full"
    scope_dir.mkdir(parents=True, exist_ok=True)
    (scope_dir / "page-00000000.json").write_text(
        json.dumps(page), encoding="utf-8"
    )
    marker = {
        "total_results": page["totalResults"],
        "completed_at": COMPLETED_AT,
    }
    (scope_dir / "complete.json").write_text(
        json.dumps(marker), encoding="utf-8"
    )


class ConditionImportTests(unittest.IsolatedAsyncioTestCase):
    """Check condition rows written by the offline NVD import.

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
        _write_scope(self.raw_dir, "cves", _cve_page())
        _write_scope(self.raw_dir, "cpes", _cpe_page())

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
            noscrape=True,
            nvd_raw=self.raw_dir,
        )
        with (
            patch("db_manager.application.updater.console", console),
            patch("db_manager.infrastructure.nvd.console", console),
            patch("db_manager.infrastructure.nvd.NVD_CPE_PAGE_SIZE", 10),
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

    async def test_and_configuration_stores_one_condition(self: Self) -> None:
        """Store one condition for an AND configuration only.

        The AND CVE pairs the vulnerable PHP product with the Windows
        platform. The OR-only CVE must produce no condition rows.
        """
        await self.run_offline()
        async with Database(self.path) as database:
            rows = (
                await database.session.execute(
                    select(ConditionModel.cve_id, ConditionModel.config_idx)
                )
            ).all()
        self.assertEqual(
            sorted(rows),
            [(AND_CVE, 0)],
        )

    async def test_affected_rows_unchanged_by_conditions(self: Self) -> None:
        """Keep affected and multiaffected rows identical to before.

        The AND CVE still gets its exact affected row, and no row is added
        to the multiaffected table.
        """
        await self.run_offline()
        async with Database(self.path) as database:
            affected = (
                (await database.session.execute(select(AffectedModel.cve_id)))
                .scalars()
                .all()
            )
            multiaffected = (
                (
                    await database.session.execute(
                        select(MultiAffectedModel.cve_id)
                    )
                )
                .scalars()
                .all()
            )
        self.assertEqual(sorted(affected), sorted([AND_CVE, OR_CVE]))
        self.assertEqual(multiaffected, [])
