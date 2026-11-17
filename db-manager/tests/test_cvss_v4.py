# SPDX-License-Identifier: GPL-3.0-or-later

"""Check CVSS v4 extraction, schema migration and display text.

Each database case uses an isolated temporary SQLite file.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Self

from db_manager.domain.models import NvdCve
from db_manager.infrastructure.nvd import cvss_scores
from db_manager.infrastructure.query_store import cvss_text
from db_manager.infrastructure.storage import Database


def _cve(metrics: dict[str, object]) -> NvdCve:
    """Build one validated NVD CVE with the given metric collections.

    Args:
        metrics: Raw NVD metrics keyed by CVSS version.

    Returns:
        Validated CVE fields for the score extraction.
    """
    return NvdCve.model_validate(
        {
            "id": "CVE-2026-1000",
            "vulnStatus": "Analyzed",
            "published": "2026-01-01T00:00:00.000",
            "metrics": metrics,
        }
    )


class CvssScoreTests(unittest.TestCase):
    """Verify the CVSS v2, v3 and v4 score extraction from NVD data."""

    def test_v4_only_is_extracted(self: Self) -> None:
        """Return only the v4 score when NVD provides a v4 metric."""
        cve = _cve({"cvssMetricV40": [{"cvssData": {"baseScore": 9.3}}]})
        self.assertEqual(cvss_scores(cve), (None, None, "9.3"))

    def test_v3_and_v2_leave_v4_empty(self: Self) -> None:
        """Keep v4 empty when only the v2 and v3 metrics are present."""
        cve = _cve(
            {
                "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}],
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
            }
        )
        self.assertEqual(cvss_scores(cve), ("7.5", "9.8", None))

    def test_no_metrics_return_no_scores(self: Self) -> None:
        """Return no scores when the CVE has no CVSS metrics."""
        self.assertEqual(cvss_scores(_cve({})), (None, None, None))

    def test_first_v4_entry_is_primary(self: Self) -> None:
        """Use the first v4 entry, which NVD lists as Primary."""
        cve = _cve(
            {
                "cvssMetricV40": [
                    {"cvssData": {"baseScore": 9.3}},
                    {"cvssData": {"baseScore": 4.0}},
                ]
            }
        )
        self.assertEqual(cvss_scores(cve), (None, None, "9.3"))


class CvssTextTests(unittest.TestCase):
    """Verify the single CVSS column text used by query results."""

    def test_all_scores_are_listed_from_v4_to_v2(self: Self) -> None:
        """List v4, v3 and v2 scores in that order."""
        self.assertEqual(
            cvss_text("7.5", "9.8", "9.3"),
            "v4:9.3 v3:9.8 v2:7.5",
        )

    def test_only_v2_is_listed(self: Self) -> None:
        """Show only the v2 score when it is the sole score."""
        self.assertEqual(cvss_text("7.5", None, None), "v2:7.5")

    def test_no_scores_show_dash(self: Self) -> None:
        """Show a dash when no CVSS score is present."""
        self.assertEqual(cvss_text(None, None, None), "-")


class CvssV4SchemaTests(unittest.IsolatedAsyncioTestCase):
    """Verify that setup adds the cvss_v4 column to older databases."""

    def setUp(self: Self) -> None:
        """Create an isolated temporary directory for the database file."""
        directory: tempfile.TemporaryDirectory[str] = (
            tempfile.TemporaryDirectory()
        )
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "cve.db"

    def _column_names(self: Self) -> set[str]:
        """Return the column names of the cves table in the database file.

        Returns:
            Names of the columns declared on the cves table.
        """
        with sqlite3.connect(self.path) as connection:
            rows: list[tuple[object, ...]] = connection.execute(
                "PRAGMA table_info(cves)"
            ).fetchall()
        return {str(row[1]) for row in rows}

    async def test_setup_adds_missing_cvss_v4_column(self: Self) -> None:
        """Add the cvss_v4 column to a cves table created without it."""
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE cves ("
                "cve_id TEXT PRIMARY KEY, "
                "cvss_v2 TEXT, "
                "cvss_v3 TEXT, "
                "published INTEGER)"
            )
        self.assertNotIn("cvss_v4", self._column_names())
        async with Database(self.path) as database:
            await database.setup()
        self.assertIn("cvss_v4", self._column_names())

    async def test_setup_is_idempotent(self: Self) -> None:
        """Run setup twice without failing on the existing cvss_v4 column."""
        async with Database(self.path) as database:
            await database.setup()
        async with Database(self.path) as database:
            await database.setup()
        self.assertIn("cvss_v4", self._column_names())
