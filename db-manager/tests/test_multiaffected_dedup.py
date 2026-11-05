# SPDX-License-Identifier: GPL-3.0-or-later

"""Check that multiaffected rows with NULL version bounds are unique.

Each case uses an isolated temporary database and the real Database
wrapper. No test calls NVD or needs network access.
"""

import asyncio
import tempfile
import unittest
from pathlib import Path
from typing import Self

from sqlalchemy import func, select, text

from db_manager.infrastructure.storage import (
    CveModel,
    Database,
    MultiAffectedModel,
)

CVE_ID: str = "CVE-2000-0244"
INDEX_NAME: str = "uq_multiaffected_bounds"
IDENTITY: tuple[str, str, str, str, str] = (
    "a",
    "vendor",
    "product",
    "1.0",
    "",
)
DUPLICATE_BOUNDS: tuple[str | None, str | None, str | None, str | None] = (
    None,
    None,
    "1.8",
    None,
)
OTHER_BOUNDS: tuple[str | None, str | None, str | None, str | None] = (
    None,
    None,
    "1.9",
    None,
)
INSERT_RAW: str = (
    "INSERT INTO multiaffected (cve_id, product_id, "
    '"versionStartIncluding", "versionStartExcluding", '
    '"versionEndIncluding", "versionEndExcluding") '
    "VALUES (:cve, :product, :vsi, :vse, :vei, :vee)"
)


class MultiAffectedDedupTests(unittest.IsolatedAsyncioTestCase):
    """Check duplicate removal and uniqueness for multiaffected rows.

    Use the real Database wrapper; only the temporary path is local.
    """

    async def asyncSetUp(self: Self) -> None:
        """Create an isolated temporary directory for each scenario.

        Keep the SQLite database file in the temporary directory.
        """
        self.directory: tempfile.TemporaryDirectory[str] = (
            tempfile.TemporaryDirectory()
        )
        self.path = Path(self.directory.name) / "cve.db"

    async def asyncTearDown(self: Self) -> None:
        """Remove the temporary directory after the workers have finished.

        Run cleanup in a worker thread to avoid blocking the event loop.
        """
        await asyncio.to_thread(self.directory.cleanup)

    async def test_setup_removes_legacy_duplicates(self: Self) -> None:
        """Remove identical legacy rows and create the unique index.

        Two identical rows with NULL bounds collapse into one row, while
        a row with a different bound is kept.
        """
        async with Database(self.path) as database:
            await database.setup()
            await database.insert_cves([_cve()])
            await database.insert_products([IDENTITY])
            await database.commit()
            async with database.engine.begin() as connection:
                await connection.execute(text(f"DROP INDEX {INDEX_NAME}"))
                product_id = (
                    await connection.execute(
                        text("SELECT product_id FROM products")
                    )
                ).scalar_one()
                legacy_rows = (
                    DUPLICATE_BOUNDS,
                    DUPLICATE_BOUNDS,
                    OTHER_BOUNDS,
                )
                for bounds in legacy_rows:
                    await connection.execute(
                        text(INSERT_RAW),
                        _raw_values(product_id, bounds),
                    )

        async with Database(self.path) as database:
            await database.setup()
            count = await _count_rows(database)
            index_exists = await _index_exists(database)

        self.assertEqual(count, 2)
        self.assertTrue(index_exists)

    async def test_insert_treats_null_bounds_as_equal(self: Self) -> None:
        """Insert identical NULL-bound rows once and distinct rows twice.

        Repeated setup calls must not remove rows that are already unique.
        """
        async with Database(self.path) as database:
            await database.setup()
            await database.insert_cves([_cve()])
            await database.insert_products([IDENTITY])
            record = (CVE_ID, IDENTITY, DUPLICATE_BOUNDS)
            await database.insert_multiaffected([record, record])
            self.assertEqual(await _count_rows(database), 1)

            other = (CVE_ID, IDENTITY, OTHER_BOUNDS)
            await database.insert_multiaffected([other])
            await database.commit()
            self.assertEqual(await _count_rows(database), 2)

        async with Database(self.path) as database:
            await database.setup()
            await database.setup()
            self.assertEqual(await _count_rows(database), 2)
            self.assertTrue(await _index_exists(database))


def _cve() -> CveModel:
    """Build a minimal CVE row for the foreign key of multiaffected.

    Returns:
        CVE record with no scores and a publication year.
    """
    return CveModel(
        cve_id=CVE_ID,
        cvss_v2=None,
        cvss_v3=None,
        cvss_v4=None,
        published=2000,
    )


def _raw_values(
    product_id: int,
    bounds: tuple[str | None, str | None, str | None, str | None],
) -> dict[str, str | int | None]:
    """Build bind parameters for a raw multiaffected insert.

    Args:
        product_id: Product identifier referenced by the row.
        bounds: Start including, start excluding, end including, and end
            excluding version bounds.

    Returns:
        Named parameters for the raw INSERT statement.
    """
    vsi, vse, vei, vee = bounds
    return {
        "cve": CVE_ID,
        "product": product_id,
        "vsi": vsi,
        "vse": vse,
        "vei": vei,
        "vee": vee,
    }


async def _count_rows(database: Database) -> int:
    """Count multiaffected rows visible in the database session.

    Args:
        database: Database wrapper whose session runs the count.

    Returns:
        Number of rows in the multiaffected table.
    """
    statement = select(func.count()).select_from(MultiAffectedModel)
    result = await database.session.execute(statement)
    return result.scalar_one()


async def _index_exists(database: Database) -> bool:
    """Report whether the unique multiaffected bounds index exists.

    Args:
        database: Database wrapper whose engine reads the schema.

    Returns:
        True when the index is registered in the SQLite schema.
    """
    async with database.engine.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'index' AND name = :name"
            ),
            {"name": INDEX_NAME},
        )
        return result.first() is not None
