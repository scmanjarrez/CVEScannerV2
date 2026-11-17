# SPDX-License-Identifier: GPL-3.0-or-later

"""Check that deprecated CPE names become product alias records.

The CPE page is a local JSON document and the database is temporary, so no
test calls NVD or needs network access.
"""

import asyncio
import json
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Self

from sqlalchemy import select, text

from db_manager.domain.models import AliasRecord
from db_manager.infrastructure.nvd import cpe_commands
from db_manager.infrastructure.storage import AliasModel, Database


def _page(*entries: Mapping[str, object]) -> bytes:
    """Build a CPE catalog page with the given entries.

    Args:
        *entries: CPE fields of each catalog entry.

    Returns:
        JSON bytes shaped like an NVD CPE response.
    """
    products = [{"cpe": entry} for entry in entries]
    return json.dumps({"products": products}).encode()


def _aliases(content: bytes) -> list[AliasRecord]:
    """Return the alias records produced by one CPE page.

    Args:
        content: JSON bytes shaped like an NVD CPE response.

    Returns:
        Alias records in page order.
    """
    _, commands = cpe_commands(content, "test")
    return [item for item in commands if isinstance(item, AliasRecord)]


class AliasExtractionTests(unittest.TestCase):
    """Check which deprecated CPE entries produce alias records."""

    def test_renamed_application_creates_alias(self: Self) -> None:
        """Map a deprecated product to the product that replaces it."""
        page = _page(
            {
                "cpeName": "cpe:2.3:a:lingotek:lingotek:*:*:*:*:*:*:*:*",
                "deprecated": True,
                "deprecatedBy": [
                    {
                        "cpeName": (
                            "cpe:2.3:a:lingotek:ray_enterprise_translation:"
                            "*:*:*:*:*:*:*:*"
                        )
                    }
                ],
            }
        )
        self.assertEqual(
            _aliases(page),
            [
                AliasRecord(
                    old_vendor="lingotek",
                    old_product="lingotek",
                    old_version="*",
                    old_update="*",
                    new_vendor="lingotek",
                    new_product="ray_enterprise_translation",
                )
            ],
        )

    def test_same_product_and_other_parts_are_ignored(self: Self) -> None:
        """Skip version-only deprecations and non-application parts."""
        same = {
            "cpeName": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
            "deprecated": True,
            "deprecatedBy": [
                {"cpeName": "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"}
            ],
        }
        os_target = {
            "cpeName": "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*",
            "deprecated": True,
            "deprecatedBy": [
                {"cpeName": "cpe:2.3:o:vendor:other:2.0:*:*:*:*:*:*:*"}
            ],
        }
        active = {"cpeName": "cpe:2.3:a:vendor:product:3.0:*:*:*:*:*:*:*"}
        self.assertEqual(_aliases(_page(same, os_target, active)), [])


class AliasStorageTests(unittest.IsolatedAsyncioTestCase):
    """Check that alias rows persist once and survive repeated setup."""

    async def asyncSetUp(self: Self) -> None:
        """Create an isolated temporary database path."""
        self.directory: tempfile.TemporaryDirectory[str] = (
            tempfile.TemporaryDirectory()
        )
        self.path = Path(self.directory.name) / "cve.db"

    async def asyncTearDown(self: Self) -> None:
        """Remove the temporary directory without blocking the loop."""
        await asyncio.to_thread(self.directory.cleanup)

    async def test_insert_aliases_ignores_duplicates(self: Self) -> None:
        """Store a repeated alias row only once."""
        row = ("misp", "misp", "2.4", "*", "misp-project", "misp")
        async with Database(self.path) as database:
            await database.setup()
            await database.insert_aliases([row, row])
            await database.commit()
        async with Database(self.path) as database:
            await database.setup()
            result = await database.session.execute(
                select(AliasModel.new_vendor, AliasModel.new_product)
            )
            self.assertEqual(result.tuples().all(), [("misp-project", "misp")])

    async def test_view_keeps_only_mostly_replaced_products(
        self: Self,
    ) -> None:
        """Expose a rename only when half of the old entries were replaced."""
        renamed = [
            ("old", "app", version, "*", "new", "app")
            for version in ("1.0", "2.0")
        ]
        partial = ("old", "live", "1.0", "*", "new", "live")
        live_products = [
            ("a", "old", "live", version, "*")
            for version in ("1.0", "2.0", "3.0", "4.0")
        ]
        renamed_products = [
            ("a", "old", "app", version, "*") for version in ("1.0", "2.0")
        ]
        async with Database(self.path) as database:
            await database.setup()
            await database.insert_products(live_products + renamed_products)
            await database.insert_aliases([*renamed, partial])
            await database.commit()
            result = await database.session.execute(
                text("SELECT * FROM product_aliases")
            )
            self.assertEqual(
                result.tuples().all(), [("old", "app", "new", "app")]
            )


if __name__ == "__main__":
    unittest.main()
