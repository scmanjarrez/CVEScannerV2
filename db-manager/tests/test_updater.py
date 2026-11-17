# SPDX-License-Identifier: GPL-3.0-or-later

"""Check updater startup against a fresh filesystem without contacting NVD.

Verify database setup while mocking the first external update request.
"""

import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Self
from unittest.mock import AsyncMock, patch

from rich.console import Console

from db_manager.application.updater import run_database
from db_manager.domain.models import DatabaseArguments


class StopAfterSetupError(Exception):
    """Stop the update before making requests to external services.

    Use this marker to inspect the schema immediately after setup.
    """


class UpdaterStartupTests(unittest.IsolatedAsyncioTestCase):
    """Exercise startup with missing and existing parent directories.

    Confirm the updater creates the schema before its first NVD request.
    """

    async def test_database_parent_directory(self: Self) -> None:
        """Create the schema before the first NVD request in either case.

        Check startup with a new parent path and with an existing parent path.
        """
        for parent_exists in (False, True):
            with (
                self.subTest(parent_exists=parent_exists),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "nested" / "data" / "cve.db"
                if parent_exists:
                    path.parent.mkdir(parents=True)
                with (
                    patch(
                        "db_manager.application.updater._read_api_key",
                        return_value="test-key",
                    ),
                    patch(
                        "db_manager.application.updater.console",
                        Console(file=io.StringIO()),
                    ),
                    patch(
                        "db_manager.application.updater.update_db",
                        AsyncMock(side_effect=StopAfterSetupError),
                    ),
                    self.assertRaises(StopAfterSetupError),
                ):
                    await run_database(DatabaseArguments(database=path))
                self.assertTrue(path.is_file())
                with sqlite3.connect(path) as connection:
                    tables = {
                        row[0]
                        for row in connection.execute(
                            "SELECT name FROM sqlite_master "
                            "WHERE type = 'table'"
                        )
                    }
                self.assertTrue({"products", "cves"}.issubset(tables))
