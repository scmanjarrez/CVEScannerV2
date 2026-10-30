# SPDX-License-Identifier: GPL-3.0-or-later

"""Expose the command-line entry point for the database updater.

Parse updater options and invoke the asynchronous application workflow.
"""

import argparse
import asyncio
from pathlib import Path

from rich_argparse import RichHelpFormatter

from db_manager.application.updater import run_database
from db_manager.constants import DEFAULT_DATABASE_PATH
from db_manager.domain.models import DatabaseArguments


class DatabaseNamespace(argparse.Namespace):
    """Hold typed command-line arguments for the database updater.

    Attributes:
        database: SQLite database file path.
        noscrape: Whether to skip Exploit-DB title scraping.
        nvd_raw: Directory with raw NVD pages to import, or None.
    """

    database: Path
    noscrape: bool
    nvd_raw: Path | None


def main() -> None:
    """Parse command-line arguments and run the database updater.

    Convert parsed values into the typed application arguments.
    """
    parser = argparse.ArgumentParser(
        description="Create or update the CVEScannerV2 vulnerability database",
        formatter_class=RichHelpFormatter,
    )
    parser.add_argument(
        "-d",
        "--database",
        default=DEFAULT_DATABASE_PATH,
        type=Path,
        help="Database file path",
    )
    parser.add_argument(
        "-ns",
        "--noscrape",
        action="store_true",
        help="Disable exploit-db name scraping",
    )
    parser.add_argument(
        "-r",
        "--nvd-raw",
        default=None,
        type=Path,
        help=(
            "Import NVD data from raw pages stored by db_manager.cli.nvd_raw "
            "instead of downloading it"
        ),
    )
    namespace = DatabaseNamespace()
    parser.parse_args(namespace=namespace)
    asyncio.run(
        run_database(
            DatabaseArguments(
                database=namespace.database,
                noscrape=namespace.noscrape,
                nvd_raw=namespace.nvd_raw,
            )
        )
    )
