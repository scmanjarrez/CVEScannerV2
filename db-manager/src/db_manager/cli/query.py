# SPDX-License-Identifier: GPL-3.0-or-later

"""Parse and execute the database query command.

Select interactive or one-off query behavior from the supplied options.
"""

import argparse
import asyncio
from pathlib import Path

from rich_argparse import RichHelpFormatter

from db_manager.application.query import QueryArguments, fetch_results
from db_manager.constants import DEFAULT_DATABASE_PATH

from .results import console, print_affected, print_multi
from .tui import DatabaseQueryApp


class QueryNamespace(argparse.Namespace):
    """Receive command-line arguments with explicit attribute types.

    Attributes:
        cve: SQLite database path.
        product: Optional product name for a one-off query.
        version: Optional product version filter.
        update: Optional product update filter.
        raw: Whether to print unfiltered rows.
        debug: Whether to log rejected version comparisons.
        interactive: Whether to open the interactive query interface.
    """

    cve: Path
    product: str | None
    version: str | None
    update: str | None
    raw: bool
    debug: bool
    interactive: bool


async def run_query(args: QueryArguments) -> None:
    """Query and print CVEs for the configured product.

    Args:
        args: Database path, product, version, and output options.
    """
    results = await fetch_results(args)
    if args.raw:
        console.rule("Unfiltered matches")
        print_affected(results.raw_exact)
        print_multi(results.raw_ranges)

    console.rule("Filtered matches")
    print_affected(results.exact)
    if results.ranges:
        print_multi(results.ranges)


def main() -> None:
    """Parse CLI options and start interactive or one-off query mode.

    Open the terminal interface or run the configured product query.
    """
    parser = argparse.ArgumentParser(
        description="Search CVEs in the local CVE database",
        epilog=(
            "Omit --product to open the interactive Textual interface. "
            "Product completion uses names stored in the selected database."
        ),
        formatter_class=RichHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--cve",
        help="Path to CVE database",
        default=DEFAULT_DATABASE_PATH,
        type=Path,
    )
    parser.add_argument(
        "-p",
        "--product",
        help="Product name for a one-off query; omit for interactive mode",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Open the interactive query interface",
    )
    parser.add_argument("-v", "--version", help="Product version")
    parser.add_argument("-u", "--update", help="Product update")
    parser.add_argument(
        "-r",
        "--raw",
        action="store_true",
        help="Output unfiltered data",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Log version comparison details",
    )
    namespace = QueryNamespace()
    parser.parse_args(namespace=namespace)
    if namespace.interactive or namespace.product is None:
        DatabaseQueryApp(namespace.cve, namespace.product).run()
        return

    arguments = QueryArguments(
        cve=namespace.cve,
        product=namespace.product,
        version=namespace.version,
        update=namespace.update,
        raw=namespace.raw,
        debug=namespace.debug,
    )
    asyncio.run(run_query(arguments))


if __name__ == "__main__":
    main()
