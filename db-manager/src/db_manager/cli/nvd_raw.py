# SPDX-License-Identifier: GPL-3.0-or-later

"""Expose the command-line entry point for raw NVD downloads.

Parse download options and run the asynchronous raw-page workflow.
"""

import argparse
import asyncio
from datetime import UTC, datetime
from pathlib import Path

from rich_argparse import RichHelpFormatter

from db_manager.application.raw_download import (
    DEFAULT_ENDPOINTS,
    NvdEndpoint,
    RawDownloadArguments,
    run_raw_download,
)
from db_manager.constants import DEFAULT_NVD_RAW_DIR


class RawDownloadNamespace(argparse.Namespace):
    """Hold typed command-line arguments for raw NVD downloads.

    Attributes:
        output: Root directory receiving the downloaded pages.
        since: UTC start of the modification window, or None for a full
            snapshot.
        endpoint: Endpoints selected with repeated options, or None.
    """

    output: Path
    since: datetime | None
    endpoint: list[NvdEndpoint] | None


def _parse_since(value: str) -> datetime:
    """Parse a UTC start date or timestamp for incremental downloads.

    Args:
        value: ISO 8601 date or timestamp, such as '2026-01-31'.

    Returns:
        Timezone-aware UTC datetime that is not in the future.

    Raises:
        argparse.ArgumentTypeError: If the value is malformed or future.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        message = f"invalid ISO 8601 date: {value}"
        raise argparse.ArgumentTypeError(message) from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    if parsed > datetime.now(UTC):
        message = f"date is in the future: {value}"
        raise argparse.ArgumentTypeError(message)
    return parsed


def _parse_endpoint(value: str) -> NvdEndpoint:
    """Convert an endpoint name into a typed NVD collection.

    Args:
        value: Endpoint name, either 'cves' or 'cpes'.

    Returns:
        The matching NVD endpoint.

    Raises:
        argparse.ArgumentTypeError: If the name is not supported.
    """
    if value == "cves":
        return "cves"
    if value == "cpes":
        return "cpes"
    message = f"unsupported endpoint: {value}"
    raise argparse.ArgumentTypeError(message)


def main() -> None:
    """Parse command-line arguments and store raw NVD pages locally.

    Convert parsed values into the typed application arguments.
    """
    parser = argparse.ArgumentParser(
        description="Store raw NVD API pages locally",
        formatter_class=RichHelpFormatter,
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_NVD_RAW_DIR,
        type=Path,
        help="Directory receiving the raw pages",
    )
    parser.add_argument(
        "-s",
        "--since",
        default=None,
        type=_parse_since,
        help=(
            "Only fetch records modified since this UTC date (YYYY-MM-DD). "
            "Omit for a full snapshot"
        ),
    )
    parser.add_argument(
        "-e",
        "--endpoint",
        action="append",
        type=_parse_endpoint,
        help="NVD endpoint to download: cves or cpes; repeat for both "
        "(default: both)",
    )
    namespace = RawDownloadNamespace()
    parser.parse_args(namespace=namespace)
    asyncio.run(
        run_raw_download(
            RawDownloadArguments(
                output=namespace.output,
                since=namespace.since,
                endpoints=(
                    tuple(namespace.endpoint)
                    if namespace.endpoint
                    else DEFAULT_ENDPOINTS
                ),
            )
        )
    )


if __name__ == "__main__":
    main()
