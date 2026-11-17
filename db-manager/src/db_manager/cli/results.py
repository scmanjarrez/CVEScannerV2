# SPDX-License-Identifier: GPL-3.0-or-later

"""Render one-off query results in the terminal.

Format exact-version and version-range records with Rich tables.
"""

from collections.abc import Sequence

from rich.console import Console
from rich.table import Table
from rich.text import Text

from db_manager.constants import EXACT_HEADERS, RANGE_HEADERS

console = Console()


def _result_table(
    title: str,
    headers: Sequence[str],
    data: Sequence[Sequence[str]],
) -> Table:
    """Build a styled Rich table for query results.

    Args:
        title: Table title.
        headers: Column labels.
        data: Rows to render.

    Returns:
        A Rich table populated with the provided data.
    """
    table = Table(title=title, header_style="bold cyan", show_lines=False)
    for header in headers:
        table.add_column(header, justify="center", overflow="fold")
    for row in data:
        table.add_row(*(Text(value) for value in row))
    return table


def print_affected(data: Sequence[Sequence[str]]) -> None:
    """Print exact-version CVE rows.

    Args:
        data: Formatted exact-version CVE rows.
    """
    if not data:
        console.print("[yellow]No data found.[/]")
        return
    console.print(_result_table("Exact-version matches", EXACT_HEADERS, data))


def print_multi(data: Sequence[Sequence[str]]) -> None:
    """Print version-range CVE rows.

    Args:
        data: Formatted version-range CVE rows.
    """
    if not data:
        console.print("[yellow]No data found.[/]")
        return
    console.print(_result_table("Version-range matches", RANGE_HEADERS, data))
