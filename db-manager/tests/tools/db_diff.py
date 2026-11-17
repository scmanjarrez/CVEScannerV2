# SPDX-License-Identifier: GPL-3.0-or-later

"""Compare two scanner SQLite databases by natural key.

Run from the db-manager directory with
``python -m tests.tools.db_diff BASE.db NEW.db``.

Both databases are opened read-only. Tables are compared by natural key
instead of autoincrement identifiers. Each table is streamed in a fixed
ORDER BY and reduced to a row count and a SHA-256 digest. Only tables
whose digest differs are inspected further with EXCEPT queries that
return a few example rows per side.

The sync and collection checkpoint tables are compared by row count only.
The metadata table keeps only last_mod: its surrogate id is not
meaningful, and last_mod comes from NVD data rather than the local clock.
"""

import argparse
import hashlib
import sqlite3
import sys
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Final

MAX_EXAMPLES: Final = 5
MAX_EXAMPLES_TEMPLATE: Final = "{query} LIMIT ?"
EXCEPT_TEMPLATE: Final = (
    "SELECT * FROM ({left}) EXCEPT SELECT * FROM ({right})"
)
COUNT_TEMPLATE: Final = "SELECT COUNT(*) FROM ({query})"

NATURAL_QUERIES: Final[dict[str, str]] = {
    "products": (
        "SELECT vendor, product, version, version_update "
        "FROM {schema}.products "
        "ORDER BY 1, 2, 3, 4"
    ),
    "affected": (
        "SELECT a.cve_id, p.vendor, p.product, p.version, p.version_update "
        "FROM {schema}.affected AS a "
        "JOIN {schema}.products AS p ON p.product_id = a.product_id "
        "ORDER BY 1, 2, 3, 4, 5"
    ),
    "multiaffected": (
        "SELECT m.cve_id, p.vendor, p.product, p.version, p.version_update, "
        'm."versionStartIncluding", m."versionStartExcluding", '
        'm."versionEndIncluding", m."versionEndExcluding" '
        "FROM {schema}.multiaffected AS m "
        "JOIN {schema}.products AS p ON p.product_id = m.product_id "
        "ORDER BY 1, 2, 3, 4, 5, 6, 7, 8, 9"
    ),
    "cves": (
        "SELECT cve_id, cvss_v2, cvss_v3, published "
        "FROM {schema}.cves "
        "ORDER BY 1, 2, 3, 4"
    ),
    "exploits": (
        "SELECT exploit_id, name FROM {schema}.exploits ORDER BY 1, 2"
    ),
    "metasploits": "SELECT name FROM {schema}.metasploits ORDER BY 1",
    "referenced_exploit": (
        "SELECT cve_id, exploit_id FROM {schema}.referenced_exploit "
        "ORDER BY 1, 2"
    ),
    "referenced_metasploit": (
        "SELECT r.cve_id, m.name "
        "FROM {schema}.referenced_metasploit AS r "
        "JOIN {schema}.metasploits AS m "
        "ON m.metasploit_id = r.metasploit_id "
        "ORDER BY 1, 2"
    ),
    "metadata": "SELECT last_mod FROM {schema}.metadata ORDER BY 1",
}
CHECKPOINT_COUNT_TEMPLATE: Final = "SELECT 1 FROM {schema}.{table}"
CHECKPOINT_TABLES: Final = ("nvd_sync", "nvd_collections", "nvd_pages")
BASE_SCHEMA: Final = "base"
NEW_SCHEMA: Final = "main"


@dataclass(slots=True, frozen=True)
class TableDigest:
    """Row count and ordered digest of one table.

    Attributes:
        rows: Number of rows streamed from the table.
        digest: Hexadecimal SHA-256 over the ordered rows.
    """

    rows: int
    digest: str


@dataclass(slots=True, frozen=True)
class TableReport:
    """Comparison outcome for one table.

    Attributes:
        name: Table name as shown in the report.
        equal: Whether both databases hold the same rows.
        lines: Human-readable report lines for the table.
    """

    name: str
    equal: bool
    lines: tuple[str, ...]


class _Arguments(argparse.Namespace):
    """Typed namespace for the command-line arguments.

    Attributes:
        base: Reference database opened read-only.
        new: Candidate database opened read-only.
    """

    base: Path
    new: Path


def _emit(line: str) -> None:
    """Write one report line to standard output.

    Args:
        line: Text to write, without a trailing newline.
    """
    sys.stdout.write(f"{line}\n")


def _fill(template: str, values: Mapping[str, str]) -> str:
    """Replace named placeholders in a SQL template.

    Args:
        template: SQL text containing '{name}' placeholders.
        values: Replacement text keyed by placeholder name.

    Returns:
        The SQL text with every placeholder replaced.
    """
    filled = template
    for key, value in values.items():
        filled = filled.replace("{" + key + "}", value)
    return filled


def _read_only_uri(path: Path) -> str:
    """Return a SQLite URI that opens a database file read-only.

    Args:
        path: Database file path.

    Returns:
        A 'file:' URI carrying the 'mode=ro' parameter.
    """
    return f"{path.resolve().as_uri()}?mode=ro"


def _open_pair(base: Path, new: Path) -> sqlite3.Connection:
    """Open the candidate database and attach the reference database.

    Args:
        base: Reference database file path.
        new: Candidate database file path.

    Returns:
        A connection whose main schema is NEW and whose 'base' schema
        is BASE, both read-only.

    Raises:
        sqlite3.Error: If either database cannot be opened.
    """
    connection = sqlite3.connect(_read_only_uri(new), uri=True)
    try:
        connection.execute(
            "ATTACH DATABASE ? AS " + BASE_SCHEMA,
            (_read_only_uri(base),),
        )
    except sqlite3.Error:
        connection.close()
        raise
    return connection


def _digest(connection: sqlite3.Connection, query: str) -> TableDigest:
    """Stream a query and digest its rows in order.

    Args:
        connection: Open connection with both schemas attached.
        query: Query whose rows are already in a fixed ORDER BY.

    Returns:
        The number of rows and the SHA-256 digest of their repr values.
    """
    digest = hashlib.sha256()
    rows = 0
    for row in connection.execute(query):
        digest.update(repr(row).encode())
        rows += 1
    return TableDigest(rows=rows, digest=digest.hexdigest())


def _count(connection: sqlite3.Connection, query: str) -> int:
    """Count the rows returned by a query.

    Args:
        connection: Open connection with both schemas attached.
        query: Query whose rows are counted.

    Returns:
        The number of rows returned by the query.
    """
    sql = _fill(COUNT_TEMPLATE, {"query": query})
    (count,) = connection.execute(sql).fetchone()
    return int(count)


def _examples(
    connection: sqlite3.Connection,
    left: str,
    right: str,
) -> tuple[tuple[object, ...], ...]:
    """Return up to MAX_EXAMPLES rows present in left but not in right.

    Args:
        connection: Open connection with both schemas attached.
        left: Query for the rows that may be missing from right.
        right: Query whose rows are excluded.

    Returns:
        Example rows, at most MAX_EXAMPLES entries.
    """
    except_sql = _fill(EXCEPT_TEMPLATE, {"left": left, "right": right})
    sql = _fill(MAX_EXAMPLES_TEMPLATE, {"query": except_sql})
    return tuple(
        tuple(row) for row in connection.execute(sql, (MAX_EXAMPLES,))
    )


def _compare_natural(
    connection: sqlite3.Connection,
    name: str,
    template: str,
) -> TableReport:
    """Compare one table by natural key.

    Args:
        connection: Open connection with both schemas attached.
        name: Table name used in the report.
        template: Query template containing the schema placeholder.

    Returns:
        The comparison outcome with its report lines.
    """
    base_query = _fill(template, {"schema": BASE_SCHEMA})
    new_query = _fill(template, {"schema": NEW_SCHEMA})
    base = _digest(connection, base_query)
    new = _digest(connection, new_query)
    if base == new:
        return TableReport(
            name=name,
            equal=True,
            lines=(f"{name}: OK {new.rows} filas",),
        )

    only_base = _count(
        connection,
        _fill(EXCEPT_TEMPLATE, {"left": base_query, "right": new_query}),
    )
    only_new = _count(
        connection,
        _fill(EXCEPT_TEMPLATE, {"left": new_query, "right": base_query}),
    )
    header = (
        f"{name}: DIFF (base={base.rows}, new={new.rows}, "
        f"solo en base={only_base}, solo en new={only_new})"
    )
    lines = [header]
    lines.extend(
        f"  solo en BASE: {row!r}"
        for row in _examples(connection, base_query, new_query)
    )
    lines.extend(
        f"  solo en NEW: {row!r}"
        for row in _examples(connection, new_query, base_query)
    )
    return TableReport(name=name, equal=False, lines=tuple(lines))


def _compare_checkpoint(
    connection: sqlite3.Connection, name: str
) -> TableReport:
    """Compare one checkpoint table by row count only.

    Args:
        connection: Open connection with both schemas attached.
        name: Checkpoint table name.

    Returns:
        The comparison outcome with its report line.
    """
    base_count = _count(
        connection,
        _fill(
            CHECKPOINT_COUNT_TEMPLATE,
            {"schema": BASE_SCHEMA, "table": name},
        ),
    )
    new_count = _count(
        connection,
        _fill(
            CHECKPOINT_COUNT_TEMPLATE,
            {"schema": NEW_SCHEMA, "table": name},
        ),
    )
    if base_count == new_count:
        return TableReport(
            name=name,
            equal=True,
            lines=(f"{name}: OK {new_count} filas (solo conteo)",),
        )
    return TableReport(
        name=name,
        equal=False,
        lines=(
            f"{name}: DIFF (solo conteo, base={base_count}, new={new_count})",
        ),
    )


def _compare_all(connection: sqlite3.Connection) -> list[TableReport]:
    """Compare every table and return the reports in a fixed order.

    A table that cannot be read in either database is reported as DIFF
    with the SQLite error message instead of aborting the whole run.

    Args:
        connection: Open connection with both schemas attached.

    Returns:
        One report per compared table.
    """
    reports: list[TableReport] = []
    for name, template in NATURAL_QUERIES.items():
        try:
            reports.append(_compare_natural(connection, name, template))
        except sqlite3.OperationalError as err:
            reports.append(_error_report(name, err))
    for name in CHECKPOINT_TABLES:
        try:
            reports.append(_compare_checkpoint(connection, name))
        except sqlite3.OperationalError as err:
            reports.append(_error_report(name, err))
    return reports


def _error_report(name: str, err: sqlite3.OperationalError) -> TableReport:
    """Build a DIFF report for a table that SQLite could not read.

    Args:
        name: Table name used in the report.
        err: SQLite error raised while reading the table.

    Returns:
        A failing report carrying the error message.
    """
    return TableReport(
        name=name,
        equal=False,
        lines=(f"{name}: DIFF (error al leer: {err})",),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the database comparison from the command line.

    Args:
        argv: Optional argument list; defaults to the process arguments.

    Returns:
        0 when every table matches, 1 when any table differs.
    """
    parser = argparse.ArgumentParser(
        description="Compare two scanner databases by natural key.",
    )
    parser.add_argument("base", type=Path, help="Reference database.")
    parser.add_argument("new", type=Path, help="Candidate database.")
    args = parser.parse_args(argv, namespace=_Arguments())
    for path in (args.base, args.new):
        if not path.is_file():
            parser.error(f"no existe el fichero: {path}")

    with closing(_open_pair(args.base, args.new)) as connection:
        reports = _compare_all(connection)

    for report in reports:
        for line in report.lines:
            _emit(line)
    all_equal = all(report.equal for report in reports)
    _emit("RESULTADO: OK" if all_equal else "RESULTADO: DIFF")
    return 0 if all_equal else 1


if __name__ == "__main__":
    sys.exit(main())
