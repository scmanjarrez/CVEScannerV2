# SPDX-License-Identifier: GPL-3.0-or-later
"""Apply product version filters to database query results.

Normalize stored rows and coordinate exact and ranged product queries.
"""

import logging
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from db_manager.infrastructure.query_store import (
    related,
    related_multi,
)
from db_manager.infrastructure.query_store import (
    suggest_product as find_product,
)
from db_manager.infrastructure.storage import Database

logger = logging.getLogger(__name__)


class QueryArguments(BaseModel):
    """Hold validated query options.

    Attributes:
        cve: SQLite database path.
        product: Product name to search.
        version: Optional product version filter.
        update: Optional product update filter.
        raw: Whether to print unfiltered rows.
        debug: Whether to log rejected version comparisons.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    cve: Path = Field(description="SQLite database path.")
    product: str = Field(description="Product name to search.")
    version: str | None = Field(description="Optional product version filter.")
    update: str | None = Field(description="Optional product update filter.")
    raw: bool = Field(description="Whether to print unfiltered rows.")
    debug: bool = Field(
        description="Whether to log rejected version comparisons."
    )


class QueryResultSet(BaseModel):
    """Hold raw and filtered database query results.

    Attributes:
        raw_exact: Unfiltered exact-version rows.
        raw_ranges: Unfiltered version-range rows.
        exact: Exact-version rows matching the optional version filter.
        ranges: Version-range rows matching the optional version filter.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    raw_exact: list[list[str]] = Field(
        description="Unfiltered exact-version rows."
    )
    raw_ranges: list[list[str]] = Field(
        description="Unfiltered version-range rows."
    )
    exact: list[list[str]] = Field(
        description="Exact-version rows matching the optional version filter."
    )
    ranges: list[list[str]] = Field(
        description="Version-range rows matching the optional version filter."
    )


def clean(data: Sequence[Sequence[object]]) -> list[list[str]]:
    """Convert database values into printable table cells.

    Args:
        data: Rows returned by the asynchronous SQLAlchemy queries.

    Returns:
        String rows; the last cell is 'EDB MSF', 'EDB', 'MSF' or '-'.
    """
    final: list[list[str]] = []
    for row in data:
        cleaned: list[str] = []
        for value in row[:-2]:
            if value is None:
                cleaned.append("")
            elif value == "-":
                cleaned.append("*")
            else:
                cleaned.append(str(value))
        flags = [
            name
            for name, present in zip(("EDB", "MSF"), row[-2:], strict=True)
            if present
        ]
        cleaned.append(" ".join(flags) or "-")
        final.append(cleaned)
    return final


def _version_part(value: str) -> tuple[bool, int | str]:
    """Return a comparable token for one dotted version component.

    Args:
        value: Version component to normalize.

    Returns:
        Numeric components sort numerically; other components sort by text.
    """
    try:
        return True, int(value)
    except ValueError:
        return False, value.lower()


def compare_version(
    user_version: str,
    db_version: str,
    user_update: str | None,
    db_update: str | None,
) -> int:
    """Compare a requested version with one database version.

    Args:
        user_version: Version observed by the user.
        db_version: Version stored in the database.
        user_update: Optional update observed by the user.
        db_update: Update stored in the database.

    Returns:
        Zero for a match, -1 or 1 for ordering, or -2 for update mismatch.
    """
    if db_version == "-":
        db_version = "*"
    if user_version == db_version and (
        user_update is None or db_update in {"*", user_update}
    ):
        return 0

    user_parts = user_version.split(".")
    db_parts = db_version.split(".")
    max_parts = max(len(user_parts), len(db_parts))
    user_parts.extend(["0"] * (max_parts - len(user_parts)))
    db_parts.extend(["0"] * (max_parts - len(db_parts)))
    for user_part, db_part in zip(user_parts, db_parts, strict=True):
        user_token = _version_part(user_part)
        db_token = _version_part(db_part)
        if user_token < db_token:
            return -1
        if user_token > db_token:
            return 1
    if user_update is not None and user_update != db_update:
        return -2
    return 0


def _filter_exact(
    data: Sequence[list[str]],
    version: str | None,
    update: str | None,
    *,
    debug: bool,
) -> list[list[str]]:
    """Keep exact-version rows that match the requested version.

    Args:
        data: Formatted exact-version rows.
        version: Optional requested version.
        update: Optional requested update.
        debug: Whether to log rejected comparisons.

    Returns:
        Matching exact-version rows.
    """
    if version is None:
        return list(data)
    results: list[list[str]] = []
    for row in data:
        database_version = row[5]
        database_update = row[6]
        if database_version == "*":
            results.append(row)
            continue
        comparison = compare_version(
            version,
            database_version,
            update,
            database_update or None,
        )
        if comparison == 0:
            results.append(row)
        elif debug:
            logger.info(
                "Version mismatch for %s: requested %s, stored %s",
                row[0],
                version,
                database_version,
            )
    return results


def _filter_ranges(
    data: Sequence[list[str]],
    version: str | None,
    *,
    debug: bool,
) -> list[list[str]]:
    """Keep range rows that contain the requested version.

    Args:
        data: Formatted version-range rows.
        version: Optional requested version.
        debug: Whether to log rejected comparisons.

    Returns:
        Matching version-range rows.
    """
    if version is None:
        return list(data)
    results: list[list[str]] = []
    for row in data:
        start_including, start_excluding = row[5], row[6]
        end_including, end_excluding = row[7], row[8]
        if (
            start_including
            and compare_version(version, start_including, None, None) < 0
        ):
            continue
        if (
            start_excluding
            and compare_version(version, start_excluding, None, None) <= 0
        ):
            continue
        if (
            end_including
            and compare_version(version, end_including, None, None) > 0
        ):
            continue
        if (
            end_excluding
            and compare_version(version, end_excluding, None, None) >= 0
        ):
            continue
        results.append(row)
    if debug and not results and data:
        logger.info("No version ranges include %s", version)
    return results


async def fetch_results(args: QueryArguments) -> QueryResultSet:
    """Fetch raw and version-filtered CVE rows for the product.

    Args:
        args: Database path, product, version, and output options.

    Returns:
        Raw exact and ranged rows together with the filtered result rows.
    """
    if args.debug:
        logging.basicConfig(
            format="%(asctime)s - %(message)s",
            level=logging.INFO,
        )
    async with Database(args.cve) as database:
        exact_rows = await related(database, args.product)
        range_rows = await related_multi(database, args.product)

    raw_exact = clean(exact_rows)
    raw_ranges = clean(range_rows)
    return QueryResultSet(
        raw_exact=raw_exact,
        raw_ranges=raw_ranges,
        exact=_filter_exact(
            raw_exact,
            args.version,
            args.update,
            debug=args.debug,
        ),
        ranges=_filter_ranges(raw_ranges, args.version, debug=args.debug),
    )


async def suggest_product(database_path: Path, prefix: str) -> str | None:
    """Return the first product name matching an autocomplete prefix.

    Args:
        database_path: SQLite database file path.
        prefix: Product name prefix entered by the user.

    Returns:
        The first matching product name, or None when there is no match.
    """
    return await find_product(database_path, prefix)
