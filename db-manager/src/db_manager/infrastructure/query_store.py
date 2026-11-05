# SPDX-License-Identifier: GPL-3.0-or-later

"""Read CVE, product, and reference rows from the SQLite database.

Convert SQLAlchemy query results into the shapes used by the application.
"""

from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import select

from db_manager.constants import EXACT_COLUMN_COUNT, RANGED_COLUMN_COUNT

from .storage import (
    AffectedModel,
    CveModel,
    Database,
    MultiAffectedModel,
    ProductModel,
    ReferencedExploitModel,
    ReferencedMetasploitModel,
)

ExactRow = tuple[
    str,
    str,
    str | None,
    str | None,
    str | None,
    str | None,
    bool,
    bool,
]

RangedRow = tuple[
    str,
    str,
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
    bool,
    bool,
]


async def related(database: Database, product: str) -> list[ExactRow]:
    """Return exact-version CVEs associated with one product name.

    Args:
        database: Active asynchronous SQLAlchemy database session.
        product: Product name to search.

    Returns:
        CVE score, product identity, and reference-presence rows.
    """
    exploit_exists = (
        select(ReferencedExploitModel.exploit_id)
        .where(ReferencedExploitModel.cve_id == AffectedModel.cve_id)
        .exists()
        .label("edb")
    )
    metasploit_exists = (
        select(ReferencedMetasploitModel.metasploit_id)
        .where(ReferencedMetasploitModel.cve_id == AffectedModel.cve_id)
        .exists()
        .label("msf")
    )
    statement = (
        select(
            AffectedModel.cve_id,
            CveModel.cvss_v2,
            CveModel.cvss_v3,
            CveModel.cvss_v4,
            ProductModel.vendor,
            ProductModel.product,
            ProductModel.version,
            ProductModel.version_update,
            exploit_exists,
            metasploit_exists,
        )
        .join(
            ProductModel, ProductModel.product_id == AffectedModel.product_id
        )
        .join(CveModel, CveModel.cve_id == AffectedModel.cve_id)
        .where(ProductModel.product == product)
    )
    result = await database.session.execute(statement)
    return [_exact_row(row) for row in result.tuples().all()]


async def related_multi(
    database: Database,
    product: str,
) -> list[RangedRow]:
    """Return version-range CVEs associated with one product name.

    Args:
        database: Active asynchronous SQLAlchemy database session.
        product: Product name to search.

    Returns:
        CVE scores, product identity, range bounds, and reference flags.
    """
    exploit_exists = (
        select(ReferencedExploitModel.exploit_id)
        .where(ReferencedExploitModel.cve_id == MultiAffectedModel.cve_id)
        .exists()
        .label("edb")
    )
    metasploit_exists = (
        select(ReferencedMetasploitModel.metasploit_id)
        .where(ReferencedMetasploitModel.cve_id == MultiAffectedModel.cve_id)
        .exists()
        .label("msf")
    )
    statement = (
        select(
            MultiAffectedModel.cve_id,
            CveModel.cvss_v2,
            CveModel.cvss_v3,
            CveModel.cvss_v4,
            ProductModel.vendor,
            ProductModel.product,
            MultiAffectedModel.version_start_including,
            MultiAffectedModel.version_start_excluding,
            MultiAffectedModel.version_end_including,
            MultiAffectedModel.version_end_excluding,
            exploit_exists,
            metasploit_exists,
        )
        .join(CveModel, CveModel.cve_id == MultiAffectedModel.cve_id)
        .join(
            ProductModel,
            ProductModel.product_id == MultiAffectedModel.product_id,
        )
        .where(ProductModel.product == product)
    )
    result = await database.session.execute(statement)
    return [_ranged_row(row) for row in result.tuples().all()]


def _required_text(value: object, column: str) -> str:
    """Validate a non-null text value returned by a database query.

    Args:
        value: Raw value returned by SQLAlchemy.
        column: Name of the column being validated.

    Returns:
        Validated text value.

    Raises:
        TypeError: If the value is not text.
    """
    if isinstance(value, str):
        return value
    message = f"Query column {column} is not text"
    raise TypeError(message)


def _optional_text(value: object, column: str) -> str | None:
    """Validate a nullable text value returned by a database query.

    Args:
        value: Raw value returned by SQLAlchemy.
        column: Name of the column being validated.

    Returns:
        Validated text value or None.

    Raises:
        TypeError: If the value is neither text nor None.
    """
    if value is None or isinstance(value, str):
        return value
    message = f"Query column {column} is not nullable text"
    raise TypeError(message)


def _required_bool(value: object, column: str) -> bool:
    """Validate a boolean value returned by a database query.

    Args:
        value: Raw value returned by SQLAlchemy.
        column: Name of the column being validated.

    Returns:
        Validated boolean value.

    Raises:
        TypeError: If the value is not boolean.
    """
    if isinstance(value, bool):
        return value
    message = f"Query column {column} is not boolean"
    raise TypeError(message)


def cvss_text(
    cvss_v2: str | None,
    cvss_v3: str | None,
    cvss_v4: str | None,
) -> str:
    """Join the available CVSS scores into one display text.

    Present scores are listed from v4 to v2, each as 'version:score' and
    separated by spaces. Scores are shown with one decimal place.

    Args:
        cvss_v2: CVSS v2 score, or None when absent.
        cvss_v3: CVSS v3 score, or None when absent.
        cvss_v4: CVSS v4 score, or None when absent.

    Returns:
        Joined score text, or '-' when no score is present.
    """
    scores = (("v4", cvss_v4), ("v3", cvss_v3), ("v2", cvss_v2))
    parts = [
        f"{label}:{float(score):.1f}"
        for label, score in scores
        if score is not None
    ]
    return " ".join(parts) if parts else "-"


def _exact_row(row: Sequence[object]) -> ExactRow:
    """Validate and type one exact-version query result.

    Args:
        row: Values returned by the exact-version SQL query.

    Returns:
        A typed row with product identity and reference flags.

    Raises:
        ValueError: If the query returned an unexpected number of columns.
        TypeError: If a value does not match the expected database type.
    """
    if len(row) != EXACT_COLUMN_COUNT:
        message = "Exact-version query returned an unexpected row"
        raise ValueError(message)
    return (
        _required_text(row[0], "cve_id"),
        cvss_text(
            _optional_text(row[1], "cvss_v2"),
            _optional_text(row[2], "cvss_v3"),
            _optional_text(row[3], "cvss_v4"),
        ),
        _optional_text(row[4], "vendor"),
        _optional_text(row[5], "product"),
        _optional_text(row[6], "version"),
        _optional_text(row[7], "version_update"),
        _required_bool(row[8], "exploit_exists"),
        _required_bool(row[9], "metasploit_exists"),
    )


def _ranged_row(row: Sequence[object]) -> RangedRow:
    """Validate and type one version-range query result.

    Args:
        row: Values returned by the version-range SQL query.

    Returns:
        A typed row with range bounds and reference flags.

    Raises:
        ValueError: If the query returned an unexpected number of columns.
        TypeError: If a value does not match the expected database type.
    """
    if len(row) != RANGED_COLUMN_COUNT:
        message = "Version-range query returned an unexpected row"
        raise ValueError(message)
    return (
        _required_text(row[0], "cve_id"),
        cvss_text(
            _optional_text(row[1], "cvss_v2"),
            _optional_text(row[2], "cvss_v3"),
            _optional_text(row[3], "cvss_v4"),
        ),
        _optional_text(row[4], "vendor"),
        _optional_text(row[5], "product"),
        _optional_text(row[6], "version_start_including"),
        _optional_text(row[7], "version_start_excluding"),
        _optional_text(row[8], "version_end_including"),
        _optional_text(row[9], "version_end_excluding"),
        _required_bool(row[10], "exploit_exists"),
        _required_bool(row[11], "metasploit_exists"),
    )


async def suggest_product(database_path: Path, prefix: str) -> str | None:
    """Return the first product name matching an autocomplete prefix.

    Args:
        database_path: SQLite database file path.
        prefix: Product name prefix entered by the user.

    Returns:
        The first matching product name, or None when there is no match.
    """
    if not prefix:
        return None
    async with Database(database_path) as database:
        products = await database.session.scalars(
            select(ProductModel.product)
            .where(ProductModel.product.is_not(None))
            .where(ProductModel.product.istartswith(prefix, autoescape=True))
            .distinct()
            .order_by(ProductModel.product)
            .limit(1)
        )
        return products.first()
