# SPDX-License-Identifier: GPL-3.0-or-later

"""Provide asynchronous SQLAlchemy models and SQLite operations.

Define the scanner schema and expose database reads and writes.
"""

from collections.abc import Sequence
from pathlib import Path
from types import TracebackType
from typing import Self

from sqlalchemy import (
    Connection,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    UniqueConstraint,
    delete,
    event,
    func,
    inspect,
    select,
    text,
    tuple_,
    update,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import URL
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import ConnectionPoolEntry
from sqlalchemy.schema import CreateIndex

from db_manager.domain.models import CpeIdentity, NvdSyncState, VersionBounds

ProductKey = tuple[str, str, str, str]
"""Vendor, product, version, and update components."""


class Base(DeclarativeBase):
    """Hold declarative SQLAlchemy metadata for the scanner database.

    Use this base to register the tables created by the database wrapper.
    """


class MetadataModel(Base):
    """Store the last successful NVD synchronization timestamp.

    Attributes:
        id: Metadata row identifier.
        last_mod: Timestamp used for the most recent NVD update.
    """

    __tablename__ = "metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_mod: Mapped[str | None] = mapped_column(String, nullable=True)


class NvdSyncModel(Base):
    """Store the singleton pending NVD synchronization scope.

    Attributes:
        id: Singleton row identifier.
        state: Serialized, validated synchronization scope.
    """

    __tablename__ = "nvd_sync"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    state: Mapped[str] = mapped_column(String, nullable=False)


class NvdCollectionModel(Base):
    """Store the result count used to validate page checkpoints.

    Attributes:
        collection: Endpoint, page size, and date filter query key.
        total_results: Result count seen on the previous attempt.
    """

    __tablename__ = "nvd_collections"

    collection: Mapped[str] = mapped_column(String, primary_key=True)
    total_results: Mapped[int] = mapped_column(Integer, nullable=False)


class NvdPageModel(Base):
    """Record pages whose data has been committed to SQLite.

    Attributes:
        collection: Query owning this page checkpoint.
        start_index: Zero-based offset of the committed page.
    """

    __tablename__ = "nvd_pages"

    collection: Mapped[str] = mapped_column(
        ForeignKey("nvd_collections.collection"), primary_key=True
    )
    start_index: Mapped[int] = mapped_column(Integer, primary_key=True)


class ExploitModel(Base):
    """Store Exploit-DB identifiers and cached titles.

    Attributes:
        exploit_id: Exploit-DB numeric identifier.
        name: Cached exploit title, or None until fetched.
    """

    __tablename__ = "exploits"

    exploit_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str | None] = mapped_column(String, nullable=True)


class MetasploitModel(Base):
    """Store unique Metasploit module names.

    Attributes:
        metasploit_id: Database identifier for the Metasploit module.
        name: Canonical Metasploit module name.
    """

    __tablename__ = "metasploits"
    __table_args__ = (UniqueConstraint("name"),)

    metasploit_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)


class CveModel(Base):
    """Store CVE scores and publication years.

    Attributes:
        cve_id: CVE identifier.
        cvss_v2: CVSS v2 score as stored by the existing schema.
        cvss_v3: CVSS v3 score as stored by the existing schema.
        cvss_v4: CVSS v4 score as stored by the schema.
        published: Publication year.
    """

    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    cvss_v2: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_v3: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_v4: Mapped[str | None] = mapped_column(String, nullable=True)
    published: Mapped[int] = mapped_column(Integer, nullable=False)


class ProductModel(Base):
    """Store unique CPE product identities.

    Attributes:
        product_id: Database identifier for the product.
        vendor: CPE vendor component.
        product: CPE product component.
        version: CPE version component.
        version_update: CPE update component.
    """

    __tablename__ = "products"
    __table_args__ = (
        UniqueConstraint("vendor", "product", "version", "version_update"),
    )

    product_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    product: Mapped[str | None] = mapped_column(String, nullable=True)
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    version_update: Mapped[str | None] = mapped_column(String, nullable=True)


class AffectedModel(Base):
    """Link CVEs to exact affected product records.

    Attributes:
        cve_id: Affected CVE identifier.
        product_id: Exact affected product identifier.
    """

    __tablename__ = "affected"

    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.cve_id"), primary_key=True
    )
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.product_id"), primary_key=True
    )


class MultiAffectedModel(Base):
    """Link CVEs to products affected within version bounds.

    Attributes:
        cve_id: Affected CVE identifier.
        product_id: Product identifier with a version range.
        version_start_including: Inclusive lower version bound.
        version_start_excluding: Exclusive lower version bound.
        version_end_including: Inclusive upper version bound.
        version_end_excluding: Exclusive upper version bound.
    """

    __tablename__ = "multiaffected"

    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.cve_id"), primary_key=True
    )
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.product_id"), primary_key=True
    )
    version_start_including: Mapped[str | None] = mapped_column(
        "versionStartIncluding", String, primary_key=True, nullable=True
    )
    version_start_excluding: Mapped[str | None] = mapped_column(
        "versionStartExcluding", String, primary_key=True, nullable=True
    )
    version_end_including: Mapped[str | None] = mapped_column(
        "versionEndIncluding", String, primary_key=True, nullable=True
    )
    version_end_excluding: Mapped[str | None] = mapped_column(
        "versionEndExcluding", String, primary_key=True, nullable=True
    )


MULTIAFFECTED_BOUNDS_INDEX = Index(
    "uq_multiaffected_bounds",
    MultiAffectedModel.cve_id,
    MultiAffectedModel.product_id,
    func.coalesce(MultiAffectedModel.version_start_including, ""),
    func.coalesce(MultiAffectedModel.version_start_excluding, ""),
    func.coalesce(MultiAffectedModel.version_end_including, ""),
    func.coalesce(MultiAffectedModel.version_end_excluding, ""),
    unique=True,
)
"""Unique index that treats NULL version bounds as equal values."""


class ConditionModel(Base):
    """Link CVEs configuration conditions to product and platform.

    Attributes:
        cve_id: Affected CVE identifier.
        product_id: Vulnerable product identifier.
        config_idx: Zero-based configuration index within the CVE.
        part: Platform CPE part component.
        vendor: Platform CPE vendor component.
        product: Platform CPE product component.
    """

    __tablename__ = "conditions"

    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.cve_id"), primary_key=True
    )
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.product_id"), primary_key=True
    )
    config_idx: Mapped[int] = mapped_column(Integer, primary_key=True)
    part: Mapped[str] = mapped_column(String, primary_key=True)
    vendor: Mapped[str] = mapped_column(String, primary_key=True)
    product: Mapped[str] = mapped_column(String, primary_key=True)


class AliasModel(Base):
    """Record one deprecated application CPE and its replacing product.

    Attributes:
        old_vendor: Vendor of the deprecated CPE.
        old_product: Product of the deprecated CPE.
        old_version: Version of the deprecated CPE.
        old_update: Update of the deprecated CPE.
        new_vendor: Vendor of the replacing CPE.
        new_product: Product of the replacing CPE.
    """

    __tablename__ = "aliases"

    old_vendor: Mapped[str] = mapped_column(String, primary_key=True)
    old_product: Mapped[str] = mapped_column(String, primary_key=True)
    old_version: Mapped[str] = mapped_column(String, primary_key=True)
    old_update: Mapped[str] = mapped_column(String, primary_key=True)
    new_vendor: Mapped[str] = mapped_column(String, primary_key=True)
    new_product: Mapped[str] = mapped_column(String, primary_key=True)


class ReferencedExploitModel(Base):
    """Link CVEs to referenced Exploit-DB records.

    Attributes:
        cve_id: Referencing CVE identifier.
        exploit_id: Referenced Exploit-DB identifier.
    """

    __tablename__ = "referenced_exploit"

    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.cve_id"), primary_key=True
    )
    exploit_id: Mapped[int] = mapped_column(
        ForeignKey("exploits.exploit_id"), primary_key=True
    )


class ReferencedMetasploitModel(Base):
    """Link CVEs to referenced Metasploit records.

    Attributes:
        cve_id: Referencing CVE identifier.
        metasploit_id: Referenced Metasploit identifier.
    """

    __tablename__ = "referenced_metasploit"

    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.cve_id"), primary_key=True
    )
    metasploit_id: Mapped[int] = mapped_column(
        ForeignKey("metasploits.metasploit_id"), primary_key=True
    )


# Renamed products: an old name qualifies when at least half of its catalog
# entries were replaced by the new one. This drops partial deprecations of
# products that are still current, such as one platform of a product.
PRODUCT_ALIASES_VIEW = """
CREATE VIEW IF NOT EXISTS product_aliases AS
SELECT old_vendor, old_product, new_vendor, new_product
FROM aliases
GROUP BY old_vendor, old_product, new_vendor, new_product
HAVING COUNT(*) * 2 >= (
    SELECT COUNT(*) FROM products
    WHERE products.vendor = aliases.old_vendor
      AND products.product = aliases.old_product
)
"""


def _core_table(name: str) -> Table:
    """Return a scanner table for SQLAlchemy Core statements.

    Args:
        name: Table name registered in the declarative metadata.

    Returns:
        Table object used by SQLAlchemy Core statements.
    """
    return Base.metadata.tables[name]


def _has_cvss_v4_column(sync_connection: Connection) -> bool:
    """Report whether the cves table already has the cvss_v4 column.

    Args:
        sync_connection: Synchronous connection used by the inspector.

    Returns:
        True when the cvss_v4 column exists in the cves table.
    """
    columns = inspect(sync_connection).get_columns("cves")
    return any(column["name"] == "cvss_v4" for column in columns)


async def _add_missing_cvss_v4(connection: AsyncConnection) -> None:
    """Add the cvss_v4 column to databases created before it existed.

    Args:
        connection: Asynchronous connection used to alter the cves table.
    """
    if await connection.run_sync(_has_cvss_v4_column):
        return
    await connection.execute(text("ALTER TABLE cves ADD COLUMN cvss_v4 TEXT"))


async def _remove_duplicate_multiaffected(
    connection: AsyncConnection,
) -> None:
    """Delete identical multiaffected rows left by NULL primary keys.

    SQLite treats NULL values as distinct in primary keys, so older
    databases can hold identical rows. Keep the first row of each group
    so the unique bounds index can be created. Do nothing when the table
    does not exist yet.

    Args:
        connection: Asynchronous connection used to delete duplicate rows.
    """
    exists = await connection.execute(
        text(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'multiaffected'
            """
        )
    )
    if exists.first() is None:
        return
    _ = await connection.execute(
        text(
            """
            DELETE FROM multiaffected WHERE rowid NOT IN (
                SELECT min(rowid) FROM multiaffected GROUP BY
                    cve_id, product_id,
                    coalesce("versionStartIncluding", ''),
                    coalesce("versionStartExcluding", ''),
                    coalesce("versionEndIncluding", ''),
                    coalesce("versionEndExcluding", '')
            )
            """
        )
    )


def _configure_connection(
    dbapi_connection: DBAPIConnection,
    connection_record: ConnectionPoolEntry,
) -> None:
    """Configure SQLite pragmas on each pooled connection.

    Enable foreign-key checks, relax fsync to NORMAL, and enlarge the page
    cache and temporary storage to speed up bulk writes.

    Args:
        dbapi_connection: Adapted SQLite DBAPI connection.
        connection_record: Connection pool entry receiving the connection.
    """
    del connection_record
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA cache_size=-262144")
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.close()


class Database:
    """Provide asynchronous operations for the scanner SQLite database.

    Attributes:
        path: SQLite database file path.
        engine: Asynchronous SQLAlchemy engine.
        session: Asynchronous ORM session.
    """

    def __init__(self: Self, path: Path) -> None:
        """Initialize an asynchronous SQLite database connection.

        Args:
            path: SQLite database file path.
        """
        self.path = path
        database_url = URL.create(
            "sqlite+aiosqlite",
            database=path.as_posix(),
        )
        self.engine: AsyncEngine = create_async_engine(database_url)
        event.listen(
            self.engine.sync_engine,
            "connect",
            _configure_connection,
        )
        session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine,
            expire_on_commit=False,
        )
        self.session: AsyncSession = session_factory()

    async def __aenter__(self: Self) -> Self:
        """Return this database wrapper as an asynchronous context manager.

        Returns:
            This database wrapper.
        """
        return self

    async def __aexit__(
        self: Self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit successful work or roll back failed work, then close.

        Args:
            exc_type: Exception type raised inside the context, if any.
            exc: Exception raised inside the context, if any.
            traceback: Traceback for the exception, if any.
        """
        try:
            if exc_type is None:
                await self.session.commit()
            else:
                await self.session.rollback()
        finally:
            await self.session.close()
            await self.engine.dispose()

    async def setup(self: Self) -> None:
        """Create the database tables when they do not already exist.

        Run SQLAlchemy schema creation through the asynchronous engine.
        """
        async with self.engine.begin() as connection:
            await _remove_duplicate_multiaffected(connection)
            await connection.run_sync(Base.metadata.create_all)
            await connection.execute(
                CreateIndex(MULTIAFFECTED_BOUNDS_INDEX, if_not_exists=True)
            )
            await _add_missing_cvss_v4(connection)
            await connection.execute(text(PRODUCT_ALIASES_VIEW))

    async def commit(self: Self) -> None:
        """Commit the active batch of database changes.

        Persist all pending writes in the current asynchronous session.
        """
        await self.session.commit()

    async def cached_metadata(self: Self) -> str | None:
        """Return the timestamp of the previous successful NVD update.

        Returns:
            Stored timestamp, or None when metadata is not initialized.
        """
        statement = select(MetadataModel.last_mod).limit(1)
        return await self.session.scalar(statement)

    async def pending_nvd_sync(self: Self) -> NvdSyncState | None:
        """Read the scope saved before an unfinished NVD download.

        Returns:
            Pending synchronization state, or None for a new run.

        Raises:
            ValidationError: If the saved synchronization scope is invalid.
        """
        state = await self.session.scalar(select(NvdSyncModel.state))
        if state is None:
            return None
        return NvdSyncState.model_validate_json(state)

    async def save_nvd_sync(self: Self, state: NvdSyncState) -> None:
        """Save the scope before issuing the first paginated request.

        Args:
            state: Fixed query windows and original synchronization cutoff.
        """
        await self.session.execute(
            sqlite_insert(NvdSyncModel).values(
                id=1, state=state.model_dump_json()
            )
        )

    async def prepare_nvd_collection(
        self: Self,
        collection: str,
        total_results: int,
        page_size: int,
        *,
        incremental: bool,
    ) -> set[int]:
        """Validate checkpoints against fresh collection metadata.

        Args:
            collection: Stable endpoint, page size, and filter query key.
            total_results: Current result count reported by NVD.
            page_size: Maximum number of records in each requested page.
            incremental: Whether last-modified filters can remove records.

        Returns:
            Page offsets that can be skipped safely on this attempt.
        """
        previous = await self.session.get(NvdCollectionModel, collection)
        completed = set(
            await self.session.scalars(
                select(NvdPageModel.start_index).where(
                    NvdPageModel.collection == collection
                )
            )
        )
        if previous is not None and previous.total_results != total_results:
            # Full catalogues are ordered by creation/publication date. If
            # they grow, retain only the contiguous prefix of full pages.
            # Replay holes, out-of-order pages, and the former partial tail.
            prefix = 0
            if not incremental and total_results > previous.total_results:
                while (
                    prefix in completed
                    and prefix + page_size <= previous.total_results
                ):
                    prefix += page_size
            await self.session.execute(
                delete(NvdPageModel).where(
                    NvdPageModel.collection == collection,
                    NvdPageModel.start_index >= prefix,
                )
            )
            completed = {index for index in completed if index < prefix}
        statement = sqlite_insert(NvdCollectionModel).values(
            collection=collection, total_results=total_results
        )
        await self.session.execute(
            statement.on_conflict_do_update(
                index_elements=[NvdCollectionModel.collection],
                set_={"total_results": total_results},
            )
        )
        return completed

    async def mark_nvd_page(
        self: Self, collection: str, start_index: int
    ) -> None:
        """Mark a page within the same transaction as its imported data.

        Args:
            collection: Query owning the validated page.
            start_index: Offset of the page just imported.
        """
        await self.session.execute(
            sqlite_insert(NvdPageModel)
            .values(collection=collection, start_index=start_index)
            .on_conflict_do_nothing()
        )

    async def clear_nvd_sync(self: Self) -> None:
        """Remove checkpoints after the whole update succeeds.

        Call alongside update_metadata so cleanup and the successful cutoff
        are committed together by the surrounding database context.
        """
        await self.session.execute(delete(NvdPageModel))
        await self.session.execute(delete(NvdCollectionModel))
        await self.session.execute(delete(NvdSyncModel))

    async def cached_cves(self: Self, cve_ids: set[str]) -> set[str]:
        """Return the requested CVE identifiers already stored in the database.

        Args:
            cve_ids: CVE identifiers to look up.

        Returns:
            Identifiers found in the database.
        """
        existing: set[str] = set()
        candidates = list(cve_ids)
        for start in range(0, len(candidates), 500):
            chunk = candidates[start : start + 500]
            statement = select(CveModel.cve_id).where(
                CveModel.cve_id.in_(chunk)
            )
            existing.update(await self.session.scalars(statement))
        return existing

    async def cached_exploits(self: Self) -> list[int]:
        """Return Exploit-DB identifiers that do not have cached titles.

        Returns:
            Exploit identifiers whose title is null.
        """
        statement = select(ExploitModel.exploit_id).where(
            ExploitModel.name.is_(None)
        )
        result = await self.session.scalars(statement)
        return list(result.all())

    async def insert_products(
        self: Self,
        identities: Sequence[CpeIdentity],
    ) -> None:
        """Insert unique CPE products without replacing existing rows.

        Args:
            identities: CPE type, vendor, product, version, and update rows.
        """
        values = [
            {
                "vendor": vendor,
                "product": product,
                "version": version,
                "version_update": version_update,
            }
            for _, vendor, product, version, version_update in identities
        ]
        if values:
            statement = sqlite_insert(
                _core_table("products")
            ).on_conflict_do_nothing()
            connection = await self.session.connection()
            await connection.execute(statement, values)

    async def insert_cves(
        self: Self,
        cves: Sequence[CveModel],
    ) -> None:
        """Insert CVE records or update their existing score data.

        Args:
            cves: Typed CVE score and publication records.
        """
        if not cves:
            return
        statement = sqlite_insert(_core_table("cves"))
        statement = statement.on_conflict_do_update(
            index_elements=[_core_table("cves").c.cve_id],
            set_={
                "cvss_v2": statement.excluded.cvss_v2,
                "cvss_v3": statement.excluded.cvss_v3,
                "cvss_v4": statement.excluded.cvss_v4,
                "published": statement.excluded.published,
            },
        )
        connection = await self.session.connection()
        await connection.execute(
            statement,
            [
                {
                    "cve_id": cve.cve_id,
                    "cvss_v2": cve.cvss_v2,
                    "cvss_v3": cve.cvss_v3,
                    "cvss_v4": cve.cvss_v4,
                    "published": cve.published,
                }
                for cve in cves
            ],
        )

    async def insert_exploits(
        self: Self,
        exploit_ids: Sequence[int],
    ) -> None:
        """Insert Exploit-DB identifiers without duplicate rows.

        Args:
            exploit_ids: Exploit-DB numeric identifiers.
        """
        if exploit_ids:
            statement = sqlite_insert(
                _core_table("exploits")
            ).on_conflict_do_nothing()
            connection = await self.session.connection()
            await connection.execute(
                statement,
                [{"exploit_id": exploit_id} for exploit_id in exploit_ids],
            )

    async def insert_metasploits(
        self: Self,
        names: Sequence[str],
    ) -> None:
        """Insert unique Metasploit module names.

        Args:
            names: Canonical Metasploit module names.
        """
        if names:
            statement = sqlite_insert(
                _core_table("metasploits")
            ).on_conflict_do_nothing()
            connection = await self.session.connection()
            await connection.execute(
                statement,
                [{"name": name} for name in names],
            )

    async def _product_ids(
        self: Self,
        keys: set[ProductKey],
    ) -> dict[ProductKey, int]:
        """Find product identifiers for the requested CPE identities.

        Args:
            keys: Vendor, product, version, and update identities.

        Returns:
            Product identifiers indexed by their CPE identity.
        """
        product_ids: dict[ProductKey, int] = {}
        candidates = list(keys)
        cols = (
            ProductModel.vendor,
            ProductModel.product,
            ProductModel.version,
            ProductModel.version_update,
        )
        for start in range(0, len(candidates), 200):
            chunk = candidates[start : start + 200]
            statement = select(ProductModel.product_id, *cols).where(
                tuple_(*cols).in_(chunk)
            )
            rows = await self.session.execute(statement)
            for product_id, vendor, product, version, version_update in rows:
                if (
                    vendor is None
                    or product is None
                    or version is None
                    or version_update is None
                ):
                    continue
                key: ProductKey = (vendor, product, version, version_update)
                product_ids[key] = product_id
        return product_ids

    async def insert_affected(
        self: Self,
        records: Sequence[tuple[str, CpeIdentity]],
    ) -> None:
        """Insert exact CVE-to-product associations.

        Args:
            records: CVE identifiers paired with exact CPE identities.

        Raises:
            LookupError: If a referenced exact product identity is missing.
        """
        product_keys = {
            (vendor, product, version, version_update)
            for _, (_, vendor, product, version, version_update) in records
        }
        product_ids = await self._product_ids(product_keys)
        values: list[dict[str, int | str]] = []
        for cve_id, identity in records:
            _, vendor, product, version, version_update = identity
            key = (vendor, product, version, version_update)
            product_id = product_ids.get(key)
            if product_id is None:
                message = f"Missing exact product identity: {key}"
                raise LookupError(message)
            values.append({"cve_id": cve_id, "product_id": product_id})
        if values:
            statement = sqlite_insert(
                _core_table("affected")
            ).on_conflict_do_nothing()
            connection = await self.session.connection()
            await connection.execute(statement, values)

    async def insert_multiaffected(
        self: Self,
        records: Sequence[tuple[str, CpeIdentity, VersionBounds]],
    ) -> None:
        """Insert CVE-to-product associations with version bounds.

        Args:
            records: CVE, CPE identity, and version bound records.

        Raises:
            LookupError: If a referenced ranged product identity is missing.
        """
        product_keys = {
            (vendor, product, version, version_update)
            for _, (_, vendor, product, version, version_update), _ in records
        }
        product_ids = await self._product_ids(product_keys)
        values: list[dict[str, int | str | None]] = []
        for cve_id, identity, bounds in records:
            _, vendor, product, version, version_update = identity
            key = (vendor, product, version, version_update)
            product_id = product_ids.get(key)
            if product_id is None:
                message = f"Missing ranged product identity: {key}"
                raise LookupError(message)
            values.append(
                {
                    "cve_id": cve_id,
                    "product_id": product_id,
                    "versionStartIncluding": bounds[0],
                    "versionStartExcluding": bounds[1],
                    "versionEndIncluding": bounds[2],
                    "versionEndExcluding": bounds[3],
                }
            )
        if values:
            statement = sqlite_insert(
                _core_table("multiaffected")
            ).on_conflict_do_nothing()
            connection = await self.session.connection()
            await connection.execute(statement, values)

    async def insert_conditions(
        self: Self,
        records: Sequence[tuple[str, CpeIdentity, int, CpeIdentity]],
    ) -> None:
        """Insert CVE configuration conditions with platform identities.

        Args:
            records: CVE, vulnerable CPE identity, configuration index,
                and platform CPE identity records.

        Raises:
            LookupError: If a referenced vulnerable product is missing.
        """
        product_keys = {
            (identity[1], identity[2], identity[3], identity[4])
            for _, identity, _, _ in records
        }
        product_ids = await self._product_ids(product_keys)
        values: list[dict[str, int | str]] = []
        for cve_id, identity, config_idx, platform in records:
            _, vendor, product, version, version_update = identity
            key = (vendor, product, version, version_update)
            product_id = product_ids.get(key)
            if product_id is None:
                message = f"Missing conditional product identity: {key}"
                raise LookupError(message)
            part, platform_vendor, platform_product, _, _ = platform
            values.append(
                {
                    "cve_id": cve_id,
                    "product_id": product_id,
                    "config_idx": config_idx,
                    "part": part,
                    "vendor": platform_vendor,
                    "product": platform_product,
                }
            )
        if values:
            statement = sqlite_insert(
                _core_table("conditions")
            ).on_conflict_do_nothing()
            connection = await self.session.connection()
            await connection.execute(statement, values)

    async def insert_aliases(
        self: Self,
        aliases: Sequence[tuple[str, str, str, str, str, str]],
    ) -> None:
        """Insert deprecated application CPEs with their replacements.

        Args:
            aliases: Old vendor, product, version and update, followed by the
                new vendor and product.
        """
        values = [
            {
                "old_vendor": old_vendor,
                "old_product": old_product,
                "old_version": old_version,
                "old_update": old_update,
                "new_vendor": new_vendor,
                "new_product": new_product,
            }
            for (
                old_vendor,
                old_product,
                old_version,
                old_update,
                new_vendor,
                new_product,
            ) in aliases
        ]
        if values:
            statement = sqlite_insert(
                _core_table("aliases")
            ).on_conflict_do_nothing()
            connection = await self.session.connection()
            await connection.execute(statement, values)

    async def insert_referenced_exploits(
        self: Self,
        references: Sequence[tuple[str, int]],
    ) -> None:
        """Insert CVE-to-Exploit-DB references.

        Args:
            references: CVE identifiers paired with exploit identifiers.
        """
        if references:
            statement = sqlite_insert(_core_table("referenced_exploit"))
            statement = statement.on_conflict_do_nothing()
            connection = await self.session.connection()
            await connection.execute(
                statement,
                [
                    {"cve_id": cve_id, "exploit_id": exploit_id}
                    for cve_id, exploit_id in references
                ],
            )

    async def insert_referenced_metasploits(
        self: Self,
        references: Sequence[tuple[str, str]],
    ) -> None:
        """Insert CVE-to-Metasploit references.

        Args:
            references: CVE identifiers paired with module names.

        Raises:
            LookupError: If a referenced Metasploit module is missing.
        """
        if not references:
            return
        names = {name for _, name in references}
        module_ids: dict[str, int] = {}
        candidates = list(names)
        for start in range(0, len(candidates), 500):
            chunk = candidates[start : start + 500]
            lookup_statement = select(
                MetasploitModel.name,
                MetasploitModel.metasploit_id,
            ).where(MetasploitModel.name.in_(chunk))
            result = await self.session.execute(lookup_statement)
            module_ids.update(dict(result.tuples().all()))
        values: list[dict[str, int | str]] = []
        for cve_id, name in references:
            module_id = module_ids.get(name)
            if module_id is None:
                message = f"Missing Metasploit module: {name}"
                raise LookupError(message)
            values.append({"cve_id": cve_id, "metasploit_id": module_id})
        insert_statement = sqlite_insert(_core_table("referenced_metasploit"))
        insert_statement = insert_statement.on_conflict_do_nothing()
        connection = await self.session.connection()
        await connection.execute(insert_statement, values)

    async def update_metadata(
        self: Self,
        last_mod: str,
    ) -> None:
        """Save the timestamp used for the latest NVD synchronization.

        Args:
            last_mod: UTC cutoff timestamp queried from NVD.
        """
        statement = sqlite_insert(MetadataModel).values(
            id=1, last_mod=last_mod
        )
        statement = statement.on_conflict_do_update(
            index_elements=[MetadataModel.id],
            set_={"last_mod": statement.excluded.last_mod},
        )
        await self.session.execute(statement)

    async def update_exploits(
        self: Self,
        updates: Sequence[tuple[int, str | None]],
    ) -> None:
        """Update cached Exploit-DB titles.

        Args:
            updates: Exploit identifiers paired with fetched titles.
        """
        if updates:
            await self.session.execute(
                update(ExploitModel),
                [
                    {"exploit_id": exploit_id, "name": title}
                    for exploit_id, title in updates
                ],
            )

    async def remove_cves(
        self: Self,
        cve_ids: Sequence[str],
    ) -> None:
        """Remove CVEs and their dependent associations.

        Args:
            cve_ids: CVE identifiers to remove.
        """
        for start in range(0, len(cve_ids), 500):
            chunk = cve_ids[start : start + 500]
            await self.session.execute(
                delete(ReferencedExploitModel).where(
                    ReferencedExploitModel.cve_id.in_(chunk)
                )
            )
            await self.session.execute(
                delete(ReferencedMetasploitModel).where(
                    ReferencedMetasploitModel.cve_id.in_(chunk)
                )
            )
            await self.session.execute(
                delete(AffectedModel).where(AffectedModel.cve_id.in_(chunk))
            )
            await self.session.execute(
                delete(MultiAffectedModel).where(
                    MultiAffectedModel.cve_id.in_(chunk)
                )
            )
            await self.session.execute(
                delete(ConditionModel).where(ConditionModel.cve_id.in_(chunk))
            )
            await self.session.execute(
                delete(CveModel).where(CveModel.cve_id.in_(chunk))
            )

    async def clean(self: Self) -> None:
        """Remove Exploit-DB records marked as broken links.

        Delete their CVE references before deleting the broken records.
        """
        broken_ids = select(ExploitModel.exploit_id).where(
            ExploitModel.name.like("404 Page %")
        )
        await self.session.execute(
            delete(ReferencedExploitModel).where(
                ReferencedExploitModel.exploit_id.in_(broken_ids)
            )
        )
        await self.session.execute(
            delete(ExploitModel).where(ExploitModel.name.like("404 Page %"))
        )


__all__ = [
    "AffectedModel",
    "Base",
    "CpeIdentity",
    "CveModel",
    "Database",
    "ExploitModel",
    "MetadataModel",
    "MetasploitModel",
    "MultiAffectedModel",
    "ProductModel",
    "ReferencedExploitModel",
    "ReferencedMetasploitModel",
    "VersionBounds",
]
