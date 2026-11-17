# SPDX-License-Identifier: GPL-3.0-or-later

"""Define validated API payloads and database worker commands.

Keep external records and queued writes in strictly typed data models.
"""

import asyncio
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, RootModel

CpeIdentity = tuple[str, str, str, str, str]
"""CPE type, vendor, product, version, and update components."""

VersionBounds = tuple[str | None, str | None, str | None, str | None]
"""Inclusive and exclusive lower and upper CPE version bounds."""


class ExternalDataModel(BaseModel):
    """Provide strict validation for external response models.

    Ignore fields returned by external services that the importer does not use.
    """

    model_config = ConfigDict(extra="ignore", strict=True)


class ImmutableModel(BaseModel):
    """Provide strict validation for immutable internal models.

    Reject unknown fields and prevent mutation after model validation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class NvdCpeMatch(ExternalDataModel):
    """Represent one CPE match from an NVD configuration.

    Attributes:
        criteria: Formatted CPE name.
        vulnerable: Whether the CPE identifies an affected product.
        version_start_including: Inclusive lower version bound.
        version_start_excluding: Exclusive lower version bound.
        version_end_including: Inclusive upper version bound.
        version_end_excluding: Exclusive upper version bound.
    """

    criteria: str = Field(description="Formatted CPE name.")
    vulnerable: bool | None = Field(
        default=None,
        description="Whether this CPE identifies an affected product.",
    )
    version_start_including: str | None = Field(
        default=None,
        alias="versionStartIncluding",
        description="Inclusive lower version bound.",
    )
    version_start_excluding: str | None = Field(
        default=None,
        alias="versionStartExcluding",
        description="Exclusive lower version bound.",
    )
    version_end_including: str | None = Field(
        default=None,
        alias="versionEndIncluding",
        description="Inclusive upper version bound.",
    )
    version_end_excluding: str | None = Field(
        default=None,
        alias="versionEndExcluding",
        description="Exclusive upper version bound.",
    )


class NvdConfigurationNode(ExternalDataModel):
    """Represent one recursive NVD configuration node.

    Attributes:
        operator: Logical operator joining the node's CPE entries.
        negate: Whether the node's criteria are negated.
        cpe_match: CPE entries directly attached to the node.
        children: Nested configuration nodes.
    """

    operator: str = Field(
        default="OR",
        description="Logical operator joining the node's CPE entries.",
    )
    negate: bool = Field(
        default=False,
        description="Whether the node's criteria are negated.",
    )
    cpe_match: list[NvdCpeMatch] = Field(
        default_factory=list[NvdCpeMatch],
        alias="cpeMatch",
        description="CPE entries attached directly to the node.",
    )
    children: list["NvdConfigurationNode"] = Field(
        default_factory=list["NvdConfigurationNode"],
        description="Nested configuration nodes.",
    )


class NvdConfiguration(ExternalDataModel):
    """Represent one NVD CVE configuration.

    Attributes:
        operator: Logical operator joining the top-level nodes, if present.
        nodes: Configuration nodes to inspect.
    """

    operator: str | None = Field(
        default=None,
        description="Logical operator joining the top-level nodes.",
    )
    nodes: list[NvdConfigurationNode] = Field(
        description="Configuration nodes to inspect."
    )


class NvdReference(ExternalDataModel):
    """Represent a reference attached to an NVD CVE.

    Attributes:
        url: Reference URL.
        tags: NVD reference tags.
    """

    url: str = Field(description="Reference URL.")
    tags: list[str] = Field(
        default_factory=list,
        description="NVD reference tags.",
    )


class CvssData(ExternalDataModel):
    """Represent the CVSS base score consumed by the importer.

    Attributes:
        base_score: CVSS base score.
    """

    base_score: float = Field(
        alias="baseScore",
        description="CVSS base score.",
    )


class NvdMetric(ExternalDataModel):
    """Wrap CVSS or SSVC data in an NVD metric entry.

    Attributes:
        cvss_data: Optional CVSS score data; absent for SSVC entries.
    """

    cvss_data: CvssData | None = Field(
        default=None,
        alias="cvssData",
        description=(
            "CVSS score data, absent for non-CVSS metrics such as SSVC."
        ),
    )


class NvdCve(ExternalDataModel):
    """Hold the validated NVD fields used by the importer.

    Attributes:
        id: CVE identifier.
        vuln_status: Current NVD vulnerability status.
        published: Publication timestamp.
        metrics: CVSS metric collections by version.
        configurations: Affected-product configurations.
        references: External references.
    """

    id: str = Field(description="CVE identifier.")
    vuln_status: str = Field(
        alias="vulnStatus",
        description="Current NVD vulnerability status.",
    )
    published: str = Field(description="Publication timestamp.")
    metrics: dict[str, list[NvdMetric]] = Field(
        default_factory=dict,
        description="CVSS metric collections by version.",
    )
    configurations: list[NvdConfiguration] = Field(
        default_factory=list[NvdConfiguration],
        description="Affected-product configurations.",
    )
    references: list[NvdReference] = Field(
        default_factory=list[NvdReference],
        description="External references.",
    )


class NvdVulnerability(ExternalDataModel):
    """Wrap one CVE record returned by NVD.

    Attributes:
        cve: CVE fields used by the importer.
    """

    cve: NvdCve = Field(description="CVE fields used by the importer.")


class NvdCpeDeprecation(ExternalDataModel):
    """Represent the CPE name that replaces a deprecated one.

    Attributes:
        cpe_name: Formatted name of the replacing CPE.
    """

    cpe_name: str = Field(
        alias="cpeName",
        description="Formatted name of the replacing CPE.",
    )


class NvdCpe(ExternalDataModel):
    """Represent a CPE name in the NVD catalog.

    Attributes:
        cpe_name: Formatted CPE name.
        deprecated: Whether NVD replaced this CPE name.
        deprecated_by: CPE names that replace this one.
    """

    cpe_name: str = Field(
        alias="cpeName",
        description="Formatted CPE name.",
    )
    deprecated: bool = Field(
        default=False,
        description="Whether NVD replaced this CPE name.",
    )
    deprecated_by: list[NvdCpeDeprecation] = Field(
        default_factory=list,
        alias="deprecatedBy",
        description="CPE names that replace this one.",
    )


class NvdCpeRecord(ExternalDataModel):
    """Wrap a CPE catalog entry returned by NVD.

    Attributes:
        cpe: CPE catalog fields.
    """

    cpe: NvdCpe = Field(description="CPE catalog fields.")


class NvdCpeResponse(ExternalDataModel):
    """Hold validated CPE catalog entries from one NVD response.

    Attributes:
        products: CPE records in the current page.
    """

    products: list[NvdCpeRecord] = Field(
        description="CPE records in the current page."
    )


class NvdCveResponse(ExternalDataModel):
    """Hold validated CVE records from one NVD response.

    Attributes:
        vulnerabilities: CVE records in the current page.
    """

    vulnerabilities: list[NvdVulnerability] = Field(
        description="CVE records in the current page."
    )


class NvdMetadataResponse(ExternalDataModel):
    """Hold metadata returned for an NVD query.

    Attributes:
        total_results: Number of results matching the request.
    """

    total_results: int = Field(
        alias="totalResults",
        ge=0,
        description="Number of results matching the request.",
    )


class NvdPageMetadataResponse(NvdMetadataResponse):
    """Identify the actual page returned by NVD.

    Attributes:
        total_results: Number of records matching the query.
        start_index: Offset of the first record in this response.
    """

    start_index: int = Field(
        alias="startIndex", ge=0, description="Actual response page offset."
    )


class MetasploitModule(ExternalDataModel):
    """Describe Metasploit metadata consumed by the importer.

    Attributes:
        fullname: Canonical Metasploit module name.
        references: External identifiers linked to the module.
    """

    fullname: str = Field(description="Canonical Metasploit module name.")
    references: list[str] = Field(
        description="External identifiers linked to the module."
    )


class MetasploitCache(RootModel[dict[str, MetasploitModule]]):
    """Validate the root module mapping returned by Metasploit.

    Attributes:
        root: Metasploit modules indexed by their cache keys.
    """


class DatabaseArguments(ImmutableModel):
    """Provide the database path required by the updater.

    Attributes:
        database: Path to the SQLite database.
        skip_scrape: Whether to skip Exploit-DB title scraping.
        nvd_raw: Directory with raw NVD pages to import instead of querying
            NVD.
    """

    database: Path = Field(description="Path to the SQLite database.")
    skip_scrape: bool = Field(
        default=False,
        description="Whether to skip Exploit-DB title scraping.",
    )
    nvd_raw: Path | None = Field(
        default=None,
        description=(
            "Directory with raw NVD pages to import instead of querying NVD."
        ),
    )


class ProductRecord(ImmutableModel):
    """Queue one CPE product identity for insertion.

    Attributes:
        identity: CPE type, vendor, product, version, and update.
    """

    identity: CpeIdentity = Field(
        description="CPE type, vendor, product, version, and update."
    )


class CveRecord(ImmutableModel):
    """Queue one CVE score and publication record.

    Attributes:
        cve_id: CVE identifier.
        cvss_v2: CVSS v2 score, or None when absent.
        cvss_v3: CVSS v3 score, or None when absent.
        cvss_v4: CVSS v4 score, or None when absent.
        published: Publication year.
    """

    cve_id: str = Field(description="CVE identifier.")
    cvss_v2: str | None = Field(
        description="CVSS v2 score, or None when absent."
    )
    cvss_v3: str | None = Field(
        description="CVSS v3 score, or None when absent."
    )
    cvss_v4: str | None = Field(
        description="CVSS v4 score, or None when absent."
    )
    published: int = Field(description="Publication year.")


class DeleteCveRecord(ImmutableModel):
    """Queue one CVE and its old associations for deletion.

    Attributes:
        cve_id: CVE identifier to remove before rebuilding its data.
    """

    cve_id: str = Field(description="CVE identifier to remove.")


class ExploitRecord(ImmutableModel):
    """Queue one Exploit-DB identifier for insertion.

    Attributes:
        exploit_id: Exploit-DB numeric identifier.
    """

    exploit_id: int = Field(description="Exploit-DB numeric identifier.")


class MetasploitRecord(ImmutableModel):
    """Queue one Metasploit module name for insertion.

    Attributes:
        name: Canonical Metasploit module name.
    """

    name: str = Field(description="Canonical Metasploit module name.")


class AffectedRecord(ImmutableModel):
    """Queue one exact CVE-to-product association.

    Attributes:
        cve_id: CVE identifier.
        identity: Exact affected product CPE identity.
    """

    cve_id: str = Field(description="CVE identifier.")
    identity: CpeIdentity = Field(
        description="Exact affected product CPE identity."
    )


class MultiAffectedRecord(ImmutableModel):
    """Queue one CVE-to-product association with version bounds.

    Attributes:
        cve_id: CVE identifier.
        identity: Affected product CPE identity.
        bounds: Inclusive and exclusive version boundaries.
    """

    cve_id: str = Field(description="CVE identifier.")
    identity: CpeIdentity = Field(description="Affected product CPE identity.")
    bounds: VersionBounds = Field(
        description="Inclusive and exclusive version boundaries."
    )


class ReferencedExploitRecord(ImmutableModel):
    """Queue one CVE-to-Exploit-DB reference.

    Attributes:
        cve_id: CVE identifier.
        exploit_id: Exploit-DB numeric identifier.
    """

    cve_id: str = Field(description="CVE identifier.")
    exploit_id: int = Field(description="Exploit-DB numeric identifier.")


class ReferencedMetasploitRecord(ImmutableModel):
    """Queue one CVE-to-Metasploit reference.

    Attributes:
        cve_id: CVE identifier.
        module_name: Canonical Metasploit module name.
    """

    cve_id: str = Field(description="CVE identifier.")
    module_name: str = Field(description="Canonical Metasploit module name.")


class ConditionRecord(ImmutableModel):
    """Queue one AND-condition pair from a CVE configuration.

    Attributes:
        cve_id: CVE identifier.
        identity: Vulnerable product CPE identity.
        config_idx: Zero-based index of the configuration within the CVE.
        platform: Platform CPE identity required by the condition.
    """

    cve_id: str = Field(description="CVE identifier.")
    identity: CpeIdentity = Field(
        description="Vulnerable product CPE identity."
    )
    config_idx: int = Field(
        ge=0,
        description="Zero-based index of the configuration within the CVE.",
    )
    platform: CpeIdentity = Field(
        description="Platform CPE identity required by the condition."
    )


class AliasRecord(ImmutableModel):
    """Queue one deprecated application CPE and its replacing product.

    Attributes:
        old_vendor: Vendor of the deprecated CPE.
        old_product: Product of the deprecated CPE.
        old_version: Version of the deprecated CPE.
        old_update: Update of the deprecated CPE.
        new_vendor: Vendor of the replacing CPE.
        new_product: Product of the replacing CPE.
    """

    old_vendor: str = Field(description="Vendor of the deprecated CPE.")
    old_product: str = Field(description="Product of the deprecated CPE.")
    old_version: str = Field(description="Version of the deprecated CPE.")
    old_update: str = Field(description="Update of the deprecated CPE.")
    new_vendor: str = Field(description="Vendor of the replacing CPE.")
    new_product: str = Field(description="Product of the replacing CPE.")


class FlushMarker(BaseModel):
    """Mark the point where queued writes must finish.

    Attributes:
        event: Async event set after all preceding writes commit.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="forbid",
        frozen=True,
        strict=True,
    )

    event: asyncio.Event = Field(
        description="Event set after all preceding writes commit."
    )


DatabaseCommand = (
    ProductRecord
    | CveRecord
    | DeleteCveRecord
    | ExploitRecord
    | MetasploitRecord
    | AffectedRecord
    | MultiAffectedRecord
    | ReferencedExploitRecord
    | ReferencedMetasploitRecord
    | ConditionRecord
    | AliasRecord
)


class NvdSyncState(ImmutableModel):
    """Keep the original scope of an interrupted NVD synchronization.

    Attributes:
        sync_time: UTC cutoff retained until the whole update succeeds.
        queries: Fixed modified-date windows, or an empty full-catalog query.
    """

    sync_time: str = Field(description="Original UTC synchronization cutoff.")
    queries: list[str] = Field(
        min_length=1, description="Fixed NVD query windows."
    )


class NvdPageBatch(ImmutableModel):
    """Persist a validated NVD page and its checkpoint atomically.

    Attributes:
        collection: Endpoint, page size, and filter identifying the query.
        start_index: Zero-based offset of the downloaded page.
        commands: Validated records to commit before marking the page done.
    """

    collection: str = Field(description="Stable NVD collection query key.")
    start_index: int = Field(ge=0, description="Page offset in the query.")
    commands: list[DatabaseCommand] = Field(
        description="Database commands belonging to this complete page."
    )


WorkerCommand = DatabaseCommand | NvdPageBatch | FlushMarker | None
