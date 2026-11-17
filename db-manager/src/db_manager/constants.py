# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared immutable configuration for the db-manager package.

The values below cover CPE parsing, NVD and reference-service access, retry
behavior, database batching, and terminal output. Runtime objects such as
consoles, loggers, and user-agent generators stay with the modules that use
them.
"""

import re
from pathlib import Path
from typing import Final

# Minimum CPE fields required to identify type, vendor, and product.
MIN_CPE_COMPONENTS: Final[int] = 3

# NVD request pacing, page limits, incremental update window, and API endpoint.
NVD_REQUEST_INTERVAL: Final[float] = 0.75
NVD_REQUEST_INTERVAL_WITHOUT_KEY: Final[float] = 6.0
NVD_MAX_CONCURRENT_REQUESTS: Final[int] = 4
NVD_CPE_PAGE_SIZE: Final[int] = 10_000
NVD_CVE_PAGE_SIZE: Final[int] = 2_000
NVD_INCREMENTAL_WINDOW_DAYS: Final[int] = 119
NVD_API_URL: Final[str] = (
    "https://services.nvd.nist.gov/rest/json/{}/2.0?startIndex={}"
)

# Patterns used to extract CVSS metric versions and Exploit-DB references.
CVSS_V3_METRIC_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(cvssMetricV3.+)"
)
# NVD metric key that carries CVSS v4 scores.
CVSS_V4_METRIC_KEY: Final[str] = "cvssMetricV40"
EXPLOITDB_REFERENCE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"https?://www.exploit-db.com/exploits/(\d+)"
)

# HTTP success status, transient failure statuses, and bounded retry timing.
HTTP_OK: Final[int] = 200
MAX_HTTP_RETRIES: Final[int] = 3
HTTP_RETRY_STATUSES: Final[frozenset[int]] = frozenset(
    {429, 500, 502, 503, 504}
)
HTTP_RETRY_BACKOFF_BASE_SECONDS: Final[int] = 2
HTTP_RETRY_MAX_BACKOFF_SECONDS: Final[int] = 60
HTTP_TIMEOUT_SECONDS: Final[int] = 120

# Metasploit and Exploit-DB request pacing, concurrency, URLs, and parsers.
METASPLOIT_REQUEST_INTERVAL: Final[float] = 1.0
EXPLOITDB_REQUEST_INTERVAL: Final[float] = 2.0
EXPLOITDB_MAX_CONCURRENT_REQUESTS: Final[int] = 3
METASPLOIT_METADATA_URL: Final[str] = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/"
    "master/db/modules_metadata_base.json"
)
EXPLOITDB_URL: Final[str] = "https://www.exploit-db.com/exploits"
EXPLOITDB_BATCH_SIZE: Final[int] = 25
METASPLOIT_CVE_PATTERN: Final[re.Pattern[str]] = re.compile(r"CVE-\d+-\d+")
EXPLOITDB_TITLE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""<meta property=(?P<quote>['"])og:title(?P=quote) """
    r"""content=(?P<quotex>['"])(.*?)(?P=quotex)""",
    re.IGNORECASE | re.DOTALL,
)

# Maximum number of typed commands grouped into one database transaction.
DATABASE_WRITE_BATCH: Final[int] = 10_000

# Default database path, relative to the repository root.
DEFAULT_DATABASE_PATH: Final[Path] = Path("data/cve.db")

# Default directory for raw NVD pages, relative to the working directory.
DEFAULT_NVD_RAW_DIR: Final[Path] = Path("data/nvd-raw")

# Expected SQL result widths, including the CVSS columns and reference flags.
EXACT_COLUMN_COUNT: Final[int] = 10
RANGED_COLUMN_COUNT: Final[int] = 12

# Column labels shared by command-line and Textual query result views.
EXACT_HEADERS: Final[tuple[str, ...]] = (
    "CVE",
    "CVSS",
    "Vendor",
    "Product",
    "Version",
    "V.Update",
    "EXPLOITS",
)
RANGE_HEADERS: Final[tuple[str, ...]] = (
    "CVE",
    "CVSS",
    "Vendor",
    "Product",
    "StartInclude",
    "StartExclude",
    "EndInclude",
    "EndExclude",
    "EXPLOITS",
)

# Legal notice printed when the database updater starts.
COPYRIGHT: Final[str] = (
    "Copyright (C) 2021-2023 Sergio Chica Manjarrez @ pervasive.it.uc3m.es, "
    "Universidad Carlos III de Madrid (UC3M).\n"
    "Copyright (C) 2026 Sergio Chica Manjarrez @ csic.es, "
    "Consejo Superior de Investigaciones Científicas (CSIC).\n"
    "This program comes with ABSOLUTELY NO WARRANTY; for details check "
    "below.\n"
    "This is free software, and you are welcome to redistribute it\n"
    "under certain conditions; check below for details."
)
