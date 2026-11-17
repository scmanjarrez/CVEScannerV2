# CVE database

This page explains how the scanner database (`cve.db`) is built, what each table holds, and how the scanner reads it. Every statement comes from the source files named in the text.

User documentation: [README](../README.md). Contributor guide: [DEVELOPMENT.md](DEVELOPMENT.md). Design decisions: [DESIGN.md](DESIGN.md).

## 1. Overview

- **What it is:** `cve.db`, a SQLite file (default path `data/cve.db`, see `DEFAULT_DATABASE_PATH` in `db-manager/src/db_manager/constants.py`).
- **Writer:** `db-manager` (`db-manager/`). It downloads NVD data, Metasploit metadata and Exploit-DB titles, and writes the file through SQLAlchemy (`infrastructure/storage.py`, `infrastructure/writer.py`).
- **Reader:** the NSE script (`nmap/src/cvescannerv2/db.lua`). It issues only `SELECT` queries (the connection is not opened with a read-only flag) and never calls an API to get CVE data at scan time. It reads SQLite through the Lua module `luasql.sqlite3`.
- **Distribution:**
  - The publication repository `CVEScannerV2DB` stores the database as SQL dump parts `dump.pNN`. `build.sh` concatenates them and imports the result with `sqlite3` (`dbrepo/build.sh`).
  - The `db` Docker target clones `CVEScannerV2DB`, runs its `build.sh` and copies the resulting `cve.db` into the image (`docker/Dockerfile`, stage `database-builder`).
  - Release tarballs include the database, built from `CVEScannerV2DB` with its `build.sh` (`.github/workflows/release.yaml`).
  - The publication job is described in section 7.

## 2. Entity diagram

Foreign keys only. `metadata`, `nvd_sync` and `aliases` have no foreign keys; `product_aliases` is a view over `aliases` and `products`.

```
cves (cve_id) ─┬─< affected >─────────── products (product_id)
               ├─< multiaffected >────── products
               ├─< conditions >───────── products
               ├─< referenced_exploit >─ exploits (exploit_id)
               └─< referenced_metasploit >─ metasploits (metasploit_id)

nvd_collections (collection) ──< nvd_pages (collection, start_index)

Standalone: metadata, nvd_sync, aliases  ──(view)──> product_aliases
```

## 3. Tables

Column types are SQLite types from `PRAGMA table_info` on the v4 `data/cve.db`. "Written by" is the code that inserts or deletes rows; "Read by" is the scanner (`db.lua`) unless noted.

### `metadata`

Purpose: timestamp of the last successful NVD synchronization.

| Column | Type | Meaning |
|---|---|---|
| `id` | INTEGER, PK | Always `1`. |
| `last_mod` | VARCHAR | UTC cutoff, e.g. `2026-11-17T10:19:13.755Z`. |

Written by `update_metadata` (`updater.py`, after a successful run). With `--nvd-raw` the value is the earliest completion time of the imported raw scopes. Read by `cached_metadata` (db-manager only). The scanner does not read it.

### `cves`

Purpose: one row per CVE with its scores and publication year.

| Column | Type | Meaning |
|---|---|---|
| `cve_id` | VARCHAR, PK | CVE identifier. |
| `cvss_v2` | VARCHAR | CVSS v2 base score as text, or NULL. |
| `cvss_v3` | VARCHAR | CVSS v3.x base score as text, or NULL. |
| `cvss_v4` | VARCHAR | CVSS v4 base score as text, or NULL. |
| `published` | INTEGER | Publication year (not a date). |

Written by `insert_cves` (upsert). Read by the scanner: `cvss_v2`, `cvss_v3`, `cvss_v4` (`cvss_v4` only when the column exists). `published` is not read by `db.lua`.

### `products`

Purpose: unique application CPE identities. The table is the target of every version association.

| Column | Type | Meaning |
|---|---|---|
| `product_id` | INTEGER, PK | Surrogate key. |
| `vendor` | VARCHAR | CPE vendor. |
| `product` | VARCHAR | CPE product. |
| `version` | VARCHAR | CPE version; `*` is the wildcard used by range rows. |
| `version_update` | VARCHAR | CPE update: `*` (any), `-` (not applicable) or a concrete update such as `rc1` or `beta`. |

Unique on (`vendor`, `product`, `version`, `version_update`). Only CPEs of type `a` (applications) are stored (`cpe_commands`, `_append_affected_products`, `_append_conditions`). Written by `insert_products` (insert-or-ignore). Read by the scanner: vendor/product lookups, `version = '*'` for ranges, exact versions.

### `affected`

Purpose: CVE linked to an exact product version (no bounds).

| Column | Type | Meaning |
|---|---|---|
| `cve_id` | VARCHAR, PK, FK → `cves` | |
| `product_id` | INTEGER, PK, FK → `products` | |

Written by `insert_affected`. Read by the scanner (`exact_affected`).

### `multiaffected`

Purpose: CVE linked to a product with version bounds, or to a product with no bounds at all (an unbounded `*` match).

| Column | Type | Meaning |
|---|---|---|
| `cve_id` | VARCHAR, PK, FK → `cves` | |
| `product_id` | INTEGER, PK, FK → `products` | |
| `versionStartIncluding` | VARCHAR, PK | Inclusive lower bound, or NULL. |
| `versionStartExcluding` | VARCHAR, PK | Exclusive lower bound, or NULL. |
| `versionEndIncluding` | VARCHAR, PK | Inclusive upper bound, or NULL. |
| `versionEndExcluding` | VARCHAR, PK | Exclusive upper bound, or NULL. |

NULL bounds are compared with `coalesce(..., '')` by the unique index `uq_multiaffected_bounds`, so duplicates are rejected even when bounds are NULL. Written by `insert_multiaffected`. Read by the scanner: `range_affected` (all rows whose product has version `*`; bounds are checked in Lua) and `range_affected_unbounded` (all four bounds NULL, product version and update `*`).

### `conditions`

Purpose: platform requirements of AND configurations. Each row pairs a vulnerable product with one platform CPE of the same configuration.

| Column | Type | Meaning |
|---|---|---|
| `cve_id` | VARCHAR, PK, FK → `cves` | |
| `product_id` | INTEGER, PK, FK → `products` | Vulnerable product. |
| `config_idx` | INTEGER, PK | Zero-based index of the root configuration in the CVE. |
| `part` | VARCHAR, PK | Platform CPE part: `a`, `h` or `o`. |
| `vendor` | VARCHAR, PK | Platform CPE vendor. |
| `product` | VARCHAR, PK | Platform CPE product. |

The platform version is not stored (`insert_conditions` keeps only `part`, `vendor`, `product`). Written by `insert_conditions`. Read by the scanner (`platform_conditions`), which joins on the vulnerable product.

### `aliases`

Purpose: deprecated application CPEs and their replacements, from the NVD CPE catalogue (`deprecatedBy`).

| Column | Type | Meaning |
|---|---|---|
| `old_vendor`, `old_product`, `old_version`, `old_update` | VARCHAR, PK | Deprecated CPE. |
| `new_vendor`, `new_product` | VARCHAR, PK | Replacing application CPE. |

Written by `insert_aliases`, only when the replacement has a different vendor or product (`_alias_commands`). The scanner does not query it directly; it uses `product_aliases`.

### `product_aliases` (view)

Purpose: renamed products. It keeps an old (vendor, product) pair only when at least half of the products with that vendor and product were replaced (`PRODUCT_ALIASES_VIEW` in `storage.py`). Partial deprecations of products that are still current are dropped. Created by `Database.setup`. Read by the scanner (`product_aliases`, `alias_names`).

### `exploits`

Purpose: Exploit-DB identifiers and cached titles.

| Column | Type | Meaning |
|---|---|---|
| `exploit_id` | INTEGER, PK | Numeric Exploit-DB identifier. |
| `name` | VARCHAR | Title scraped from the Exploit-DB page, or NULL. |

Written by `insert_exploits` (from NVD references) and `update_exploits` (titles). `name` is NULL until scraped, or when scraping is skipped (`--skip-scrape`). It is never the generic site title (`OffSec’s Exploit Database Archive` and its older `Offensive Security’s…` form): Exploit-DB serves that title on pages without one of their own, such as 404 pages. At the start of every title update `clean()` removes rows whose title starts with `404 Page ` (together with their `referenced_exploit` rows) and sets generic titles back to NULL so they are fetched again. An exploit whose page answers 404 is removed with its `referenced_exploit` rows (`remove_exploits`). Read by the scanner through `referenced_exploit`.

### `metasploits`

Purpose: unique Metasploit module names.

| Column | Type | Meaning |
|---|---|---|
| `metasploit_id` | INTEGER, PK | Surrogate key. |
| `name` | VARCHAR, UNIQUE | Module full name, e.g. `auxiliary/admin/2wire/xslt_password_reset`. |

Written by `insert_metasploits` from Metasploit's `modules_metadata_base.json`. Read by the scanner through `referenced_metasploit`.

### `referenced_exploit`

Purpose: CVE to Exploit-DB reference. PK (`cve_id`, `exploit_id`); FKs to `cves` and `exploits`. Written by `insert_referenced_exploits`; read by the scanner (`exploit_refs`).

### `referenced_metasploit`

Purpose: CVE to Metasploit module reference. PK (`cve_id`, `metasploit_id`); FKs to `cves` and `metasploits`. Written by `insert_referenced_metasploits`, only for CVEs already present in `cves` (`update_metasploit`). Read by the scanner (`metasploit_refs`).

### Checkpoint tables: `nvd_sync`, `nvd_collections`, `nvd_pages`

Described in section 6. The scanner does not read them.

## 4. NVD to database mapping

Sources: CVE API 2.0 (`.../rest/json/cves/2.0`) and CPE API 2.0 (`.../rest/json/cpes/2.0`), as in `NVD_API_URL` (`constants.py`). Field names are the JSON aliases in `domain/models.py`.

| NVD field | Target | Rule |
|---|---|---|
| CVE `id` | `cves.cve_id` | As received. |
| CVE `published` | `cves.published` | Year only: first four characters, `int()`. |
| CVE `vulnStatus` | — | `Deferred` or `Rejected` (case-insensitive): no `cves` row and no links. |
| `metrics.cvssMetricV2[]` | `cves.cvss_v2` | First entry that has `cvssData`; its `baseScore` as text. |
| `metrics.cvssMetricV30` or `cvssMetricV31` (any key matching `cvssMetricV3.+`) | `cves.cvss_v3` | First key in NVD order with a score. The code does not prefer 3.1 over 3.0. |
| `metrics.cvssMetricV40[]` | `cves.cvss_v4` | First entry with `cvssData`. |
| `configurations[].nodes[]` `cpeMatch[]`, `vulnerable: true` | `products` + `affected` or `multiaffected` | See the rule below. |
| `cpeMatch` `versionStartIncluding` / `…Excluding` / `versionEndIncluding` / `…Excluding` | `multiaffected` bounds | Stored as given (unescaped). |
| `cpeMatch` `vulnerable: false` | `conditions.part/vendor/product` | Only in AND configurations (see below). |
| `nodes[].negate: true` | — | Node skipped, including its children. |
| `references[].url` matching `https?://www.exploit-db.com/exploits/(\d+)`, not tagged `Broken Link` | `exploits`, `referenced_exploit` | Exploit-DB numeric id. Other URLs are ignored. |
| CPE `products[].cpe.cpeName` (type `a`) | `products` | One row per identity. |
| CPE `cpe.deprecated` + `deprecatedBy[].cpeName` | `aliases` | Replacement of type `a` with a different vendor or product. |

**Affected vs multiaffected.** A vulnerable CPE becomes an `affected` row only when all four bounds are absent **and** its version is not `*`. Any other vulnerable CPE becomes a `multiaffected` row: rows with bounds, and rows with version `*` and no bounds (`_append_affected_products`). In `data/cve.db`, all 270 101 `multiaffected` rows reference products with version `*`; the code does not enforce that.

**CPE 2.3 splitting.** `split()` in `domain/cpe.py` takes the fields after `cpe:2.3:` (or `cpe:/` for 2.2) and returns `(part, vendor, product, version, update)`. Missing trailing fields become `*`. Escaped colons (`\:`) stay inside their field, and the backslash is removed. At least three components are required.

**`vulnerable` flag.** Only `vulnerable: true` entries define affected products. The NVD catalogue also lists platforms (`vulnerable: false`). The importer keeps them only as `conditions` rows when the configuration uses AND. An OR-only configuration produces no `conditions` rows (`parse_conditions`).

**`conditions`.** For a configuration with AND at its root or in any node, every vulnerable product is paired with every platform of that configuration. `config_idx` is the index of the root configuration in the CVE's `configurations` list.

**Deprecated CPEs.** Deprecated application CPEs become `aliases` rows through `deprecatedBy`. The `product_aliases` view then decides which renames are used (section 3).

**Re-imports.** Unless the run creates the database file (populate), each CVE is deleted before it is re-imported. This includes a run that resumes an interrupted synchronization (`update_db`). Its old `cves`, `affected`, `multiaffected`, `conditions` and referenced rows are deleted first (`DeleteCveRecord`, `remove_cves`). A deferred or rejected CVE is only deleted.

## 5. Exploit and Metasploit references

- **Exploit-DB:** the source is the NVD reference list of each CVE (see the mapping table). Titles come later from the Exploit-DB page (`og:title`), fetched by `update_exploitdb` in batches of 25. `exploits.name` stays NULL when the page has no title of its own (the generic site title is discarded), when the title is not yet fetched, or when `--skip-scrape` is used. A page that answers HTTP 404 removes the exploit and its CVE references; any other HTTP error stops the update. In a full rebuild, the workflow copies titles from the previous database for rows that are still NULL (`.github/workflows/database.yaml`).
- **Metasploit:** the source is `modules_metadata_base.json` from the Metasploit framework repository (`METASPLOIT_METADATA_URL`). `metasploits.name` is the module full name. The module's `references` that match `CVE-\d+-\d+` link the module to a CVE, but only if that CVE already exists in `cves` at that moment (`update_metasploit`).
- **Linking:** both are many-to-many through `referenced_exploit` and `referenced_metasploit`. The scanner shows the reference flags (`ExploitDB`, `Metasploit`) for each CVE.

## 6. Checkpoint tables

Purpose: let an interrupted NVD download resume without downloading finished pages again.

- `nvd_sync` (singleton, `id = 1`): JSON of `NvdSyncState` (`sync_time`, the list of query windows). It is saved before the first request (`save_nvd_sync`). A later run with a row in this table resumes with the same cutoff and windows (`update_db`).
- `nvd_collections`: one row per collection key. The key is the URL of the endpoint (`cpes` or `cves`), the first page offset, `resultsPerPage` and the date filter. In an offline import (`--nvd-raw`) the key is `raw:<endpoint>/<scope>:<page size>`. It stores `total_results` from the last attempt.
- `nvd_pages`: one row per committed page (`collection`, `start_index`). The page mark is written in the same transaction as the page's data (`NvdPageBatch` → `flush_database_commands(page=...)` → `mark_nvd_page` → `commit`). A page is therefore either fully stored and marked, or not stored at all.

When `total_results` changes between attempts (`prepare_nvd_collection`):
- Incremental runs and shrinking catalogues delete all page marks for that collection.
- Growing full catalogues keep the contiguous prefix of marked pages. Later pages are downloaded again.

Clearing: `clear_nvd_sync` deletes all three tables. It runs in the same database session as `update_metadata` at the end of `run_database`, so the cutoff and the cleanup commit together.

A publishable database has these tables empty. `database.yaml` checks this (section 7). The scanner does not read them.

## 7. Update lifecycle

**Modes**
- **New database (populate):** the database file does not exist yet (`run_database`). Every CPE and CVE is downloaded and no CVE is deleted before import.
- **Refresh of everything on an existing file:** the file exists but `metadata.last_mod` is empty, is not a valid timestamp with time zone, or is later than the current time. All records are downloaded again, and each CVE is deleted before it is re-imported.
- **Workflow `mode=full`:** `database.yaml` moves the previous database aside and runs `db-manager --skip-scrape` on a new file (populate), then copies the Exploit-DB titles from the previous database into rows whose `name` is NULL. It forces this mode when the previous database has no `conditions` table.
- **Incremental (default in the workflow):** queries `lastModStartDate`/`lastModEndDate` from `metadata.last_mod` to now, in windows of 119 days (`NVD_INCREMENTAL_WINDOW_DAYS`). The same windows apply to CPEs and CVEs. Modified CVEs are deleted and re-imported.

**Resume:** see section 6. A run started with an existing `nvd_sync` row reuses its cutoff and windows.

**Offline import:** `--nvd-raw DIR` (`-r`) reads raw pages from a directory instead of calling the API (`update_db_offline`). The API key is not needed in that mode.

**Validation (`.github/workflows/database.yaml`, step "Validate database")**
- `PRAGMA integrity_check` returns `ok`.
- `nvd_sync`, `nvd_collections`, `nvd_pages` are empty.
- `metadata.last_mod` is not empty and advances compared with the previous database (when the previous one has a value).
- `cves` and `products` have at least 95 % of the previous row counts.
- Table `conditions` exists.
- Column `cves.cvss_v4` exists.

**Publication**
1. Restore the previous database from `CVEScannerV2DB` (`dbrepo/build.sh`).
2. Run `db-manager` (full or incremental, depending on the input `mode`).
3. Validate (above).
4. `sqlite3 cve.db .dump`, split into 25 MiB parts `dump.p00`, `dump.p01`, … (`split -b 25M -d`), plus `build.sh`, `README.md` and `.gitignore` from `dbrepo/` and the repository `LICENSE`.
5. Round-trip check: rebuild with `out/build.sh` and compare the SHA-256 of `.dump` with the original.
6. Force-push the `out/` tree to `CVEScannerV2DB` master (`--force-with-lease`), with a commit message `Update database (v4 <short SHA of the CVEScannerV2 commit>, nvd <NEW_LAST_MOD>)`.
7. After a successful publication, the `image` job runs `docker.yaml`. Separately, `release.yaml` builds the tarballs (with and without the database) for a release tag.

## 8. How the scanner queries the database

Source: `nmap/src/cvescannerv2/db.lua` (SQL templates), `version_scope.lua`, `platform_match.lua`, `service_cves.lua`.

| Query | Tables | Purpose |
|---|---|---|
| `exact_affected` | `products`, `affected`, `cves`, `referenced_*` | CVEs for an exact version. |
| `range_affected` | `multiaffected`, `products` (version `*`), `cves`, `referenced_*` | CVEs with version bounds. |
| `range_affected_unbounded` | as above, bounds all NULL, version and update `*` | CVEs with no bounds. |
| `platform_conditions` | `conditions`, `products` | Platform rows per CVE and config. |
| `product_aliases` | `product_aliases` view | Renamed product names, followed forward and one step back. |
| `product_vendors`, `series_children` | `products` | Vendor scope and version series. |
| `exploit_refs`, `metasploit_refs` | `referenced_*`, `exploits`, `metasploits` | Reference names. |

Matching logic (`version_scope.lua`): an exact row matches when its version equals the observed one (with or without the update appended) and the updates are equal or either one is `*`. A concrete row update with an unknown observed update gets the reason `update_unknown`. When Nmap reports a version range, exact rows between the two ends match. A range row matches when its bounds contain or overlap the observed version. Unbounded ranges are reported with reason `nvd_unbounded`.

**Old databases.** Without a `conditions` table, platform checks are skipped and the log gets `warning: database without conditions table; platform checks skipped.` (`service_cves.lua`). Without `cves.cvss_v4`, the scanner logs a warning and reports the v4 score as null (`warning: database without cvss_v4 column`). The README (section on platform checks) says the same.

## 9. Useful queries

The examples use a v4 `data/cve.db`. Run them with `sqlite3 -readonly data/cve.db "…"`. The results quoted below were obtained on the database built on 2026-11-17 (`metadata.last_mod` `2026-11-17T10:19:13.755Z`) and change with each update.

**1. CVEs for an exact product version** (`apache http_server 2.4.49` returns `CVE-2021-41524` (7.5), `CVE-2021-41773` (9.8) and `CVE-2021-42013` (9.8), scores from `cvss_v3`):

```sql
SELECT DISTINCT a.cve_id, c.cvss_v3
FROM affected a
JOIN products p ON p.product_id = a.product_id
JOIN cves c ON c.cve_id = a.cve_id
WHERE p.vendor = 'apache' AND p.product = 'http_server' AND p.version = '2.4.49';
```

**2. Version ranges for a product** (rows with version `*`, bounds shown):

```sql
SELECT m.cve_id, m.versionStartIncluding, m.versionStartExcluding,
       m.versionEndIncluding, m.versionEndExcluding
FROM multiaffected m
JOIN products p ON p.product_id = m.product_id
WHERE p.vendor = 'apache' AND p.product = 'http_server' AND p.version = '*';
```

**3. Platform conditions of a CVE** (`part`: `a` application, `h` hardware, `o` operating system):

```sql
SELECT cve_id, config_idx, part, vendor, product
FROM conditions
WHERE cve_id = 'CVE-1999-0678';
```

**4. Renamed products** (old names that map to a new product, from the view):

```sql
SELECT old_vendor, old_product, new_vendor, new_product
FROM product_aliases
WHERE old_vendor = '3d_flipbook_project';
```

**5. Row count per table:**

```sql
SELECT 'cves', count(*) FROM cves
UNION ALL SELECT 'products', count(*) FROM products
UNION ALL SELECT 'affected', count(*) FROM affected
UNION ALL SELECT 'multiaffected', count(*) FROM multiaffected
UNION ALL SELECT 'conditions', count(*) FROM conditions;
```

**6. Check that the checkpoint tables are empty** (a publishable database returns 0 for each):

```sql
SELECT (SELECT count(*) FROM nvd_sync)        AS nvd_sync,
       (SELECT count(*) FROM nvd_collections) AS nvd_collections,
       (SELECT count(*) FROM nvd_pages)       AS nvd_pages;
```
