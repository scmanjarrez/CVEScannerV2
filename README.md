# CVEScannerV2

CVEScannerV2 is an Nmap NSE script that maps the services found on a target to
the CVEs that probably affect them, together with a Python package
(`db-manager`) that builds and queries the SQLite CVE database the script reads.

Nmap discovers services and versions. CVEScannerV2 then **improves that
evidence** (HTTP fingerprints, safe protocol probes, OS context), looks the
product up in a local copy of the NVD, and tells you **how much to trust each
match** through a confidence level and the reasons behind it.

**Highlights**

- Local NVD database with Metasploit and Exploit-DB references: no API calls
  during a scan.
- Version evidence beyond `nmap -sV`: HTTP fingerprints and read-only service
  probes (Samba, UnrealIRCd) that replace empty, generic or range versions.
- Platform awareness: CVEs that only apply to Windows, Linux or a specific
  distribution are checked against the detected operating system.
- Every CVE carries a `confidence` (`high`, `medium`, `low`) and a list of
  `reasons`, so you can filter noise with `minconf`.
- Machine-readable JSON report plus a human-readable log.

**Contents**

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Local](#local)
  - [Docker](#docker)
- [Execution](#execution)
- [Output](#output)
- [Detection pipeline](#detection-pipeline)
  - [Where the version comes from](#where-the-version-comes-from)
  - [Service probes](#service-probes)
  - [HTTP fingerprinting](#http-fingerprinting)
  - [Operating system context](#operating-system-context)
  - [Version matching](#version-matching)
  - [Confidence levels](#confidence-levels)
- [Project architecture](#project-architecture)
- [Measured impact](#measured-impact)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Query database](#query-database)
- [Tests](#tests)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

# How it works

```
 nmap -sV            evidence                  database              result
┌──────────┐   ┌───────────────────┐   ┌───────────────────┐   ┌────────────────┐
│ service, │   │ HTTP fingerprints │   │ CVEs for product  │   │ CVE + CVSS +   │
│ product, ├──▶│ service probes    ├──▶│ and version range ├──▶│ exploits +     │
│ CPE,     │   │ (SMB, IRC)        │   │ platform rules    │   │ confidence +   │
│ version  │   │ OS context        │   │ (data/cve.db)     │   │ reasons        │
└──────────┘   └───────────────────┘   └───────────────────┘   └────────────────┘
```

1. **Nmap** detects each open port's service, CPE and version.
2. **Evidence enrichment.** When the Nmap version is missing, generic or a
   range, the script looks for something better: HTTP fingerprints on web
   ports and, for a few services, a safe protocol probe. It also works out the
   operating system of the host.
3. **Database lookup.** The product and version are searched in `data/cve.db`:
   exact matches, ranges that contain the version and, when the version is
   unknown, CVEs that affect every version.
4. **Scoping and scoring.** Platform conditions, version series and range
   bounds are evaluated, and each CVE gets a confidence level.

> **Note**: the script depends on Nmap's detection. If Nmap misses a service or
> identifies it incorrectly, the output for that service will be wrong or
> empty. Enrichment reduces this problem; it cannot remove it.

# Requirements

Run commands from the repository root. The scanner needs:

- Nmap (the Docker images ship Nmap 7.97) and Lua 5.4 bindings for SQLite:
  `lua-sql-sqlite3` (Ubuntu) or `lua5.4-sql-sqlite3` (Alpine).
- The CVE database at `data/cve.db` (default path).
- The Vulners HTTP fingerprint catalogue in `data/` (optional, see
  [HTTP fingerprinting](#http-fingerprinting)). The script never downloads
  anything, so scans need no Internet access.

The database and the downloaded catalogue are excluded from version control.
Product and vendor aliases (`data/product-aliases.json`,
`data/vendor-aliases.json`) and the platform map
(`data/platform-families.json`) are versioned.

## Getting the database

The [CVEScannerV2DB](https://github.com/scmanjarrez/CVEScannerV2DB) repository
contains the v4 database dump (`dump.pNN` files and `build.sh`). The
`database.yaml` workflow of this repository generates it on the 1st and 15th
of each month. CVEScannerV2DB no longer holds artifacts. For the old NSE (v3),
use the `v3-final` tag of CVEScannerV2DB. You can also build it yourself:

```bash
uv sync --project db-manager
uv run --project db-manager db-manager
```

```bash
git clone https://github.com/scmanjarrez/CVEScannerV2DB
cd CVEScannerV2DB && sh build.sh
```

`build.sh` requires `sqlite3` and fails if `cve.db` already exists; use
`--remove` or `-o` to replace it. The `database.yaml` workflow also uploads a
`cve.db` artifact (kept for 15 days) on each run in Actions.

> **Note**: `db-manager` needs an
> [NVD API key](https://nvd.nist.gov/developers/request-an-api-key), saved in a
> file named `.api` in the working directory or in the `NVD_KEY` environment
> variable.

> **Important**: platform checks (Windows-only, Linux-only, distribution
> specific CVEs) need a database built with the current `db-manager`, which
> stores the NVD platform conditions in a `conditions` table. With an older
> database those checks are skipped and a warning is logged. The importer also
> associates a CVE only with NVD CPE entries marked `vulnerable: true`, so
> databases from older versions may list supporting platform entries as
> affected products. Build a fresh database after upgrading; use a new path to
> keep the old one:
>
> ```bash
> uv run --project db-manager db-manager --database data/cve-clean.db
> nmap -sV --script cvescannerv2 --script-args db=data/cve-clean.db <target>
> ```

<details>
<summary><b>How database updates work</b></summary>

- Updates rebuild the records modified by NVD since the saved timestamp. Long
  gaps are split into date ranges shorter than NVD's 120-day maximum. If the
  timestamp is missing, invalid or in the future, all records are refreshed.
- Interrupted downloads resume automatically when you run the same command
  against the same database. SQLite stores the original query windows and a
  checkpoint per page, committed in the same transaction as its records;
  incomplete or failed pages are downloaded again. If reference downloads fail
  after NVD finishes, a retry keeps all completed NVD pages.
- NVD uses live offset pagination, not snapshots. On resumption the importer
  checks fresh result counts: for a growing full catalogue it keeps the
  contiguous prefix of complete pages and retries gaps and the old partial
  tail; a smaller catalogue or a changed filtered count makes that collection
  be fetched again. The original synchronisation cutoff is retained, so later
  incremental updates include changes made during the interruption.
- Downloads interrupted before checkpoint support existed must fetch their
  pages once more. Existing databases gain the checkpoint tables
  automatically.
- NVD pages are validated and processed asynchronously. CVE changes and their
  product associations travel through a typed queue to a batched SQLite
  writer. On incremental updates each changed CVE is removed and rebuilt. The
  updater then refreshes Metasploit references and optionally scrapes
  Exploit-DB titles (`--noscrape` skips the title requests).
- Rate limits: NVD request starts are at least 0.75 s apart with at most four
  in flight; Metasploit requests are one second apart; Exploit-DB scraping is
  two seconds apart with at most three in flight. HTTP 429 and selected server
  errors are retried up to three times, honouring `Retry-After`.

</details>

## Getting the HTTP catalogue

The HTTP fingerprint catalogue (`index.json`, `fingerprints.json`, `paths.json`
and `probes.json`) comes from
[nmap-vulners](https://github.com/vulnersCom/nmap-vulners). Download it into
`data/` with:

```bash
scripts/download-catalog.sh [-b BASE_URL] [-d DEST_DIR]
```

`-b` (or the `CATALOG_BASE` environment variable) selects a mirror and `-d`
a different destination. Files are written only when all four download and
parse correctly. Without the catalogue the script still uses Nmap CPEs and
service probes (see [HTTP fingerprinting](#http-fingerprinting)). The Docker
image already includes it.

# Installation

## Local

> **Note**: copy `nmap/src/cvescannerv2.nse` **and** the `nmap/src/cvescannerv2/`
> directory together into the same Nmap script directory. The script loads its
> modules relative to its own path, with priority over older copies in
> `nselib/`. A **symbolic link** to each keeps them in sync with the repository.
> Data paths (`data/cve.db`, ...) are relative to the current working directory:
> run the script from the repository root or pass absolute paths.
>
> - Linux and macOS: `/usr/local/share/nmap/scripts/`,
>   `/usr/share/nmap/scripts/`, `/opt/local/share/nmap/scripts/`,
>   `/usr/local/Cellar/nmap/<version>/share/nmap/scripts/`
> - Windows: `C:\Program Files\Nmap\Scripts`, `%APPDATA%\nmap`

## Docker

The multi-stage Docker build publishes two `scratch` images. The `db` target
contains the latest database built from the `CVEScannerV2DB` dump repository;
the `nodb` target omits it. Both contain only Nmap, its runtime dependencies,
the NSE script and the data files the scanner needs. The `database.yaml`
workflow publishes the dump and then rebuilds the `:db` image.

- Database embedded: `scmanjarrez/cvescanner:db` or
  `scmanjarrez/cvescanner:latest`
- No database: `scmanjarrez/cvescanner:nodb`

On a release, the workflow also publishes the Git tag for the database image
and the same tag with `-nodb` appended for the lightweight image (for example
`v4.0` and `v4.0-nodb`).

```bash
docker run -v /tmp/cvslogs:/tmp/cvslogs scmanjarrez/cvescanner:db \
  --script-args log=/tmp/cvslogs/scan.log,json=/tmp/cvslogs/scan.json <TARGET>

# The mounted data/ replaces the one in the image, so it must contain the
# HTTP catalogue (scripts/download-catalog.sh) unless you only need CPEs.
docker run -v "$PWD/data:/CVEScannerV2/data" \
  -v /tmp/cvslogs:/tmp/cvslogs scmanjarrez/cvescanner:nodb \
  --script-args log=/tmp/cvslogs/scan.log,json=/tmp/cvslogs/scan.json \
  <TARGET>
```

Build either target locally with Docker Buildx:

```bash
docker buildx build --load --target nodb -f docker/Dockerfile \
  -t scmanjarrez/cvescanner:nodb .
docker buildx build --load --target db -f docker/Dockerfile \
  --build-arg DATABASE_REFRESH="$(date +%s)" \
  -t scmanjarrez/cvescanner:db .
```

The HTTP catalogue is downloaded at build time by the `catalog-fetcher` stage
from the `CATALOG_BASE` build argument (default: the nmap-vulners catalog
branch). Pass `--build-arg CATALOG_BASE=<mirror>/` to use a mirror.

Nmap dependencies, the upstream database and scanner source assets are built
in independent stages. APK downloads use a cache mount per architecture, and
`COPY --link` keeps the large runtime and database layers reusable when only
the NSE script, aliases or license change. The build context includes only the
scanner runtime assets; local databases, virtual environments, results and API
keys are excluded.

Keep `DATABASE_REFRESH` unchanged to reuse the database build; change it to
fetch a new upstream snapshot (the release workflow does this automatically).
BuildKit is required for the cache mounts and linked copies.

> **Note**: your logs are in the `/tmp/cvslogs` directory.

# Execution

```bash
nmap -sV --script cvescannerv2 <TARGET>
nmap -sV --script cvescannerv2 --script-args log=logfile.log,json=logfile.json <TARGET>
```

`-sV` is required: the script reads the CPE and version that Nmap detects.

## Script arguments

> **Note**: write arguments **without** the script name prefix
> (`probes=none`, not `cvescannerv2.probes=none`); prefixed arguments are
> ignored.

| Argument | Default | Description |
|---|---|---|
| `db` | `data/cve.db` | CVE database location. |
| `maxcve` | `10` | Maximum number of CVEs printed per service on screen. |
| `maxredirect` | `1` | Maximum number of HTTP redirections followed. |
| `sweep` | `0` | Request every catalogue path on HTTP ports (slow). Values: `0`, `1`. |
| `log` | `cvescannerv2.log` | Log file (includes every exploit and Metasploit module found). |
| `json` | `cvescannerv2.json` | JSON report. |
| `catalog` | `auto` | Vulners catalogue read from `data/` (`index.json`, `fingerprints.json`, `paths.json`, `probes.json`). The script never downloads it (see [Getting the HTTP catalogue](#getting-the-http-catalogue)). `none` disables HTTP fingerprinting and its HTTP probes. |
| `local_catalog` | `data/local-catalog.json` | Local catalogue merged on top of the Vulners one. `none` disables it. |
| `aliases`, `vendor_aliases` | `data/product-aliases.json`, `data/vendor-aliases.json` | Product and vendor alias files. |
| `product_cpe` | `data/product-cpe.json` | Product to CPE overrides for Nmap products. `none` disables it. |
| `service` | `all` | Restrict the scan to one product (for example `http_server`). |
| `version` | `all` | Restrict the scan to one version. |
| `probes` | `all` | Service probes to run: `all`, `none` or a comma-separated list (`smb`, `irc`, `smb_os`). |
| `minconf` | `low` | Minimum confidence shown in the table and the log (`low`, `medium`, `high`). The JSON report always keeps every CVE. |

> **Changes in v4**: the arguments `smb`, `http`, `catalog_url`, `path` and
> `regex` were removed. They are ignored silently, so an old command line still
> runs, but it no longer has any effect. The script no longer downloads the
> catalogue; use `scripts/download-catalog.sh` instead.

<details>
<summary><b>Examples</b></summary>

```bash
# Change report paths
nmap -sV --script cvescannerv2 --script-args log=scan2023.log,json=scan2023.json <TARGET>

# Only one product and version
nmap -sV --script cvescannerv2 --script-args service=http_server,version=2.4.57 <TARGET>

# Show only medium and high confidence results in the table and the log
nmap -sV --script cvescannerv2 --script-args minconf=medium <TARGET>

# Pure Nmap evidence: no service probes
nmap -sV --script cvescannerv2 --script-args probes=none <TARGET>

# Only some probes
nmap -sV --script cvescannerv2 --script-args probes=irc <TARGET>

# Disable the HTTP catalogue (no HTTP fingerprints, no HTTP probes)
nmap -sV --script cvescannerv2 --script-args catalog=none <TARGET>

# Also request every catalogue path on HTTP ports (slow)
nmap -sV --script cvescannerv2 --script-args sweep=1 <TARGET>
```

</details>

# Output

Every service with matches produces three outputs: the Nmap script output,
the log file (`cvescannerv2.log`) and the JSON report (`cvescannerv2.json`).
All three are built from the same per-service result, so they always agree.

Each CVE shows one **CVSS** column with the scores that exist, newest first:
`v4:9.3 v3:9.8 v2:7.5`. A CVE without scores shows `-`. Each service also
shows **where the version came from** (`source`) and the CVEs with a `CONF`
column holding the confidence level (`HIGH`, `MED`, `LOW`).

## Nmap output

The table is printed under the service, one line per CVE, sorted by
confidence and then by the main CVSS score (v4, then v3, then v2).

```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
| cvescannerv2:
| vsftpd 2.3.4 (cpe:/a:vsftpd:vsftpd:2.3.4)  source: nmap_cpe
| CVEs: 3  high: 3  medium: 0  low: 0
|   CVE              CONF  EXPLOITS  CVSS
|   CVE-2011-2523    HIGH  MSF       v3:9.8 v2:10.0
|   CVE-2021-3618    HIGH  -         v3:7.4 v2:5.8
|_  CVE-2015-1419    HIGH  -         v2:5.0
```

The example is taken from a real scan. The rules are:

- The line after `cvescannerv2:` is `product version (cpe)  source: <value>`,
  with the vendor only when it differs from the product and `update <value>`
  only when the update is known.
- The `CVEs:` line gives the counts. `warning:` lines, if any, follow it.
- `EXPLOITS` is `EDB` (Exploit-DB), `MSF` (Metasploit), `EDB MSF` or `-`.
- The last line of the block starts with `|_` (Nmap convention). It appears
  only when CVEs are hidden, by `maxcve` (`+N more`), by `minconf`
  (`N below minconf=<level>`), or by both, for example
  `|_+55 more (maxcve=10). Full list: cvescannerv2.json`. It points to the JSON
  report, which always keeps every CVE.
- `-oX` (structured output) carries the same visible CVEs, cut to `maxcve`,
  with the CVSS scores that are present.

Values of `source` (`version_source`):

| Value | Meaning |
|---|---|
| `nmap_cpe` | Version taken from the CPE that Nmap reports. |
| `nmap_version` | Version taken from the Nmap version string. |
| `http` | Version found by an HTTP probe. |
| `smb` | Version found by the SMB probe. |
| `irc` | Version found by the IRC probe. |

See [Where the version comes from](#where-the-version-comes-from).

## Log file

The log records every CVE with its reasons and every exploit reference. A run
writes a header, one block per service and a footer:

```
=== cvescannerv2 4.0  2026-11-05T06:11:04+00:00 ===
args: minconf=low maxcve=10 db=data/cve.db

[192.168.251.131 512/tcp exec] netkit *
  cpe: cpe:/a:netkit:netkit  source: nmap_cpe  os: linux (cpe)
  CVEs: 0  high: 0  medium: 0  low: 0
[192.168.251.131 21/tcp ftp] vsftpd 2.3.4
  cpe: cpe:/a:vsftpd:vsftpd:2.3.4  source: nmap_cpe  os: -
  CVEs: 3  high: 3  medium: 0  low: 0
  CVE-2011-2523   HIGH  v3:9.8 v2:10.0       exact_version
      MSF  exploit/unix/ftp/vsftpd_234_backdoor
  CVE-2021-3618   HIGH  v3:7.4 v2:5.8        range_contains
[192.168.251.131 139/tcp netbios-ssn] samba 3.0.20
  cached: same result as 192.168.251.131 445/tcp

=== end  hosts: 1  services: 15  CVEs: 640 ===
```

The example is trimmed from a real scan.

- Each service line starts with `[ip port/proto service]`, so `grep` works.
  The log lists every service of the run, including those with `CVEs: 0`.
- The `cpe:` line gives the CPE, the `source` of the version and the OS
  context (`os: -` when unknown).
- Each CVE line shows the CVE, `CONF`, CVSS and the reasons. Its exploits follow,
  indented: `MSF <module>` or `EDB <id> <url> <title>`.
- `reasons` explain how each CVE matched; the confidence is the lowest level
  among them.
- A service reused from the cache says `cached: same result as ...` and does
  not repeat its CVEs.
- A service may carry `warning: ...` lines (for example `distro_backport`).
  Warnings of the run, such as an invalid `minconf` or a database without the
  conditions table, also appear as `warning: ...` lines.
- Each run appends its own header, blocks and footer to the file, so a log with
  several runs holds several blocks.

## JSON report

The JSON report is **JSON Lines**: each run appends one line with one JSON
document, so a file with several runs is a sequence of documents, one per
line. The format is `schema_version: 2`. Keys are shown here pretty-printed
for reading; the file has no line breaks inside a record.

Each run appends one record to the file. A record holds only services with at
least one CVE. Within a port, a service repeated with the same vendor, product,
version and update is written once: the first detection wins.

```json
{
  "schema_version": 2,
  "scanner": { "name": "cvescannerv2", "version": "4.0" },
  "timestamp": "2026-11-05T10:00:00+00:00",
  "args": { "minconf": "low", "maxcve": 10 },
  "hosts": [
    { "ip": "192.168.1.10",
      "ports": [
        { "port": 3306, "protocol": "tcp", "service": "mysql",
          "products": [
            { "cpe": "cpe:/a:mysql:mysql:5.0.51a-3ubuntu5",
              "vendor": "mysql", "product": "mysql",
              "version": "5.0.51", "update": "a",
              "version_source": "nmap_cpe",
              "os_context": { "family": "linux", "distro": null, "source": "nmap" },
              "warnings": [],
              "cached": false,
              "counts": { "total": 2, "high": 1, "medium": 1, "low": 0 },
              "cves": [
                { "id": "CVE-2009-2446",
                  "cvss": { "v4": null, "v3": null, "v2": 8.5 },
                  "confidence": "high",
                  "reasons": ["exact_version"],
                  "exploitdb": [],
                  "metasploit": [] },
                { "id": "CVE-2009-4484",
                  "cvss": { "v4": null, "v3": 9.8, "v2": 7.5 },
                  "confidence": "medium",
                  "reasons": ["range_overlap"],
                  "exploitdb": [],
                  "metasploit": ["exploit/linux/mysql/mysql_yassl_getname"] }
              ] } ] } ] },
    { "ip": "192.168.1.11", "ports": [ ] }
  ]
}
```

| Field | Meaning |
|---|---|
| `schema_version` | Layout version of the document. This README describes `2`. |
| `scanner` | Name and version of the script that wrote the record. |
| `timestamp` | Start of the run. |
| `args` | Effective `minconf` and `maxcve` of the run. |
| `hosts[]` | One entry per scanned host, with `ip` and `ports`. A host with no products keeps `"ports": []`. |
| `ports[]` | `port`, `protocol`, `service` (or `null`) and `products`. |
| `products[]` | One service result: `cpe`, `vendor`, `product`, `version`, `update` (or `null`), `version_source`, `os_context`, `warnings`, `cached`, `counts` and `cves`. |
| `counts` | Number of CVEs in total and per confidence level. |
| `cves[]` | Every CVE of the service, in confidence order (not cut by `maxcve` or `minconf`). |
| `cves[].cvss` | `v4`, `v3` and `v2`, each a number or `null`. The three keys are always present. |
| `cves[].confidence` | `high`, `medium` or `low`. |
| `cves[].reasons` | Why the CVE matched (for example `exact_version`, `range_overlap`, `platform_mismatch:windows`). |
| `cves[].exploitdb` | Exploit-DB entries with `id`, `name` and `url`. |
| `cves[].metasploit` | Metasploit module names. |
| `cached` | `true` when the result was reused from an earlier service. The `cves` list is still complete. |

## Changes in the v4 output

- **Breaking change, no legacy mode.** The Nmap table has one `CVSS` column
  instead of `CVSSv2` and `CVSSv3`. The JSON report is `schema_version: 2`:
  the old `services`/`vulnerabilities`/`summary` layout is gone, and `hosts`
  is now an array. Scripts that parsed the previous format must be updated.
- **CVSSv4.** Scores from NVD CVSS v4 are stored and shown as `v4:`.
- **Older databases.** A database built before CVSSv4 has no `cvss_v4` values
  until it is updated and re-imported. The scanner still works without them
  and writes a `warning` line to the log when the column is missing; the
  `v4` field of the JSON is `null`.

<a id="detection-heuristics"></a>
# Detection pipeline

This section explains every decision the script makes between Nmap's output and
the final list, so you can judge how much to trust a result.

*Nmap CPE → product-cpe/aliases → service probes → banner fingerprints → HTTP catalogue (targeted probes; sweep opt-in) → version matching → OS/platform context → confidence.*

## Where the version comes from

The CVE lookup is only as good as the version it uses. The script keeps the
origin of that version in `version_source`:

| `version_source` | Origin | Typical reliability |
|---|---|---|
| `nmap_cpe` | Version embedded in Nmap's CPE. | High when Nmap saw a precise version. |
| `nmap_version` | Nmap's version text (may be empty, a series such as `5.5`, or a range such as `3.X - 4.X`). | Varies; imprecise values are the reason the other sources exist. |
| `http` | HTTP fingerprints or targeted HTTP probes. | Good when the page or header exposes the version. |
| `smb` | SMB probe (Samba `lanmanager`). | Exact version. |
| `irc` | IRC probe (UnrealIRCd `VERSION` reply). | Exact version. |

When a probe returns a precise version for the port's product it **replaces**
the Nmap version; it is not added as a second candidate.

## Version evidence sources

Nmap sources were classified by how the version is obtained. Each row is a
route; a script or probe belongs to exactly one.

| Route | Meaning |
|---|---|
| V0 | Already covered: `-sV` gives the version, or the script is in `dependencies` or `SERVICE_PROBES`. No action. |
| V1 | A Nmap `version` script publishes a product without a usable CPE. Map it in `data/product-cpe.json` only if the product, CPE and version are right; otherwise discard (V5). Adding it to `dependencies` is not needed: with `-sV` every `version` script runs in runlevel 1. |
| V2 | The version comes only from a `rarity` 8-9 probe that is not in the default set. Usage advice; the NSE cannot change it. |
| V3 | A non-`version` script whose logic yields a version that nothing publishes. Needs its own `SERVICE_PROBES` entry. |
| V4 | The version is in HTTP headers or HTML. Needs a `data/local-catalog.json` entry. |
| V5 | Discarded: no CVEs in the database, only `o:`/`h:` CPEs, not `safe`, needs credentials, or no lab target. |

**Inventory.** The Nmap 7.993 service probe file has 188 probes, 49 of them
with rarity 7 or lower, and 48 scripts in the `version` category. The
script depends on 10 of them through `dependencies`.

**Version intensity.** `--version-intensity` is a command-line flag only:

- A script cannot set it. `nmap.version_intensity(n)` does not change the
  probes sent by `-sV`, and its getter always returns 9.
- Intensity 7 sends 30 probes on a port that no probe lists; 9 sends 104. The
  extra 74 have rarity 8-9. A rarity 8-9 probe whose `ports` or `sslports`
  list the port is still sent at intensity 7 (verified in the lab with the
  rarity 9 `OfficeScan` probe on a non-standard redis port).
- Measured on MS2 (10 services), on a lab with redis 3.2 and mongodb 3.6, and
  on MS3 (192.168.251.132, 25 open ports): intensity 9 gave no extra version
  and no change in CVEs or confidence. On MS3 the only change was port 3389,
  where `ms-wbt-server` became `ssl`. MS3 reported 553 CVEs and 72
  high/critical with both intensities. MS3 took 203.5 s with intensity 7 and
  581.6 s with intensity 9 (about 2.9 times slower). On MS2 and the lab,
  intensity 9 was faster. Each time was measured once. The MS3 JSON carries a
  product for only 4 of 25 open ports, so its CVE total is undercounted.

**Recommendation.** Do not set `--version-intensity 9` by default. On MS3 it
cost about 2.9 times the scan time with no gain in versions or CVEs. Repeat
the measurement on a target that responds differently to the intensity first.

**Pending candidates.** Plans 012 and later, one per route. No dates are
promised.

- **P1 (V1):** `mcafee-epo-agent`, mapped to `mcafee:agent` (7 CVEs). The
  script identifies the agent, not the server, so
  `mcafee:epolicy_orchestrator` is not used. It is the only P1 candidate.
  `ntp-info` was first listed as V3 but already runs the same mode 6
  `readvar` through `probes/ntp.lua`, so it is V0.
- **V1 outcome (14 scripts):**
  - Mapped in `data/product-cpe.json`: `mcafee-epo-agent`
    (`mcafee:agent`), `ventrilo-info` (`flagship_industries:ventrilo`).
  - Discarded (V5):
    - `snmp-info`: composite, variable product.
    - `iax2-version`: no product or version; IAX2 is not Asterisk.
    - `ovs-agent-version`: agent version, not server.
    - `skypev2-version`: no version published.
    - `teamspeak2-version`: the DB only has `2.0.32` in
      `teamspeak:teamspeak`; the script publishes `2.0.32.60`.
    - `rpcinfo`: RPC program version, no product.
    - `quake1-info`: version is a state, not numeric.
    - `s7-info`: no CPE with CVEs; no version published.
    - `http-trane-info`: variable product and version.
    - `mikrotik-routeros-version`: WinBox to RouterOS; version not set.
    - `netbus-version`: honeypot, no version.
    - `tftp-version`: variable product.
- **V2 (check before acting):** `redis-info` (redis 46 CVEs; standard port
  6379 is in the `ports` of `redis-server`, rarity 8), `drda-info` (ibm:db2
  351 CVEs; ports 50000 and 60000 are in the `ibm-db2` probe), `quake3-info`
  (27960-27969 are in the `Quake3_getstatus` probe ports) and `fox-info`
  (port 1911 is in the `niagara-fox` probe ports, rarity 9). These may already
  be resolved at intensity 7 on those ports.
- **V3 `SERVICE_PROBES`:** `couchdb-databases`, `couchdb-stats`,
  `uptime-agent-info`, `http-mcmp`, `irc-info` (may overlap the existing `irc`
  probe) and `versant-info`.
- **V4 HTTP catalogue:** `hadoop-namenode-info`, `hadoop-datanode-info`,
  `hadoop-jobtracker-info`, `hadoop-secondary-namenode-info`,
  `hadoop-tasktracker-info`, `hbase-master-info`, `hbase-region-info`,
  `flume-master-info` and `http-server-header`.

## Service probes

When Nmap cannot give a precise version (empty, a `x.y` series or a range such
as `3.X - 4.X`), the script can ask the service itself. Probes are designed to
be cheap and safe:

- **Targeted, never blind.** A probe runs only if Nmap already identified the
  matching service **and** product on that port. A port number alone never
  triggers a probe. Service probes never sweep; the HTTP path sweep is opt-in
  with `sweep=1`.
- **Only when needed.** A probe never runs if Nmap already reported a precise
  version.
- **Read-only.** No credentials, no writes, no exploit payloads.
- **Fail soft.** Any error or timeout falls back to the Nmap result and never
  aborts the port. Results (including failures) are cached.
- **Bounded cost.** At most one extra connection per service (two retries for `irc`
  when throttled) and one SMB round per host.

| Probe | Triggers on | What it asks | Notes |
|---|---|---|---|
| `smb` | Samba on 139/445 (`netbios-ssn`, `microsoft-ds`) | Nmap's `smb.get_os` (`lanmanager` field) | Gives the exact Samba version instead of `3.X - 4.X`. One query per host, shared by all its SMB ports. |
| `irc` | UnrealIRCd on an `irc`/`ircs` service | `NICK`/`USER`/`VERSION`, reads reply 351 | Exact UnrealIRCd version. The nick appears in the IRC server log. UnrealIRCd throttles reconnections right after `-sV`: on `Throttled` the probe waits 30 s and retries up to two times, 30 s apart. If the server still throttles, the Nmap version is kept. |
| `smb_os` | A host with an SMB service, only when a CVE needs a platform and the OS is unknown | Nmap's `smb.get_os` (`os` field) | Reports `windows` for real Windows hosts. See [Operating system context](#operating-system-context). |
| `ntp` | An `ntp` service (UDP, needs `-sU`) | NTP mode 6 `readvar` (`version="ntpd 4.2.6p5..."`) | Exact ntpd version and patch (`4.2.6p5`) instead of `NTP v4`. `ntpsec`/`chrony` are ignored. Many ntpd block mode 6 (`noquery`): then it falls back to Nmap. |
| `cups` | A CUPS service (`ipp`, product `cups`) with a series version | `GET /` and reads the page title (`Home - CUPS 2.1.3`, also on a 403 page) | Exact CUPS version instead of `2.1`. One request, no catalogue involved. |
| `upnp` | A `upnp` service (UDP 1900, needs `-sU`) | Unicast SSDP `M-SEARCH`, reads the `SERVER:` header | Exact miniupnpd version (`MiniUPnPd/1.8`) when Nmap gives none. Other UPnP stacks are ignored. |

Select them with `probes=none`, `probes=all` or `probes=<csv>`.

**Version scripts.** The `dependencies` list (`weblogic-t3-info`,
`oracle-tns-version`, `docker-version`, `jdwp-version`, `vmware-version`,
`db2-das-info`, `ike-version`, `mqtt-subscribe`, `amqp-info`, `xmpp-info`)
only raises the runlevel: `cvescannerv2` runs in runlevel 2. It does not
select which scripts run. With `-sV` every `version` script runs in runlevel
1, before `cvescannerv2`, so `port.version` is set whether or not a script is
listed. Verified: `rpcinfo` (not listed) runs in runlevel 1 and
`cvescannerv2` sees its result. Not verified: adding `rpcinfo` to
`dependencies`. The `version` scripts only run with `-sV`.

**Product to CPE overrides.** `data/product-cpe.json` (arg `product_cpe`,
`none` disables it) maps an exact Nmap product string to the right CPE and
replaces the one Nmap reports. Today it holds:

- `Oracle GlassFish`, which Nmap reports with the CPE of JSP
  (`cpe:/a:oracle:jsp`); the alias `glassfish_server` also queries
  `glassfish`.
- `McAfee ePolicy Orchestrator Agent` maps to `mcafee:agent`. This is the
  agent, not the server.
- `Ventrilo` maps to `flagship_industries:ventrilo`.

**Local HTTP catalogue.** `data/local-catalog.json` (arg `local_catalog`,
`none` disables it) is merged on top of the Vulners catalogue with the same
schema (`fingerprints`, `paths`, `probes`). Invalid sections are dropped. It is
ignored when the Vulners catalogue is not loaded. It ships empty: anything a
targeted probe can read (such as CUPS) is a probe, not a catalogue rule. A rule
may opt in with `"accept_403": true` to be evaluated on 403 bodies; every
other rule keeps seeing only 2xx and 3xx responses, so error pages of WAFs or
proxies cannot be attributed to the wrong service.

**Limits.** Versions hidden on purpose (Apache `ServerTokens Prod`, OpenSSL,
Dovecot, Postfix) have no network method. Scan by IP (`-n`) when the target
rejects unknown `Host` names, as CUPS does.

Candidates that were evaluated against lab targets and **discarded** because
`nmap -sV` already gives the same information, or because no target exposed
them: `ftp-syst`, `ajp-headers`, NTLM probes (`rdp-ntlm-info`,
`http-ntlm-info`), `snmp-sysdescr` and `mysql-info`.

## HTTP fingerprinting

Used only on ports that Nmap's `shortport` library classifies as HTTP, SSL or
UPnP, **and** whose detected service can actually speak HTTP.

- The script reads the [nmap-vulners](https://github.com/vulnersCom/nmap-vulners)
  catalogue (`index.json`, `fingerprints.json`, `paths.json` and `probes.json`)
  from `data/`. It never downloads it; fetch it with
  [`scripts/download-catalog.sh`](#getting-the-http-catalogue). If the files are
  missing, the script logs that the catalogue was not found and continues with
  Nmap CPEs and service probes only.
- It checks the responses of the catalogue paths: headers, body, title, meta
  tags, script sources and cookies, plus Nmap's own service fingerprints.
  Requests are pipelined in batches paced according to Nmap's timing template.
- A **targeted probe** (for example a changelog page) runs only after its
  product detector matched and no precise version was found.
- **Non-HTTP services are excluded.** Services such as `ms-wbt-server` (RDP),
  `ssh`, `mysql` or `microsoft-ds` never enter the HTTP engine, even when they
  use TLS. Before this rule an RDP port could keep the scan busy
  indefinitely.
- **Sweep is opt-in.** The catalogue path sweep runs only with `sweep=1`
  because it is slow. Targeted probes run by default.
- **Abort on silence.** If a port stops answering HTTP, the sweep gives up when
  a whole request batch returns no response, instead of trying every path.

## Operating system context

Many CVEs only apply on a given platform (a Windows-only flaw in a product that
also runs on Linux, or a bug specific to a distribution). The database stores
these NVD platform conditions, and the script compares them with the OS it
detects for the host. The detected context is reported as `os_context`
(`family`, `distro`, `source`).

**Sources, from highest to lowest priority:**

| Source | Where it comes from |
|---|---|
| `probe:<name>` | A service probe (currently `smb_os`). |
| `cpe` | An operating-system CPE (`cpe:/o:...`) reported for the port. |
| `ostype` | Nmap's `ostype` for the service. |
| `host_os` | Nmap OS detection (`-O`) for the host. |
| `extrainfo` | Words in the version text, such as `Ubuntu`, `Debian`, `Red Hat`, `CentOS`, `SUSE` or `Windows`. |

**On-demand OS probing.** The OS probe runs only when it can change the
outcome: at least one CVE of the service carries a platform condition
(`requires_platform`) **and** the OS is still unknown. If the host has no SMB
service detected, nothing is probed. The result is cached per host and shared
by all its ports, and the analysis cache is keyed by host while the OS is
unknown, so one host never inherits another host's conclusions.

**Samba is not Windows.** Samba announces itself as `Windows 6.1 (Samba x.y)`
in the SMB `os` field. The probe ignores any answer whose `lanmanager`
starts with `Samba`, and it never infers a Linux distribution from Samba.

**Effect on the results.** A CVE whose platform matches the host is kept as
is; one whose platform differs gets `platform_mismatch:<family>` (low
confidence); one whose platform cannot be checked gets `requires_platform`
(medium). No CVE is removed because of platform: the information is
presented through confidence, not hidden.

**Distribution backports.** Linux distributions often patch security fixes
into an older upstream version without changing its number. When the version
string looks like a distribution package (for example `Ubuntu`, `Debian`,
`el7`, `deb9`, `Red Hat`) the service gets the `distro_backport` warning:
treat its CVEs as candidates to verify against the distribution's security
tracker rather than as confirmed exposure.

## Version matching

What the script searches depends on what Nmap (or a probe) reports:

| Evidence | CVEs returned |
|---|---|
| CPE **and** precise version | Those affecting that version, and those whose affected range contains it. |
| CPE and a **range** (`3.X - 4.X`) | Those affecting versions inside the range (inclusive), flagged `observed_range`. |
| CPE and a **series** (`5.5`) | The series is expanded to its releases, flagged `series_expanded`. |
| CPE, **no version** | Those that affect every version of the product. |

Range bounds respect NVD's inclusive and exclusive start and end markers.
When NVD publishes no bound for the affected range, the match is flagged
`nvd_unbounded`. When NVD lists a specific update (for example `p1`) but the
detected update is unknown, the match is flagged `update_unknown`.

## Confidence levels

Each CVE receives the **lowest** level among the reasons that produced it.

| Level | Meaning |
|---|---|
| `high` | The version matches directly and the evidence is unambiguous. |
| `medium` | The match depends on a range overlap, a version series or an unverified condition. |
| `low` | The match relies on weak evidence: an unbounded or observed range, or a platform mismatch. |

| Reason | Level | Description |
|---|---|---|
| `exact_version` | high | The detected version equals the affected version. |
| `range_contains` | high | The detected version lies inside the affected range. |
| `range_overlap` | medium | The detected version range overlaps the affected range. |
| `series_expanded` | medium | The version was expanded to its release series. |
| `update_unknown` | medium | The update level is unknown. |
| `requires_platform` | medium | The CVE applies only on a specific platform that could not be verified. |
| `requires_component` | medium | The CVE needs another component that was not detected. |
| `nvd_unbounded` | low | NVD gives no bound for the affected range. |
| `observed_range` | low | Nmap reported a broad version range (for example `3.X - 4.X`). |
| `platform_mismatch:<family or distro>` | low | The detected platform differs from the one the CVE requires. |

Use `minconf=medium` or `minconf=high` to focus the table and the log on the
most reliable results.

# Project architecture

The repository has two runtime components:

- `nmap/src/cvescannerv2.nse` is the entrypoint. It scans discovered services
  and reads CVE data from SQLite. Its logic lives in the Lua modules under
  `nmap/src/cvescannerv2/`.
- `db-manager/` is a Python package that updates and queries that database.

The NSE modules form layers. Each layer number is listed below.

| Module | Layer | Responsibility |
|--------|-------|----------------|
| `util` | L0 | Pure string and file helpers. |
| `state` | L0 | Shared state, the only place where data is shared between threads. |
| `config` | L0 | Reads and normalizes every script argument. |
| `cpe` | L0 | Pure CPE 2.2 and 2.3 string parser. |
| `version` | L1 | Version parsing and comparison. |
| `match_table` | L2 | Records detected versions and prunes series entries. |
| `catalog.validate` | L2 | Pure validation of the catalogue JSON files. |
| `reference_files` | L2 | Loads and validates the reference data files. |
| `db` | L2 | SQLite access. |
| `log` | L2 | Log file helpers. |
| `json_report` | L2 | JSON report helpers. |
| `catalog.store` | L3 | Vulners catalogue loading from `data/` and the local catalogue overlay. |
| `fingerprint_match` | L3 | Fingerprint matching against catalogue rules and response text. |
| `os_context` | L3 | Operating system context from Nmap and catalogue data. |
| `probes.smb` | L3 | SMB version and OS probes. |
| `probes.irc` | L3 | UnrealIRCd version probe. |
| `probes.ntp` | L3 | ntpd version probe (readvar). |
| `probes.upnp` | L3 | miniupnpd version probe (SSDP). |
| `http_fingerprint` | L4 | HTTP fingerprint engine: targeted probes and opt-in catalogue sweep. |
| `probes.cups` | L4 | CUPS version probe from the GET / page title. |
| `probes.init` | L5 | Probe list, selection and dispatch with a per-key cache. |
| `version_scope` | L5 | Scope matching of NVD rows against the observed version. |
| `platform_match` | L5 | OS platform compatibility of CVE configurations. |
| `confidence` | L5 | Confidence levels and ordering of CVE rows. |
| `port_matches` | L6 | Match collection for one port. |
| `text_output` | L6 | Text output lines for one service. |
| `service_cves` | L7 | Vulnerability lookup for one service and JSON report entries. |
| `port_analysis` | L8 | Analysis of the matches of one port. |
| `lifecycle` | L9 | Rules that decide whether the script runs and the Nmap script actions. |

A module only imports modules from strictly lower layers. The rule is checked by
`nmap/tests/lua/test_architecture.lua`.

To add a service probe, create a new file under `nmap/src/cvescannerv2/probes/`
that returns a probe table, then register it in `probes/init`: add a `require`
line and an entry in the `SERVICE_PROBES` list.

The database package separates command-line and Textual interfaces,
application workflows, domain data and CPE parsing, and infrastructure
adapters for NVD, Metasploit, Exploit-DB, HTTP and SQLite. See the
[`db-manager` guide](db-manager/README.md) for its architecture and workflows.

# Measured impact

Measured on the Metasploitable lab targets with `probes=none` (Nmap evidence
only) against `probes=all`, validating every product–CVE pair independently
against the raw NVD data and the real service versions. These are lab figures;
they show what the heuristics do, not a guarantee for other networks.

| Target | Service | Without probes | With probes |
|---|---|---|---|
| Metasploitable 2 | Samba | `3.X - 4.X`: 195 CVEs, 131 false positives, all `low` | `3.0.20` (`version_source: smb`): 64 CVEs, 63 `high`, no false positives |
| Metasploitable 2 | UnrealIRCd | No version: 0 CVEs, misses the backdoor CVE-2010-2075 | `3.2.8.1` (`version_source: irc`): 3 CVEs, all `high`, including CVE-2010-2075 |
| Metasploitable 3 (Ubuntu) | Samba | `3.X - 4.X`: 195 CVEs, all `low` | `4.3.11`: 77 CVEs, 76 `high` |
| Metasploitable 2 (all ports) | `high` confidence CVEs | 615 CVEs, 90.9 % confirmed | 681 CVEs, 91.8 % confirmed, no new false positives |

Cost: scan time grew about 4 % on Metasploitable 2 (17.1 s → 17.7 s for the
service scripts) and was unchanged on Metasploitable 3. On Metasploitable 3
(Windows) no CVE of the detected services needed a platform check, so the OS
probe correctly never ran.

# Limitations

The Nmap-based detection has limits that the script cannot overcome:

- It cannot confirm that a CVE is exploitable on the target.
- It cannot see the configuration of the service, so a vulnerable version may
  not be reachable or exposed.
- It cannot tell which Metasploit or Exploit-DB modules are active or
  applicable.
- A CVE whose affected configuration requires several applications (AND) cannot
  be fully checked when one of those applications is not detected.
- Samba over SMB2/3 only (SMB1 disabled) exposes no version, so the `smb`
  probe cannot refine it.
- The OS probe only recognises Windows. Linux and BSD hosts rely on Nmap's own
  OS evidence (`cpe`, `ostype`, `-O`, version text).
- The database only contains application CPEs, so OS-level CVEs (for example
  Windows kernel flaws) are not reported.
- Backported fixes cannot be detected from the version number (see
  `distro_backport`).

# Troubleshooting

## Upstream request failures
The updater retries HTTP 429 and selected server errors up to three times and
honours `Retry-After`. If a request still fails, check network access and the
upstream service before running the update again. The NVD synchronisation
timestamp is saved after the update completes, so a failed run can retry the
same window.

## Missing catalogue
If the scan logs `Vulners catalogue not found in data/` (run with `-d` or
verbose output to see it), the HTTP catalogue files are missing. Run
`scripts/download-catalog.sh` from the repository root, or pass `-d` with the
directory the scanner reads. Until then, the scan uses Nmap CPEs and service
probes only; HTTP fingerprints are not evaluated.

## Missing luasql
> cvescannerv2.nse: module 'luasql.sqlite3' not found:<br>
> NSE failed to find nselib/luasql/sqlite3.lua in search paths.<br>
> ...

**Fix:** install the library for your OS (see [Requirements](#requirements)).
The script also looks for `luasql/sqlite3.so` in the standard Lua library
directories when Nmap cannot load it by itself. If it is still not found,
create a symlink to Nmap's search path:

```bash
apt install lua-sql-sqlite3
ln -s /usr/lib/x86_64-linux-gnu/lua /usr/local/lib/lua
```

```bash
apk add --no-cache lua5.4-sql-sqlite3
ln -s /usr/lib/lua /usr/local/lib/lua
```
> The commands above may require super user permissions.

## A probe does not find the version
- UnrealIRCd rejects fast reconnections ("Throttled"). The probe waits 30 s
  and retries up to two times, 30 s apart; if the server is still throttling,
  the Nmap result is kept. Run with `-d` to see the probe messages.
- Probes only run when Nmap identified the service and product. If Nmap shows
  `irc?` or an empty product, no probe is attempted.

# Query database

The `db-query` command opens an interactive Textual interface when run without
`--product`. It suggests product names from the selected database and displays
exact-version and version-range matches in separate tables. Press the right
arrow to accept a suggestion, then press Enter or select Search.

Exact versions are compared by their dotted components. Range results respect
NVD's inclusive and exclusive bounds. Use `--raw` to include unfiltered
database rows alongside the filtered matches.

```bash
uv run --project db-manager db-query
uv run --project db-manager db-query --interactive
```

For a one-off query, pass the product and optional version filters:

```bash
uv run --project db-manager db-query --help
uv run --project db-manager db-query -p "gibbon" -v "25.0.0"
```

# Tests

Run these checks from the repository root. They use temporary SQLite databases
and mocked external services; the scanner tests do not need Nmap.

```bash
# Database package
PYTHONPATH=db-manager/src uv run --project db-manager \
  python -m unittest discover -s db-manager/tests -v

# Scanner (requires lua5.4; the SQLite suite also needs luasql.sqlite3 and is
# skipped when it is missing)
sh nmap/tests/run.sh

# Scanner suites run directly
lua5.4 nmap/tests/lua/run.lua
lua5.4 nmap/tests/test_scanner.lua
```

`nmap/tests/run.sh` runs the HTTP and catalogue-cache tests plus the Lua suites for
version matching, scoping and platform checks, the catalogue, service probes
and the SQLite integration. Probe tests use stubbed sockets and Nmap libraries,
so they never touch the network. See [`nmap/tests/README.md`](nmap/tests/README.md) for
the containerised runner.

# Acknowledgements

**This work has been supported by National R&D Project TEC2017-84197-C4-1-R and
by the Comunidad de Madrid project CYNAMON P2018/TCS-4566 and co-financed by
European Structural Funds (ESF and FEDER).**

- Based on the [alegr3/CVEscanner](https://github.com/alegr3/CVEscanner)
  script.
- Common server regexes and paths from
  [vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners).
- Modules cache generated from
  [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)
  (found in `~/.msf4/store/modules_metadata.json` after running `msfconsole`).
- CVE information gathered from [nvd.nist.gov](https://nvd.nist.gov).

# License

    CVEScannerV2  Copyright (C) 2021-2025 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](LICENSE)
