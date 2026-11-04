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
- [Execution](#execution)
- [Output](#output)
- [Detection heuristics](#detection-heuristics)
  - [Where the version comes from](#where-the-version-comes-from)
  - [HTTP fingerprinting](#http-fingerprinting)
  - [Service probes](#service-probes)
  - [Operating system context](#operating-system-context)
  - [Version matching](#version-matching)
  - [Confidence levels](#confidence-levels)
- [Measured impact](#measured-impact)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Docker container](#docker-container)
- [Project architecture](#project-architecture)
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
- Internet access on first use, only to download the HTTP fingerprint
  catalogue (see [HTTP fingerprinting](#http-fingerprinting)). Scans work
  offline afterwards.

The database and the downloaded catalogue are excluded from version control.
Product and vendor aliases (`data/product-aliases.json`,
`data/vendor-aliases.json`) and the platform map
(`data/platform-families.json`) are versioned.

## Getting the database

You can download a (semi-updated) copy from
[CVEScannerV2DB](https://github.com/scmanjarrez/CVEScannerV2DB) (`.sql` files,
or Actions → Latest → Summary → Artifacts; the repository is refreshed every
two weeks), or build it yourself:

```bash
uv sync --project db-manager
uv run --project db-manager db-manager
```

```bash
git clone https://github.com/scmanjarrez/CVEScannerV2DB
cd CVEScannerV2DB && sh build.sh
```

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
| `minconf` | `low` | Minimum confidence shown in the table and the log (`low`, `medium`, `high`). The JSON report always keeps every CVE. |
| `log` | `cvescannerv2.log` | Log file (includes every exploit and Metasploit module found). |
| `json` | `cvescannerv2.json` | JSON report. |
| `service` | `all` | Restrict the scan to one product (for example `http_server`). |
| `version` | `all` | Restrict the scan to one version. |
| `probes` | `all` | Service probes to run: `all`, `none` or a comma-separated list (`smb`, `irc`, `smb_os`). |
| `smb` | `1` | `0` disables the SMB probes (legacy switch, same as removing `smb` and `smb_os` from `probes`). |
| `http` | `1` | `0` disables HTTP analysis. |
| `maxredirect` | `1` | Maximum number of HTTP redirections followed. |
| `sweep` | `0` | Enable the catalogue path sweep over HTTP ports (slow, asks every catalogue path). Default: `0` (disabled). Possible values: `0`, `1`. Transitional: it will be removed. |
| `catalog` | `auto` | `none` disables the upstream HTTP fingerprint catalogue. |
| `catalog_url` | `https://raw.githubusercontent.com/vulnersCom/nmap-vulners/catalog/` | Base URL of the catalogue (use it for a local mirror). |
| `path`, `regex` | `data/http-paths-vulnerscom.json`, `data/http-regex-vulnerscom.json` | Legacy HTTP files, used only if the catalogue is unavailable. |
| `aliases`, `vendor_aliases` | `data/product-aliases.json`, `data/vendor-aliases.json` | Product and vendor alias files. |

<details>
<summary><b>Examples</b></summary>

```bash
# Change report paths
nmap -sV --script cvescannerv2 --script-args log=scan2023.log,json=scan2023.json <TARGET>

# Only one product and version
nmap -sV --script cvescannerv2 --script-args service=http_server,version=2.4.57 <TARGET>

# Show only medium and high confidence results in the table and the log
nmap -sV --script cvescannerv2 --script-args minconf=medium <TARGET>

# Pure Nmap evidence: no service probes, no HTTP analysis
nmap -sV --script cvescannerv2 --script-args probes=none,http=0 <TARGET>

# Only some probes
nmap -sV --script cvescannerv2 --script-args probes=irc,smb <TARGET>

# Disable the remote/legacy HTTP fingerprint catalogues, or use a mirror
nmap -sV --script cvescannerv2 --script-args catalog=none <TARGET>
nmap -sV --script cvescannerv2 --script-args catalog_url=http://127.0.0.1:8000/ <TARGET>
```

</details>

> **Note**: `nmap/src/cvescannerv2.nse` can be placed in Nmap's default script
> directory to run it globally; a **symbolic link** keeps it in sync with the
> repository.
>
> - Linux and macOS: `/usr/local/share/nmap/scripts/`,
>   `/usr/share/nmap/scripts/`, `/opt/local/share/nmap/scripts/`,
>   `/usr/local/Cellar/nmap/<version>/share/nmap/scripts/`
> - Windows: `C:\Program Files\Nmap\Scripts`, `%APPDATA%\nmap`

# Output

For every service with matches, the table shows the product, the version used
for the lookup, **where that version came from** (`version_source`) and the
CVEs with a `Conf` column holding the confidence level.

<details>
<summary><b>Nmap output (Metasploitable 2)</b></summary>

```
PORT     STATE SERVICE     VERSION
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
| cvescannerv2:
|   vendor: samba
|   product: samba
|   version: 3.0.20
|   vupdate: *
|   version_source: smb
|   cves: 64
|   	CVE ID              	Conf  	CVSSv2	CVSSv3	ExploitDB 	Metasploit
|   	CVE-2007-2446       	HIGH  	10.0 	-    	No        	Yes
|   	CVE-2012-1182       	HIGH  	10.0 	-    	No        	Yes
|   	CVE-2022-45141      	HIGH  	nil  	9.8  	No        	No
|   	...
6667/tcp open  irc         UnrealIRCd
| cvescannerv2:
|   vendor: unrealircd
|   product: unrealircd
|   version: 3.2.8.1
|   vupdate: *
|   version_source: irc
|   cves: 3
|   	CVE ID              	Conf  	CVSSv2	CVSSv3	ExploitDB 	Metasploit
|   	CVE-2016-7144       	HIGH  	6.8  	8.1  	No        	No
|   	CVE-2010-2075       	HIGH  	7.5  	-    	Yes       	Yes
|   	CVE-2017-13649      	HIGH  	2.1  	5.5  	No        	No
```

Nmap alone reports `Samba smbd 3.X - 4.X` and `UnrealIRCd` without a version;
the probes provide the exact versions (see [Service probes](#service-probes)).

</details>

Fields of the service header:

| Field | Meaning |
|---|---|
| `version_source` | Evidence that produced the version: `nmap_cpe`, `nmap_version`, `http`, `smb`, `irc` (see [Where the version comes from](#where-the-version-comes-from)). |
| `warnings` | `distro_backport` when the version string suggests a distribution package that may carry backported fixes (see [Operating system context](#operating-system-context)). |

The **log** (`*.log`) contains every exploit and Metasploit module found.

<details>
<summary><b>cvescannerv2.log</b></summary>

```
## 2023-08-26T14:38:30+00:00

[*] host: 192.168.69.129
[*] port: 3306
[+] protocol: tcp
[+] service: mysql
[+] cpe: cpe:/a:mysql:mysql:5.0.51a-3ubuntu5
[+] product: mysql
[+] version: 5.0.51
[+] vupdate: a
[+] cves: 212
[-] 	id: CVE-2009-2446     	cvss_v2: 8.5  	cvss_v3: -
[-] 	id: CVE-2009-4484     	cvss_v2: 7.5  	cvss_v3: -
[!] 		Metasploit:
[#] 			name: exploit/linux/mysql/mysql_yassl_getname
...
```

</details>

The **JSON report** (`*.json`) has the same information and adds, per
service, `version_source`, `os_context`, `warnings` and `summary` (number of
CVEs per confidence level), and per CVE, `confidence` and `reasons`.

<details>
<summary><b>cvescannerv2.json</b></summary>

```json
{
  "192.168.251.131": {
    "timestamp": "2026-10-30T14:32:36+00:00",
    "ports": {
      "6667/tcp": {
        "services": [
          {
            "name": "irc",
            "cpe": "cpe:/a:unrealircd:unrealircd",
            "vendor": "unrealircd",
            "product": "unrealircd",
            "version": "3.2.8.1",
            "vupdate": "*",
            "version_source": "irc",
            "os_context": {},
            "warnings": {},
            "summary": { "high": 3, "medium": 0, "low": 0 },
            "vulnerabilities": {
              "total": 3,
              "info": "scan",
              "cves": {
                "CVE-2016-7144": {
                  "cvssv2": "6.8",
                  "cvssv3": "8.1",
                  "confidence": "high",
                  "reasons": ["range_contains"]
                }
              }
            }
          }
        ]
      }
    }
  }
}
```

</details>

# Detection heuristics

This section explains every decision the script makes between Nmap's output and
the final list, so you can judge how much to trust a result.

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

## HTTP fingerprinting

Used only on ports that Nmap's `shortport` library classifies as HTTP, SSL or
UPnP, **and** whose detected service can actually speak HTTP.

- On first use the script downloads `index.json`, `fingerprints.json`,
  `paths.json` and `probes.json` from the upstream
  [nmap-vulners](https://github.com/vulnersCom/nmap-vulners) catalogue and
  caches them in `data/`. Later runs reuse them (delete the four files and
  `data/.vulners-catalog-source` to download them again). If the catalogue
  cannot be fetched, the legacy JSON files are used when present; Nmap CPE
  detection works without either source.
- It checks the responses of the catalogue paths: headers, body, title, meta
  tags, script sources and cookies, plus Nmap's own service fingerprints.
  Requests are pipelined in batches paced according to Nmap's timing template.
- A **targeted probe** (for example a changelog page) runs only after its
  product detector matched and no precise version was found.
- **Non-HTTP services are excluded.** Services such as `ms-wbt-server` (RDP),
  `ssh`, `mysql` or `microsoft-ds` never enter the HTTP engine, even when they
  use TLS. Before this rule an RDP port could keep the scan busy
  indefinitely.
- **Abort on silence.** If a port stops answering HTTP, the engine gives up
  after five consecutive failed requests (legacy mode) or when a whole request
  batch returns no response (catalogue mode), instead of trying every path.

## Service probes

When Nmap cannot give a precise version (empty, a `x.y` series or a range such
as `3.X - 4.X`), the script can ask the service itself. Probes are designed to
be cheap and safe:

- **Targeted, never blind.** A probe runs only if Nmap already identified the
  matching service **and** product on that port. A port number alone never
  triggers a probe, and there are no sweeps.
- **Only when needed.** A probe never runs if Nmap already reported a precise
  version.
- **Read-only.** No credentials, no writes, no exploit payloads.
- **Fail soft.** Any error or timeout falls back to the Nmap result and never
  aborts the port. Results (including failures) are cached.
- **Bounded cost.** At most one extra connection per service (two for `irc`
  when throttled) and one SMB round per host.

| Probe | Triggers on | What it asks | Notes |
|---|---|---|---|
| `smb` | Samba on 139/445 (`netbios-ssn`, `microsoft-ds`) | Nmap's `smb.get_os` (`lanmanager` field) | Gives the exact Samba version instead of `3.X - 4.X`. One query per host, shared by all its SMB ports. |
| `irc` | UnrealIRCd on an `irc`/`ircs` service | `NICK`/`USER`/`VERSION`, reads reply 351 | Exact UnrealIRCd version. The nick appears in the IRC server log. UnrealIRCd throttles reconnections right after `-sV`: on `Throttled` the probe waits 20 s and retries once. |
| `smb_os` | A host with an SMB service, only when a CVE needs a platform and the OS is unknown | Nmap's `smb.get_os` (`os` field) | Reports `windows` for real Windows hosts. See [Operating system context](#operating-system-context). |
| `ntp` | An `ntp` service (UDP, needs `-sU`) | NTP mode 6 `readvar` (`version="ntpd 4.2.6p5..."`) | Exact ntpd version and patch (`4.2.6p5`) instead of `NTP v4`. `ntpsec`/`chrony` are ignored. Many ntpd block mode 6 (`noquery`): then it falls back to Nmap. |
| `cups` | A CUPS service (`ipp`, product `cups`) with a series version | `GET /` and reads the page title (`Home - CUPS 2.1.3`, also on a 403 page) | Exact CUPS version instead of `2.1`. One request, no catalogue involved. |
| `upnp` | A `upnp` service (UDP 1900, needs `-sU`) | Unicast SSDP `M-SEARCH`, reads the `SERVER:` header | Exact miniupnpd version (`MiniUPnPd/1.8`) when Nmap gives none. Other UPnP stacks are ignored. |

Select them with `probes=none`, `probes=all` or `probes=<csv>`.

**Version scripts.** The script declares `dependencies` on the Nmap
`version` scripts that publish a version (`weblogic-t3-info`,
`oracle-tns-version`, `docker-version`, `jdwp-version`, `vmware-version`,
`db2-das-info`, `ike-version`, `mqtt-subscribe`, `amqp-info`, `xmpp-info`), so
that `port.version` already holds their result when the analysis runs. Without
this, WebLogic was analysed with version `*` (race with `weblogic-t3-info`).
They only run with `-sV`.

**Product to CPE overrides.** `data/product-cpe.json` (arg `product_cpe`,
`none` disables it) maps an exact Nmap product string to the right CPE and
replaces the one Nmap reports. Today it holds `Oracle GlassFish`, which Nmap
reports with the CPE of JSP (`cpe:/a:oracle:jsp`); the alias
`glassfish_server` also queries `glassfish`.

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
- UnrealIRCd rejects fast reconnections ("Throttled"). The probe waits 20 s
  and retries once; if the server is still throttling, the Nmap result is
  kept. Run with `-d` to see the probe messages.
- Probes only run when Nmap identified the service and product. If Nmap shows
  `irc?` or an empty product, no probe is attempted.

# Docker container

The multi-stage Docker build publishes two `scratch` images. The `db` target
contains the latest database built from the `CVEScannerV2DB` dump repository;
the `nodb` target omits it. Both contain only Nmap, its runtime dependencies,
the NSE script and the data files the scanner needs.

- Database embedded: `scmanjarrez/cvescanner:db` or
  `scmanjarrez/cvescanner:latest`
- No database: `scmanjarrez/cvescanner:nodb`

On a release, the workflow also publishes the Git tag for the database image
and the same tag with `-nodb` appended for the lightweight image (for example
`v4.0` and `v4.0-nodb`).

```bash
docker run -v /tmp/cvslogs:/tmp/cvslogs scmanjarrez/cvescanner:db \
  --script-args log=/tmp/cvslogs/scan.log,json=/tmp/cvslogs/scan.json <TARGET>

docker run -v "$PWD/data:/CVEScannerV2/data" \
  -v /tmp/cvslogs:/tmp/cvslogs scmanjarrez/cvescanner:nodb \
  --script-args log=/tmp/cvslogs/scan.log,json=/tmp/cvslogs/scan.json \
  <TARGET>
```

Build either target locally with Docker Buildx:

```bash
docker buildx build --load --target nodb \
  -t scmanjarrez/cvescanner:nodb .
docker buildx build --load --target db \
  --build-arg DATABASE_REFRESH="$(date +%s)" \
  -t scmanjarrez/cvescanner:db .
```

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

# Project architecture

The repository has two runtime components:

- `cvescannerv2.nse` scans discovered services and reads CVE data from SQLite.
- `db-manager/` is a Python package that updates and queries that database.

The database package separates command-line and Textual interfaces,
application workflows, domain data and CPE parsing, and infrastructure
adapters for NVD, Metasploit, Exploit-DB, HTTP and SQLite. See the
[`db-manager` guide](db-manager/README.md) for its architecture and workflows.

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
