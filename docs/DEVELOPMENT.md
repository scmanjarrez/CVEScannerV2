# CVEScannerV2 development guide

This guide is for contributors. User documentation is in [`../README.md`](../README.md); the design rationale is in [DESIGN.md](DESIGN.md).

## Repository components

- `nmap/src/cvescannerv2.nse` is the entrypoint. It scans discovered services
  and reads CVE data from SQLite. Its logic lives in the Lua modules under
  `nmap/src/cvescannerv2/`.
- `db-manager/` is a Python package that updates and queries that database.
- [`DATABASE.md`](DATABASE.md) describes the `cve.db` schema, the NVD mapping and the update lifecycle.

## Scanner modules and layers

| Module | Layer | Responsibility |
|--------|-------|----------------|
| `util` | L0 | Pure string and file helpers. |
| `state` | L0 | Shared state, the only place where data is shared between threads. |
| `config` | L0 | Reads and normalizes every script argument. |
| `cpe` | L0 | Pure CPE 2.2 and 2.3 string parser. |
| `version` | L1 | Version parsing and comparison. |
| `match_table` | L2 | Records detected versions and prunes series entries. |
| `catalog.validate` | L2 | Pure validation of the catalogue JSON files. |
| `catalog.tiers` | L2 | Route classifier into core, family and tail tiers for the sweep. |
| `reference_files` | L2 | Loads and validates the reference data files. |
| `db` | L2 | SQLite access. |
| `log` | L2 | Log file helpers. |
| `json_report` | L2 | JSON report helpers. |
| `catalog.store` | L3 | Vulners catalogue loading from `data/` and the local catalogue overlay. |
| `fingerprint_match` | L3 | Fingerprint matching against catalogue rules and response text. |
| `sweep_evidence` | L3 | Family and linked-prefix evidence from HTTP responses. |
| `os_context` | L3 | Operating system context from Nmap and catalogue data. |
| `probes.smb` | L3 | SMB version and OS probes. |
| `probes.irc` | L3 | UnrealIRCd version probe. |
| `probes.ntp` | L3 | ntpd version probe (readvar). |
| `probes.upnp` | L3 | miniupnpd version probe (SSDP). |
| `http_fingerprint` | L4 | HTTP fingerprint engine: targeted probes and tiered catalogue sweep. |
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
[`db-manager` guide](../db-manager/README.md) for its architecture and workflows.

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

**Pending candidates.** One per route. No dates are promised.

- **P1 (V1):** `mcafee-epo-agent`, mapped to `mcafee:agent` (25 CVEs in the database built on 2026-11-17). The
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
    - `teamspeak2-version`: the only 2.x version the DB
      has in `teamspeak:teamspeak` is `2.0.32`; the script publishes
      `2.0.32.60`.
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
  (27960-27964 are in the `Quake3_getstatus` probe ports) and `fox-info`
  (port 1911 is in the `niagara-fox` probe ports, rarity 9). These may already
  be resolved at intensity 7 on those ports.
- **V3 `SERVICE_PROBES`:** `couchdb-databases`, `couchdb-stats`,
  `uptime-agent-info`, `http-mcmp`, `irc-info` (may overlap the existing `irc`
  probe) and `versant-info`.
- **V4 HTTP catalogue:** `hadoop-namenode-info`, `hadoop-datanode-info`,
  `hadoop-jobtracker-info`, `hadoop-secondary-namenode-info`,
  `hadoop-tasktracker-info`, `hbase-master-info`, `hbase-region-info`,
  `flume-master-info` and `http-server-header`.

## Version scripts and runlevels

**Version scripts.** The `dependencies` list (`weblogic-t3-info`,
`oracle-tns-version`, `docker-version`, `jdwp-version`, `vmware-version`,
`db2-das-info`, `ike-version`, `mqtt-subscribe`, `amqp-info`, `xmpp-info`)
only raises the runlevel: `cvescannerv2` runs in runlevel 2. It does not
select which scripts run. With `-sV` every `version` script runs in runlevel
1, before `cvescannerv2`, so `port.version` is set whether or not a script is
listed. Verified: `rpcinfo` (not listed) runs in runlevel 1 and
`cvescannerv2` sees its result. The `version` scripts only run with `-sV`.

## Discarded probe candidates

Candidates that were evaluated against lab targets and **discarded** because
`nmap -sV` already gives the same information, or because no target exposed
them: `ftp-syst`, `ajp-headers`, NTLM probes (`rdp-ntlm-info`,
`http-ntlm-info`), `snmp-sysdescr` and `mysql-info`.

## Releasing

Releases are cut from `master`. The version must match in the code, the README
examples and the release tag.

1. Set the version and commit:

   ```bash
   scripts/bump-version.sh X.Y.Z          # nmap/src/cvescannerv2.nse, db-manager/pyproject.toml, db-manager/uv.lock, README.md examples
   scripts/bump-version.sh --check X.Y.Z  # verifies the three version files only
   ```

   Commit and push to `master`, and wait for CI to pass.

2. Create the release with the same number:

   ```bash
   gh release create vX.Y.Z --target master --title "CVEScannerV2 X.Y.Z" --generate-notes
   ```

3. Publishing the release triggers:

   - `docker.yaml` (Publish Nmap images), after checking the version against the
     tag. It pushes `scmanjarrez/cvescanner` with `db` images tagged `db`, `v4-db`,
     `latest`, `X.Y.Z` and `X.Y`, and `nodb` images tagged `nodb`, `v4-nodb`,
     `X.Y.Z-nodb` and `X.Y-nodb`.
   - `release.yaml` (Release tarballs), after checking the version against the
     tag. It builds `cvescannerv2-X.Y.Z-db.tar.gz` and
     `cvescannerv2-X.Y.Z-nodb.tar.gz` plus `SHA256SUMS`, and attaches them to the
     release.

   Both checks fail if the code version does not match the tag. `docker.yaml`
   also runs after each database update (`database.yaml`), which rebuilds only
   the rolling tags (`db`, `nodb`, `v4-db`, `v4-nodb`).

4. Before releasing, the `CVEScannerV2DB` dump must be v4. `release.yaml` fails
   otherwise and asks you to run the "Update database" workflow first.

Published version tags and releases are not moved. Fix a mistake with a new
release. CI does move the rolling tags listed above.

## Tests


Run these checks from the repository root. They use temporary SQLite databases
and mocked external services; the scanner tests do not need Nmap.

```bash
# Database package (run inside db-manager/, as the CI does: the tests import
# the `tests` package)
(cd db-manager && uv run python -m unittest discover -s tests -v)

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
so they never touch the network. See [`nmap/tests/README.md`](../nmap/tests/README.md) for
the containerised runner.
