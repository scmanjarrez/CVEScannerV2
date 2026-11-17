# CVEScannerV2 design decisions

User documentation: [README](../README.md). Contributor guide: [DEVELOPMENT.md](DEVELOPMENT.md).

This page explains why the main decisions were taken. Every fact comes from the README.

## 1. Local database, no API calls at scan time

**Decision:** the scan reads a local SQLite database (`data/cve.db`). It makes no API calls and never downloads the catalogue.

**Why:** scans need no Internet access. The database is built ahead of time with `db-manager`, and the HTTP catalogue is fetched separately with `scripts/download-catalog.sh` ([Requirements](../README.md#requirements)).

## 2. Improve Nmap evidence instead of replacing it

**Decision:** Nmap stays the source of service, product and version. The script adds evidence on top: HTTP fingerprints, safe protocol probes and OS context.

**Why:** Nmap discovers the services. Enrichment reduces its errors but cannot remove them ([How it works](../README.md#how-it-works)). A probe that returns a precise version **replaces** the imprecise Nmap version; it is not added as a second candidate ([Where the version comes from](../README.md#where-the-version-comes-from)).

## 3. Service probes: targeted, read-only, fail soft, bounded

**Decision:** a probe runs only when Nmap already identified the matching service and product on that port. It never runs when Nmap already reported a precise version.

**Why:**
- A port number alone never triggers a probe.
- Probes are read-only: no credentials, no writes, no exploit payloads.
- Any error or timeout falls back to the Nmap result and never aborts the port. Results, including failures, are cached.
- Cost is bounded: at most one extra connection per service (two retries for `irc` when throttled) and one SMB round per host ([Service probes](../README.md#service-probes)).

## 4. HTTP fingerprinting: scoped, opt-in sweep

**Decision:**
- Non-HTTP services never enter the HTTP engine, even when they use TLS.
- The catalogue sweep is opt-in (`sweep=1`) and tiered (T0 to T3), capped at `sweep_budget` (default `50`) requests per port.
- Soft-404 responses are detected and discarded.
- The sweep gives up when a whole request batch gets no response.
- Rules see only 2xx and 3xx responses unless they set `accept_403`.
- The local catalogue ships empty.

**Why:**
- Before the non-HTTP rule, an RDP port (`ms-wbt-server`) could keep the scan busy indefinitely.
- On Metasploitable 2 and 3, `sweep=1` finds the same products and CVEs as `sweep=2` with about 95 % fewer requests (50 instead of ~955 per port).
- Stopping on silence avoids trying every path on a port that no longer answers HTTP.
- `accept_403` is opt-in so that error pages of WAFs or proxies are not attributed to the wrong service.
- Anything a targeted probe can read (such as CUPS) is a probe, not a catalogue rule ([HTTP fingerprinting](../README.md#http-fingerprinting)).

## 5. Platform handling

**Decision:**
- The OS probe runs on demand only.
- Samba is not Windows.
- No CVE is removed because of its platform; the platform is shown through confidence.
- Distribution packages get a `distro_backport` warning.
- While the OS is unknown, the analysis cache is keyed per host.

**Why:**
- The OS probe runs only when a CVE carries a platform condition and the OS is still unknown.
- Samba announces itself as `Windows 6.1 (Samba x.y)`. The probe ignores such answers and never infers a Linux distribution from Samba.
- Hiding a CVE would hide information. Confidence shows it instead.
- Distributions backport fixes without changing the version number, so their CVEs need checking against the distribution's tracker.
- One host must never inherit another host's conclusions ([Operating system context](../README.md#operating-system-context)).

## 6. Confidence and filtering

**Decision:**
- A CVE's confidence is the **lowest** level among its reasons.
- The JSON report keeps every CVE. `minconf` filters only the table and the log.
- The default is `minconf=medium`.

**Why:**
- A match is only as reliable as its weakest reason.
- Filtering must not lose data: the JSON report is the complete record for scripts ([Script arguments](../README.md#script-arguments)).
- The default hides low-confidence noise. `minconf=low` shows everything ([Confidence levels](../README.md#confidence-levels)).

## 7. Version intensity: no `--version-intensity 9` by default

**Decision:** do not set `--version-intensity 9` by default. The script cannot set it itself.

**Why:**
- `nmap.version_intensity(n)` does not change the probes sent by `-sV`.
- Intensity 7 sends 30 probes on a port that no probe lists; 9 sends 104. The extra 74 have rarity 8-9.
- On MS3 (192.168.251.132, 25 open ports), intensity 9 gave no extra version and no change in CVEs or confidence, except port 3389, where `ms-wbt-server` became `ssl`.
- MS3 reported 553 CVEs and 72 high/critical with both intensities.
- MS3 took 203.5 s with intensity 7 and 581.6 s with intensity 9, about 2.9 times slower.
- On MS2 and the lab, intensity 9 was faster.
- Each time was measured once. The MS3 JSON carries a product for only 4 of 25 open ports, so its CVE total is undercounted.
- Repeat the measurement on a target that responds differently to the intensity before changing the default ([Version evidence sources](DEVELOPMENT.md#version-evidence-sources)).

## 8. v4 output: breaking change, schema version 2

**Decision:**
- The v4 output breaks compatibility. There is no legacy mode.
- The JSON report is `schema_version: 2`.
- NVD CVSS v4 scores are stored and shown as `v4`.

**Why:**
- The old `services`/`vulnerabilities`/`summary` layout is gone, and `hosts` is now an array. Scripts that parsed the previous format must be updated.
- A database built before CVSSv4 has no `cvss_v4` values. The scanner still works, writes a `warning` line to the log and reports `v4` as `null` ([Changes in the v4 output](../README.md#changes-in-the-v4-output)).

## 9. Limits accepted by design

The script cannot overcome these limits of Nmap-based detection. See [Limitations](../README.md#limitations) for the full list.

- It cannot confirm that a CVE is exploitable on the target.
- It cannot see the service configuration.
- It cannot tell which Metasploit or Exploit-DB modules are active or applicable.
- A CVE that needs several applications (AND) cannot be fully checked when one of them is not detected.
- Samba over SMB2/3 only exposes no version to the `smb` probe.
- The OS probe recognises only Windows.
- The database holds only application CPEs, so OS-level CVEs are not reported.
- Backported fixes cannot be detected from the version number.

## Measured impact

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
