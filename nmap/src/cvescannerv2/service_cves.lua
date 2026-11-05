-- SPDX-License-Identifier: GPL-3.0-or-later
-- Vulnerability lookup for one service. (Layer L7)
--
-- Finds the CVEs that affect a service, adds the platform reasons, sorts
-- them by confidence, stores them in the JSON report and returns the
-- output rows for the entrypoint. I/O: SQL reads through db, log output
-- and report writes; no network or files. Reads state.has_conditions,
-- config.minconf and config.maxcve.

local util = require 'cvescannerv2.util'
local config = require 'cvescannerv2.config'
local state = require 'cvescannerv2.state'
local report = require 'cvescannerv2.json_report'
local db = require 'cvescannerv2.db'
local log = require 'cvescannerv2.log'
local version = require 'cvescannerv2.version'
local scope = require 'cvescannerv2.version_scope'
local platform = require 'cvescannerv2.platform_match'
local confidence = require 'cvescannerv2.confidence'
local render = require 'cvescannerv2.text_output'

local is_blank, fmt = util.is_blank, util.fmt
local log_separator = log.log_separator
local vendor_scope = db.vendor_scope
local series_has_children = db.series_has_children
local has_conditions = db.has_conditions
local display_version = version.display_version
local series_prefix = version.series_prefix
local spans_series = version.spans_series
local scoped_multi_versions = scope.scoped_multi_versions
local scoped_versions = scope.scoped_versions
local merge_series = scope.merge_series
local platform_probe_needed = platform.platform_probe_needed
local strip_platform_reasons = platform.strip_platform_reasons
local confidence_comparator = confidence.confidence_comparator
local assign_confidence = confidence.assign_confidence
local add_reason = confidence.add_reason
local LEVEL_RANK = confidence.LEVEL_RANK
local cve_row = render.cve_row
local host_probe_os = require 'cvescannerv2.probes.init'.host_probe_os

local M = {}

-- Store one CVE in the JSON report and, when show is true, in the log.
local function report_exploits(host, port, vuln, rec, show)
  local _ip = host.ip
  local _port = fmt('%s/%s', port.number, port.protocol)
  local emit = show and log.write or function() end
  local reasons = #rec.reasons > 0 and table.concat(rec.reasons, ', ') or '-'
  -- Dump the CVE score
  local cvssv2, cvssv3 = db.cvss_scores(vuln)
  emit("[-] \tid: %-18s\tcvss_v2: %-5s\tcvss_v3: %-5s", vuln, cvssv2,
    cvssv3 or "-")
  emit("[-] \tconfidence: %s\treasons: %s", rec.confidence, reasons)
  report.set_cve(_ip, _port, vuln, {
    ['cvssv2'] = cvssv2,
    ['cvssv3'] = cvssv3 or "-",
    ['confidence'] = rec.confidence,
    ['reasons'] = rec.reasons,
  })
  local cves = report.last_service(_ip, _port)['vulnerabilities']['cves']

  -- Dump exploits from Exploit-DB
  local exploits = db.exploitdb_refs(vuln)
  if #exploits > 0 then
    emit("[!] \t\tExploitDB:")
    cves[vuln]['exploitdb'] = {}
    local exp_list = cves[vuln]['exploitdb']
    for _, exploit in ipairs(exploits) do
      emit("[#] \t\t\tname: %s", exploit.name)
      emit("[#] \t\t\tid: %s", exploit.id)
      emit("[#] \t\t\turl: https://www.exploit-db.com/exploits/%s", exploit.id)
      exp_list[#exp_list + 1] = {
        ['name'] = exploit.name,
        ['id'] = exploit.id,
        ['url'] = fmt('https://www.exploit-db.com/exploits/%s', exploit.id)
      }
    end
  end

  -- Dump exploits from Metasploit
  local modules = db.metasploit_refs(vuln)
  if #modules > 0 then
    emit("[!] \t\tMetasploit:")
    cves[vuln]['metasploit'] = {}
    local meta_list = cves[vuln]['metasploit']
    for _, name in ipairs(modules) do
      emit("[#] \t\t\tname: %s", name)
      meta_list[#meta_list + 1] = { ['name'] = name }
    end
  end
end


-- Append the platform reasons of the CVEs in vulns to rec.reasons.
-- No CVE is removed; the visible output does not change.
local function add_platform_reasons(vulns, vendors, product, os_ctx)
  local rows_by_cve = {}
  local first_check = state.has_conditions == nil
  local present = has_conditions()
  if first_check and not present then
    log.write('[!] Database without conditions table; platform checks skipped.')
  end
  if present then
    rows_by_cve = db.platform_condition_rows(vendors, product)
  end
  platform.add_platform_reasons(vulns, rows_by_cve, os_ctx)
end


-- Return the version bounds of the service as a table with the fields
-- from, to, multi_from, multi_to and observed_update.
local function version_bounds(info)
  local bounds = {
    from = info.version,
    to = info.version,
    observed_update = info.update or '*',
  }
  bounds.multi_from = bounds.from
  bounds.multi_to = bounds.to
  if not info.matches_any then
    if info.is_range then
      bounds.from = info.from:gsub('[xX]', '0')
      bounds.to = info.to:gsub('[xX]', '9999999999')
      bounds.multi_from = bounds.from
      bounds.multi_to = bounds.to
    elseif not is_blank(bounds.observed_update)
        and bounds.observed_update ~= '*'
        and bounds.observed_update ~= '-' then
      bounds.multi_from = info.version .. bounds.observed_update
      bounds.multi_to = bounds.multi_from
    end
  end
  return bounds
end


-- Collect the CVEs whose multi-version ranges match the service.
-- Return the CVE table and whether the series children are expanded.
local function collect_multi(vendors, product, info, bounds, series)
  local vulns = {}
  -- Given that we assumed '*' as version and vupdate when empty, we can't
  -- search vulnerabilities for specific versions.
  local cve_lines = db.range_affected_rows(vendors, product, info.matches_any)
  scoped_multi_versions(cve_lines, bounds.multi_from, bounds.multi_to,
    vulns, info.matches_any)
  local expand = series ~= nil
    and series_has_children(vendors, product, series)
  if expand then
    local found = {}
    scoped_multi_versions(cve_lines, series .. '.0',
      series .. '.9999999999', found, false)
    merge_series(found, vulns)
  end
  return vulns, expand
end


-- Add to vulns the CVEs that affect the exact service version.
local function collect_exact(vendors, product, bounds, series, expand, vulns)
  local cve_lines = db.exact_affected_rows(vendors, product)
  scoped_versions(cve_lines, bounds.from, bounds.to,
    bounds.observed_update, vulns)
  if expand then
    local found = {}
    scoped_versions(cve_lines, series .. '.0',
      series .. '.9999999999', '*', found)
    merge_series(found, vulns)
  end
end


-- Return the CVEs that affect the service, with their scope reasons.
local function find_cves(vendors, product, info, bounds)
  local series = series_prefix(info)
  local vulns, expand = collect_multi(vendors, product, info, bounds, series)
  if not info.matches_any then
    collect_exact(vendors, product, bounds, series, expand, vulns)
  end
  if info.is_range and spans_series(info.from, info.to) then
    add_reason(vulns, 'observed_range')
  end
  return vulns
end


-- Add the platform reasons and re-check them when the OS is unknown.
-- Return the OS context used for the service.
local function resolve_os_context(host, vulns, vendors, product, scan_ctx)
  local os_ctx = scan_ctx and scan_ctx.os or {}
  add_platform_reasons(vulns, vendors, product, os_ctx)
  if platform_probe_needed(vulns, os_ctx) then
    local probed = host_probe_os(host)
    if probed then
      os_ctx = { family = probed.family, source = probed.source }
      strip_platform_reasons(vulns)
      add_platform_reasons(vulns, vendors, product, os_ctx)
    end
  end
  return os_ctx
end


-- Build the meta table with the confidence summary and the warnings.
local function build_meta(vulns, scan_ctx, os_ctx)
  local meta = {
    summary = assign_confidence(vulns),
    warnings = {},
    version_source = scan_ctx and scan_ctx.version_source,
    os_context = os_ctx,
    shown = 0,
  }
  if scan_ctx and scan_ctx.backport then
    table.insert(meta.warnings, 'distro_backport')
  end
  return meta
end


-- Return the CVEs as sorted tuples by confidence, CVSSv3 and CVSSv2.
local function sort_cves(vulns)
  local sorted = {}
  for key, value in pairs(vulns) do
    table.insert(sorted, { key,
      value.CVSSV2, value.CVSSV3,
      value.ExploitDB,
      value.Metasploit,
      value.confidence })
  end
  table.sort(sorted, confidence_comparator)
  log.write("[+] cves: %d", #sorted)
  return sorted
end


-- Store the service and its version data in the JSON report.
local function add_service_entry(host, port, cpe, vendor, product, info,
    meta)
  local port_proto = fmt('%s/%s', port.number, port.protocol)
  report.ensure_port(host.ip, port_proto)
  local ver_text, update = display_version(info)
  report.add_service(host.ip, port_proto,
    {
      name = port.service,
      cpe = cpe,
      vendor = vendor,
      product = product,
      version = ver_text,
      vupdate = update,
      version_source = meta.version_source,
      os_context = meta.os_context,
      warnings = meta.warnings,
      summary = meta.summary,
      vulnerabilities = {
        ['total'] = 0,
        ['info'] = 'scan',
        ['cves'] = {}
      }
    }
  )
end


-- Dump each CVE in the report and append the shown rows to output.
-- Return the number of CVEs shown.
local function emit_cve_rows(host, port, sorted, vulns, output)
  local cnt = 0
  for _, value in ipairs(sorted) do
    local show = LEVEL_RANK[value[6]] >= LEVEL_RANK[config.minconf]
    report_exploits(host, port, value[1], vulns[value[1]], show)
    if show then
      if cnt < config.maxcve then
        table.insert(output,
          cve_row(value[1], value[6], value[2], value[3],
            value[4], value[5])
        )
      end
      cnt = cnt + 1
    end
  end
  return cnt
end


-- Return the CVE count, the output lines, and the meta table with the
-- confidence summary and the service warnings.
local function find_service_cves(host, port, cpe, vendor, product, info,
    scan_ctx)
  local vendors = vendor_scope(vendor, product)
  local bounds = version_bounds(info)
  local vulns = find_cves(vendors, product, info, bounds)
  local os_ctx = resolve_os_context(host, vulns, vendors, product, scan_ctx)
  local meta = build_meta(vulns, scan_ctx, os_ctx)

  local sorted = sort_cves(vulns)
  local output = {}
  table.insert(output, #sorted)
  if #sorted > 0 then
    add_service_entry(host, port, cpe, vendor, product, info, meta)
  end
  meta.shown = emit_cve_rows(host, port, sorted, vulns, output)
  log_separator()
  return output, meta
end


M.add_platform_reasons = add_platform_reasons
M.find_service_cves = find_service_cves

return M
