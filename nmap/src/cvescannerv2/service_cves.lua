-- SPDX-License-Identifier: GPL-3.0-or-later
-- Vulnerability lookup for one service. (Layer L7)
--
-- Finds the CVEs that affect a service, adds the platform reasons, sorts
-- them by confidence and the exploit references, and returns the result
-- table that text_output and json_report render. I/O: SQL reads through
-- db and warnings through log; no report or output writes, no network or
-- files. Reads state.has_conditions, state.has_aliases, state.has_cvss_v4,
-- config.minconf.

local util = require 'cvescannerv2.util'
local config = require 'cvescannerv2.config'
local state = require 'cvescannerv2.state'
local db = require 'cvescannerv2.db'
local log = require 'cvescannerv2.log'
local version = require 'cvescannerv2.version'
local scope = require 'cvescannerv2.version_scope'
local platform = require 'cvescannerv2.platform_match'
local confidence = require 'cvescannerv2.confidence'

local is_blank, fmt = util.is_blank, util.fmt
local vendor_scope = db.vendor_scope
local series_has_children = db.series_has_children
local has_conditions = db.has_conditions
local alias_names = db.alias_names
local display_version = version.display_version
local series_prefix = version.series_prefix
local spans_series = version.spans_series
local scoped_multi_versions = scope.scoped_multi_versions
local scoped_versions = scope.scoped_versions
local merge_series = scope.merge_series
local merge_alias = scope.merge_alias
local platform_probe_needed = platform.platform_probe_needed
local strip_platform_reasons = platform.strip_platform_reasons
local confidence_comparator = confidence.confidence_comparator
local assign_confidence = confidence.assign_confidence
local add_reason = confidence.add_reason
local LEVEL_RANK = confidence.LEVEL_RANK
local host_probe_os = require 'cvescannerv2.probes.init'.host_probe_os

local M = {}


-- Warn once when the database has no cvss_v4 column.
local function warn_missing_cvss_v4()
  local first_check = state.has_cvss_v4 == nil
  local present = db.has_cvss_v4()
  if first_check and not present then
    log.write('warning: database without cvss_v4 column; CVSSv4 scores '
      .. 'unavailable. Update the database.')
  end
end


-- Return the exploit references of a CVE as {id, name, url} entries.
local function exploit_entries(id)
  local entries = {}
  for _, exploit in ipairs(db.exploitdb_refs(id)) do
    entries[#entries + 1] = {
      id = exploit.id,
      name = exploit.name,
      url = fmt('https://www.exploit-db.com/exploits/%s', exploit.id),
    }
  end
  return entries
end


-- Build the result entry of one CVE from its database record.
local function cve_entry(id, rec)
  local entry = {
    id = id,
    cvss = {
      v4 = tonumber(rec.CVSSV4),
      v3 = tonumber(rec.CVSSV3),
      v2 = tonumber(rec.CVSSV2),
    },
    confidence = rec.confidence,
    reasons = rec.reasons,
    visible = LEVEL_RANK[rec.confidence] >= LEVEL_RANK[config.minconf],
    exploitdb = {},
    metasploit = {},
  }
  if tonumber(rec.ExploitDB) == 1 then
    entry.exploitdb = exploit_entries(id)
  end
  if tonumber(rec.Metasploit) == 1 then
    entry.metasploit = db.metasploit_refs(id)
  end
  return entry
end


-- True when the record was found through another name of a renamed product.
local function found_by_alias(rec)
  if rec == nil then return false end
  for _, reason in ipairs(rec.reasons or {}) do
    if reason == 'alias_product' then return true end
  end
  return false
end


-- Append the platform reasons of the CVEs in vulns to rec.reasons.
-- No CVE is removed; the visible output does not change.
local function add_platform_reasons(vulns, vendors, product, os_ctx)
  local rows_by_cve = {}
  local first_check = state.has_conditions == nil
  local present = has_conditions()
  if first_check and not present then
    log.write('warning: database without conditions table; '
      .. 'platform checks skipped.')
  end
  if present then
    rows_by_cve = db.platform_condition_rows(vendors, product)
    -- The conditions of a renamed product apply only to the CVEs found
    -- through that name, not to the ones the detected name already found.
    for _, alias in ipairs(alias_names(vendors, product)) do
      local rows = db.platform_condition_rows({ alias.vendor }, alias.product)
      for cve, cve_rows in pairs(rows) do
        if rows_by_cve[cve] == nil and found_by_alias(vulns[cve]) then
          rows_by_cve[cve] = cve_rows
        end
      end
    end
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


-- Add to vulns the CVEs filed under the other names of a renamed product.
local function collect_alias(vendors, product, info, bounds, series, vulns)
  for _, alias in ipairs(alias_names(vendors, product)) do
    local names = { alias.vendor }
    local found, expand = collect_multi(names, alias.product, info, bounds,
      series)
    if not info.matches_any then
      collect_exact(names, alias.product, bounds, series, expand, found)
    end
    merge_alias(found, vulns)
  end
end


-- Return the CVEs that affect the service, with their scope reasons.
local function find_cves(vendors, product, info, bounds)
  local series = series_prefix(info)
  local vulns, expand = collect_multi(vendors, product, info, bounds, series)
  if not info.matches_any then
    collect_exact(vendors, product, bounds, series, expand, vulns)
  end
  collect_alias(vendors, product, info, bounds, series, vulns)
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
  }
  if scan_ctx and scan_ctx.backport then
    table.insert(meta.warnings, 'distro_backport')
  end
  return meta
end


-- Return the CVE entries sorted by confidence, then by CVSS.
local function sort_cves(vulns)
  local entries = {}
  for id, rec in pairs(vulns) do
    entries[#entries + 1] = cve_entry(id, rec)
  end
  table.sort(entries, confidence_comparator)
  return entries
end


-- Return the version and update text of the service. A '*' or empty update
-- is nil.
local function version_text(info)
  local ver_text, raw_update = display_version(info)
  ---@type string?
  local update = raw_update
  if update == nil or update == '*' or update == '' then
    update = nil
  end
  return ver_text, update
end


-- Return the result of one service: its product data, the CVE entries
-- sorted by confidence and the counters. Always returns a table, also
-- when no CVE affects the service.
local function find_service_cves(host, _, cpe, vendor, product, info,
                                 scan_ctx)
  warn_missing_cvss_v4()
  local vendors = vendor_scope(vendor, product)
  local bounds = version_bounds(info)
  local vulns = find_cves(vendors, product, info, bounds)
  local os_ctx = resolve_os_context(host, vulns, vendors, product, scan_ctx)
  local meta = build_meta(vulns, scan_ctx, os_ctx)

  local cves = sort_cves(vulns)
  local shown = 0
  for _, entry in ipairs(cves) do
    if entry.visible then shown = shown + 1 end
  end
  local ver_text, update = version_text(info)
  return {
    cpe = cpe,
    vendor = vendor,
    product = product,
    version = ver_text,
    update = update,
    version_source = meta.version_source,
    os_context = meta.os_context,
    warnings = meta.warnings,
    counts = {
      total = #cves,
      high = meta.summary.high,
      medium = meta.summary.medium,
      low = meta.summary.low,
      shown = shown,
    },
    cves = cves,
  }
end


M.add_platform_reasons = add_platform_reasons
M.find_service_cves = find_service_cves

return M
