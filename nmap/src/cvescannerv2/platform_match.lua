-- SPDX-License-Identifier: GPL-3.0-or-later
-- Platform (operating system) compatibility of CVE configurations.  (Layer L5)
--
-- Pure comparison of the OS platform rows of each CVE with the OS context
-- of the host. Only the family table is read from the shared state, on
-- every call. No SQL and no logging here: the caller loads the rows.
-- E/S: ninguna (no red, no fichero, no SQL).

local state = require 'cvescannerv2.state'

local M = {}


local PLATFORM_RANK = { ok = 4, family = 3, unknown = 2, bad = 1 }

-- Compare one OS platform row with the host context.
-- Return 'ok', 'family', 'unknown' or 'bad'.
local function os_platform_status(row, os_ctx)
  local family = state.platform_families[row.vendor]
  if family == nil or os_ctx.family == nil then return 'unknown' end
  if family ~= os_ctx.family then return 'bad' end
  if row.vendor == 'linux' then return 'ok' end
  if os_ctx.distro == nil then return 'family' end
  local distro_vendor = os_ctx.distro
  if os_ctx.distro == 'ubuntu' then distro_vendor = 'canonical' end
  if row.vendor == distro_vendor then return 'ok' end
  return 'bad'
end


-- Return the best status, family and vendor of one AND configuration.
-- A configuration without OS platform rows is a component requirement.
local function config_status(rows, os_ctx)
  local best, family, vendor = nil, nil, nil
  for _, row in ipairs(rows) do
    if row.part == 'o' then
      local status = os_platform_status(row, os_ctx)
      family = family or state.platform_families[row.vendor]
      vendor = vendor or row.vendor
      if best == nil or PLATFORM_RANK[status] > PLATFORM_RANK[best] then
        best = status
      end
    end
  end
  if best == nil then return 'component', nil, nil end
  return best, family, vendor
end


-- Return the platform reason for the configuration rows of one CVE.
-- Any compatible configuration clears the reason.
local function evaluate_platform(rows, os_ctx)
  if #rows == 0 then return nil end
  local configs, order = {}, {}
  for _, row in ipairs(rows) do
    if configs[row.config_idx] == nil then
      configs[row.config_idx] = {}
      table.insert(order, row.config_idx)
    end
    table.insert(configs[row.config_idx], row)
  end
  table.sort(order)
  local all_bad, needs_platform, has_component = true, false, false
  local first_family, first_vendor = nil, nil
  for _, idx in ipairs(order) do
    local status, family, vendor = config_status(configs[idx], os_ctx)
    if status == 'ok' then return nil end
    if status ~= 'bad' then all_bad = false end
    if status == 'unknown' or status == 'family' then
      needs_platform = true
    end
    if status == 'component' then has_component = true end
    if first_family == nil then
      first_family, first_vendor = family, vendor
    end
  end
  if all_bad then
    -- Same family but wrong distro: name the required vendor.
    if first_family == os_ctx.family then
      return 'platform_mismatch:' .. first_vendor
    end
    return 'platform_mismatch:' .. first_family
  end
  if needs_platform then return 'requires_platform' end
  if has_component then return 'requires_component' end
  return nil
end


-- Append the platform reasons of the CVEs in vulns to rec.reasons.
-- rows_by_cve maps each CVE to its platform rows. No CVE is removed.
local function add_platform_reasons(vulns, rows_by_cve, os_ctx)
  for id, rec in pairs(vulns) do
    local reason = evaluate_platform(rows_by_cve[id] or {}, os_ctx)
    rec.reasons = rec.reasons or {}
    if reason then table.insert(rec.reasons, reason) end
  end
end


-- True when a platform reason depends on the OS context of the host.
local function is_platform_reason(reason)
  return reason == 'requires_platform' or reason == 'requires_component'
      or reason:find('^platform_mismatch:') ~= nil
end

-- True when a CVE needs the OS and the context has no family and no probe.
local function platform_probe_needed(vulns, os_ctx)
  if os_ctx.family ~= nil then return false end
  if (os_ctx.source or ''):find('^probe') then return false end
  for _, rec in pairs(vulns) do
    for _, reason in ipairs(rec.reasons) do
      if reason == 'requires_platform' then return true end
    end
  end
  return false
end

-- Remove the platform reasons added by a previous add_platform_reasons.
local function strip_platform_reasons(vulns)
  for _, rec in pairs(vulns) do
    local kept = {}
    for _, reason in ipairs(rec.reasons) do
      if not is_platform_reason(reason) then table.insert(kept, reason) end
    end
    rec.reasons = kept
  end
end


--- Return the platform reason of one CVE, or nil when it is compatible.
M.evaluate_platform = evaluate_platform
--- Append the platform reasons of each CVE in vulns to its reasons.
M.add_platform_reasons = add_platform_reasons
--- True when a CVE needs an OS probe to be evaluated.
M.platform_probe_needed = platform_probe_needed
--- Remove the platform reasons added earlier from vulns.
M.strip_platform_reasons = strip_platform_reasons


return M
