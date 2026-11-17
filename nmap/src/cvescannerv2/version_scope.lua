-- SPDX-License-Identifier: GPL-3.0-or-later
-- Scope matching of NVD rows against the observed version.  (Layer L5)
--
-- Pure decisions: whether an NVD row applies to an observed version or
-- range, and the reason that explains the match. Nothing here touches the
-- shared state. No I/O and no state or config reads.

local M = {}

local version = require 'cvescannerv2.version'

local compare_version = version.compare_version
local version_or_default = version.version_or_default


-- Strength of each scope reason. A nil reason means a plain match (the
-- strongest). Unknown reasons count as the weakest.
local REASON_STRENGTH = {
  exact_version = 3,
  range_contains = 3,
  range_overlap = 2,
  update_unknown = 2,
  nvd_unbounded = 1,
}

local function reason_strength(reason)
  if reason == nil then return 3 end
  return REASON_STRENGTH[reason] or 1
end


-- Keep one reason per CVE: the strongest one. A tie keeps the existing one,
-- so the final reason does not depend on the order of the rows.
local function add_scoped_vulnerability(row, result, reason)
  local rec = result[row.id]
  if rec == nil then
    result[row.id] = {
      ['CVSSV2'] = row.CVSSV2,
      ['CVSSV3'] = row.CVSSV3,
      ['CVSSV4'] = row.CVSSV4,
      ['ExploitDB'] = row.ExploitDB,
      ['Metasploit'] = row.Metasploit,
      ['reasons'] = reason and { reason } or {}
    }
    return
  end
  local current = rec.reasons[1]
  if reason_strength(reason) > reason_strength(current) then
    rec.reasons = reason and { reason } or {}
  end
end


-- True when the NVD row has at least one version bound.
local function is_bounded(row)
  return row.StartInc ~= nil or row.StartExc ~= nil
      or row.EndInc ~= nil or row.EndExc ~= nil
end


-- True when the NVD row interval contains the whole observed interval.
local function range_contains(row, from, to)
  local cmp
  if row.StartInc ~= nil then
    cmp = compare_version(row.StartInc, from)
    if cmp == nil or cmp > 0 then return false end
  end
  if row.StartExc ~= nil then
    cmp = compare_version(row.StartExc, from)
    if cmp == nil or cmp >= 0 then return false end
  end
  if row.EndInc ~= nil then
    cmp = compare_version(row.EndInc, to)
    if cmp == nil or cmp < 0 then return false end
  end
  if row.EndExc ~= nil then
    cmp = compare_version(row.EndExc, to)
    if cmp == nil or cmp <= 0 then return false end
  end
  return true
end


-- Return the reason of a matched NVD range row.
local function multi_reason(row, from, to)
  if not is_bounded(row) then return 'nvd_unbounded' end
  if range_contains(row, from, to) then return 'range_contains' end
  return 'range_overlap'
end


local function scoped_multi_versions(all_versions, from, to, result, unknown_version)
  for _, row in pairs(all_versions) do
    if unknown_version then
      -- The corresponding SQL query already limits these to unbounded
      -- NVD ranges, so no version comparison is possible or necessary.
      add_scoped_vulnerability(row, result, 'nvd_unbounded')
    else
      local applies = true
      local cmp
      if row.StartInc ~= nil then
        cmp = compare_version(row.StartInc, to)
        applies = cmp ~= nil and cmp <= 0
      end
      if applies and row.StartExc ~= nil then
        cmp = compare_version(row.StartExc, to)
        applies = cmp ~= nil and cmp < 0
      end
      if applies and row.EndInc ~= nil then
        cmp = compare_version(row.EndInc, from)
        applies = cmp ~= nil and cmp >= 0
      end
      if applies and row.EndExc ~= nil then
        cmp = compare_version(row.EndExc, from)
        applies = cmp ~= nil and cmp > 0
      end
      -- Report a range-based CVE only when the NVD interval overlaps the
      -- version interval Nmap reported. Exclusive boundaries stay strict.
      if applies then
        add_scoped_vulnerability(row, result, multi_reason(row, from, to))
      end
    end
  end
end


-- True when an NVD update is a concrete update, not '*', '-' or empty.
local function concrete_update(update)
  return update ~= '*' and update ~= '-' and update ~= ''
end


-- Return the reason of an exact row. A concrete row update with an
-- unknown observed update is only medium confidence.
local function exact_reason(row_update, observed_update)
  if observed_update == '*' and concrete_update(row_update) then
    return 'update_unknown'
  end
  return 'exact_version'
end


local function scoped_versions(all_versions, from, to, observed_update, result)
  for _, row in pairs(all_versions) do
    local pr_v = version_or_default(row.version, '0')
    local row_update = version_or_default(row.version_update, '*')
    local applies = false
    local reason = nil
    if from ~= to then
      -- The observed version is a range, never exact evidence.
      reason = 'range_overlap'
      local affected_version = pr_v
      if row_update ~= '*' and row_update ~= '-' and row_update ~= '' then
        affected_version = affected_version .. row_update
      end
      local lower = compare_version(affected_version, from)
      local upper = compare_version(affected_version, to)
      applies = lower ~= nil and lower >= 0
          and upper ~= nil and upper <= 0
    else
      local observed_full = from
      if observed_update ~= nil and observed_update ~= '*'
          and observed_update ~= '-' then
        observed_full = from .. observed_update
      end
      local base = compare_version(pr_v, from)
      local full = compare_version(pr_v, observed_full)
      local update_matches = row_update == observed_update
          or row_update == '*' or observed_update == '*'
      applies = (base == 0 or full == 0) and update_matches
      reason = exact_reason(row_update, observed_update)
    end
    if applies then add_scoped_vulnerability(row, result, reason) end
  end
end


-- Add CVEs from a series expansion that are not already in vulns.
local function merge_series(found, vulns)
  for id, rec in pairs(found) do
    if vulns[id] == nil then
      rec.series_expanded = true
      rec.reasons = { 'series_expanded' }
      vulns[id] = rec
    end
  end
end


-- Add CVEs found under a renamed product that are not already in vulns.
-- The reasons of the match are kept and alias_product is appended.
local function merge_alias(found, vulns)
  for id, rec in pairs(found) do
    if vulns[id] == nil then
      table.insert(rec.reasons, 'alias_product')
      vulns[id] = rec
    end
  end
end


--- Return true when the NVD row interval contains the observed one.
M.range_contains = range_contains
--- Add the range-based NVD rows that overlap the observed range.
M.scoped_multi_versions = scoped_multi_versions
--- Add the exact-version NVD rows that match the observed version.
M.scoped_versions = scoped_versions
--- Merge series-expanded CVEs into vulns, skipping known IDs.
M.merge_series = merge_series
--- Merge CVEs found under renamed products, skipping known IDs.
M.merge_alias = merge_alias


return M
