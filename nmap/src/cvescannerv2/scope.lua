-- SPDX-License-Identifier: GPL-3.0-or-later
-- Scope matching of NVD rows against the observed version.

-- Pure decisions: whether an NVD row applies to an observed version or
-- range, and the reason that explains the match. Nothing here touches the
-- shared state.

local M = {}

local version = require 'cvescannerv2.version'

local compare_version = version.compare_version
local default_version = version.default_version


local function add_scoped_vulnerability(v, result, reason)
  if result[v.id] == nil then
    result[v.id] = {
      ['CVSSV2'] = v.CVSSV2,
      ['CVSSV3'] = v.CVSSV3,
      ['ExploitDB'] = v.ExploitDB,
      ['Metasploit'] = v.Metasploit,
      ['reasons'] = reason and { reason } or {}
    }
  end
end


-- True when the NVD row has at least one version bound.
local function is_bounded(v)
  return v.StartInc ~= nil or v.StartExc ~= nil
      or v.EndInc ~= nil or v.EndExc ~= nil
end


-- True when the NVD row interval contains the whole observed interval.
local function range_contains(v, from, to)
  local cmp
  if v.StartInc ~= nil then
    cmp = compare_version(v.StartInc, from)
    if cmp == nil or cmp > 0 then return false end
  end
  if v.StartExc ~= nil then
    cmp = compare_version(v.StartExc, from)
    if cmp == nil or cmp >= 0 then return false end
  end
  if v.EndInc ~= nil then
    cmp = compare_version(v.EndInc, to)
    if cmp == nil or cmp < 0 then return false end
  end
  if v.EndExc ~= nil then
    cmp = compare_version(v.EndExc, to)
    if cmp == nil or cmp <= 0 then return false end
  end
  return true
end


-- Return the reason of a matched NVD range row.
local function multi_reason(v, from, to)
  if not is_bounded(v) then return 'nvd_unbounded' end
  if range_contains(v, from, to) then return 'range_contains' end
  return 'range_overlap'
end


local function scoped_multi_versions(all_versions, from, to, result, unknown_version)
  for _, v in pairs(all_versions) do
    if unknown_version then
      -- The corresponding SQL query already limits these to unbounded
      -- NVD ranges, so no version comparison is possible or necessary.
      add_scoped_vulnerability(v, result, 'nvd_unbounded')
    else
      local applies = true
      local cmp
      if v.StartInc ~= nil then
        cmp = compare_version(v.StartInc, to)
        applies = cmp ~= nil and cmp <= 0
      end
      if applies and v.StartExc ~= nil then
        cmp = compare_version(v.StartExc, to)
        applies = cmp ~= nil and cmp < 0
      end
      if applies and v.EndInc ~= nil then
        cmp = compare_version(v.EndInc, from)
        applies = cmp ~= nil and cmp >= 0
      end
      if applies and v.EndExc ~= nil then
        cmp = compare_version(v.EndExc, from)
        applies = cmp ~= nil and cmp > 0
      end
      -- Report a range-based CVE only when the NVD interval overlaps the
      -- version interval Nmap reported. Exclusive boundaries stay strict.
      if applies then
        add_scoped_vulnerability(v, result, multi_reason(v, from, to))
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
local function exact_reason(pr_vu, upd)
  if upd == '*' and concrete_update(pr_vu) then return 'update_unknown' end
  return 'exact_version'
end


local function scoped_versions(all_versions, from, to, upd, result)
  for _, v in pairs(all_versions) do
    local pr_v = default_version(v.version, '0')
    local pr_vu = default_version(v.version_update, '*')
    local applies = false
    local reason = nil
    if from ~= to then
      local affected_version = pr_v
      if pr_vu ~= '*' and pr_vu ~= '-' and pr_vu ~= '' then
        affected_version = affected_version .. pr_vu
      end
      local lower = compare_version(affected_version, from)
      local upper = compare_version(affected_version, to)
      applies = lower ~= nil and lower >= 0
          and upper ~= nil and upper <= 0
    else
      local observed_full = from
      if upd ~= nil and upd ~= '*' and upd ~= '-' then
        observed_full = from .. upd
      end
      local base = compare_version(pr_v, from)
      local full = compare_version(pr_v, observed_full)
      local update_matches = pr_vu == upd or pr_vu == '*' or upd == '*'
      applies = (base == 0 or full == 0) and update_matches
      reason = exact_reason(pr_vu, upd)
    end
    if applies then add_scoped_vulnerability(v, result, reason) end
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


M.add_scoped_vulnerability = add_scoped_vulnerability
M.is_bounded = is_bounded
M.range_contains = range_contains
M.multi_reason = multi_reason
M.scoped_multi_versions = scoped_multi_versions
M.concrete_update = concrete_update
M.exact_reason = exact_reason
M.scoped_versions = scoped_versions
M.merge_series = merge_series


return M
