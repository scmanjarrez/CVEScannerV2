-- SPDX-License-Identifier: GPL-3.0-or-later
-- Confidence levels of CVE matches.  (Layer L5)
--
-- Pure scoring over the reasons attached to each CVE. A reason maps to a
-- level, a CVE takes the lowest level of its reasons, and rows are ordered
-- by level and then by CVSS scores. No I/O and no access to shared state.

local M = {}

--- Compare two rows by CVSS score, highest first.
local function cvss_comparator(a, b)
  local score_a = tonumber(a[3]) or tonumber(a[2]) or -1
  local score_b = tonumber(b[3]) or tonumber(b[2]) or -1
  if score_a == score_b then return a[1] < b[1] end
  return score_a > score_b
end

-- Confidence level of each reason. Platform mismatches are low.
local REASON_LEVEL = {
  exact_version = 'high',
  range_contains = 'high',
  range_overlap = 'medium',
  series_expanded = 'medium',
  update_unknown = 'medium',
  requires_platform = 'medium',
  requires_component = 'medium',
  nvd_unbounded = 'low',
  observed_range = 'low',
}

local LEVEL_RANK = { low = 1, medium = 2, high = 3 }

local LEVEL_LABEL = { high = 'HIGH', medium = 'MED', low = 'LOW' }

--- Order rows by confidence first, then by CVSSv3 and CVSSv2.
local function confidence_comparator(a, b)
  if a[6] ~= b[6] then return LEVEL_RANK[a[6]] > LEVEL_RANK[b[6]] end
  return cvss_comparator(a, b)
end


-- Return the level of one reason. Unknown reasons count as low.
local function reason_level(reason)
  if reason:find('^platform_mismatch:') then return 'low' end
  return REASON_LEVEL[reason] or 'low'
end


--- Return the lowest level among the reasons. No reasons means high.
local function confidence_of(reasons)
  local level = 'high'
  for _, reason in ipairs(reasons) do
    local current = reason_level(reason)
    if LEVEL_RANK[current] < LEVEL_RANK[level] then level = current end
  end
  return level
end


--- Set rec.confidence on every CVE and count the levels.
local function assign_confidence(vulns)
  local summary = { high = 0, medium = 0, low = 0 }
  for _, rec in pairs(vulns) do
    rec.confidence = confidence_of(rec.reasons)
    summary[rec.confidence] = summary[rec.confidence] + 1
  end
  return summary
end


--- Add one reason to every CVE of a scan, such as observed_range.
local function add_reason(vulns, reason)
  for _, rec in pairs(vulns) do
    table.insert(rec.reasons, reason)
  end
end

M.cvss_comparator = cvss_comparator
M.LEVEL_RANK = LEVEL_RANK
M.LEVEL_LABEL = LEVEL_LABEL
M.confidence_comparator = confidence_comparator
M.confidence_of = confidence_of
M.assign_confidence = assign_confidence
M.add_reason = add_reason

return M
