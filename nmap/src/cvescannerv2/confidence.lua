-- SPDX-License-Identifier: GPL-3.0-or-later
-- Confidence levels of CVE matches.  (Layer L5)
--
-- Pure scoring over the reasons attached to each CVE. A reason maps to a
-- level, a CVE takes the lowest level of its reasons, and entries are ordered
-- by level and then by the main CVSS score. No I/O and no access to shared state.

local M = {}

--- Return the main score of a cvss table: the first of v4, v3 and v2.
-- Returns nil when the table has no score.
local function primary_score(cvss)
  return cvss.v4 or cvss.v3 or cvss.v2
end

--- Compare two CVE entries by main CVSS score, highest first.
-- Entries are tables with the fields id and cvss. Ties order by id.
local function cvss_comparator(a, b)
  local score_a = primary_score(a.cvss) or -1
  local score_b = primary_score(b.cvss) or -1
  if score_a == score_b then return a.id < b.id end
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

--- Order CVE entries by confidence first, then by main CVSS score.
-- Entries are tables with the fields id, cvss and confidence.
local function confidence_comparator(a, b)
  if a.confidence ~= b.confidence then
    return LEVEL_RANK[a.confidence] > LEVEL_RANK[b.confidence]
  end
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

M.primary_score = primary_score
M.cvss_comparator = cvss_comparator
M.LEVEL_RANK = LEVEL_RANK
M.LEVEL_LABEL = LEVEL_LABEL
M.confidence_comparator = confidence_comparator
M.confidence_of = confidence_of
M.assign_confidence = assign_confidence
M.add_reason = add_reason

return M
