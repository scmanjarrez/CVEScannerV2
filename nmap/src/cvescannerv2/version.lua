-- SPDX-License-Identifier: GPL-3.0-or-later
-- Version parsing and comparison for the cvescannerv2 script.  (Layer L1)
--
-- Parses Nmap and CPE versions into info records and compares them.
-- Pure computation: no network, file, database, state or config access.

local M = {}


local util = require 'cvescannerv2.util'
local split_cpe = require('cvescannerv2.cpe').split_cpe
local is_blank = util.is_blank


--- Return the version and update, or the range text for a range.
local function display_version(info)
  if not info.is_range then
    return info.version, info.update
  else
    return info.from .. " - " .. info.to, "*"
  end
end


--- Return whether the version is a series such as 2.4 or 2.x.
local function is_series_version(version)
  return version:match('^%d+%.%d+$') ~= nil
      or version:match('%.[xX]$') ~= nil
      or version:match('%.%*$') ~= nil
end

--- Return whether the version is a single exact release.
local function is_precise_version(version)
  return not is_series_version(version)
      and version:find('%s+%-%s+') == nil
end


-- Words that make a dash suffix a pre-release instead of a build tag.
local PRERELEASE_WORDS = {
  alpha = true, beta = true, rc = true, pre = true, preview = true, dev = true,
}

-- Drop a build or distro tag (-log, -3ubuntu5) from a version suffix.
-- The suffix is kept when its dash introduces a known pre-release (-rc1).
local function strip_build_suffix(suffix)
  local head, tail = suffix:match('^([^%-]*)(%-.*)$')
  if not head then return suffix end
  local word = tail:match('^%-(%a+)')
  if word and PRERELEASE_WORDS[word:lower()] then return suffix end
  return head
end


-- Remove Nmap comments and a leading 'v' before the version number.
local function clean_version(version)
  if not version then return nil end
  local cleaned = version:gsub('for_windows_', '')
  -- remove a leading 'v' before the number (v1.2.3 -> 1.2.3)
  cleaned = cleaned:gsub('^[vV](%d)', '%1')
  return cleaned
end


-- Info record for a version Nmap could not detect ('-').
local function unknown_info()
  return {
    version = '-',
    update = '-',
    from = nil,
    to = nil,
    matches_any = false,
    is_range = false
  }
end


-- Info record for a missing version, or '*', that matches any version.
local function any_info()
  return {
    version = '*',
    update = '*',
    from = nil,
    to = nil,
    matches_any = true,
    is_range = false
  }
end


-- Info record for a range such as 3.x - 4.x or 3.3.x - 3.4.x, or nil.
local function range_info(version)
  local p1, p2 = version:match('^(.-)%s+%-%s+(.+)$')
  if is_blank(p1) or is_blank(p2) then return nil end
  local f1, f2 = p1:match('([^%a]*)(.*)')
  local t1, t2 = p2:match('([^%a]*)(.*)')
  return {
    version = nil,
    update = nil,
    from = f1 .. f2,
    to = t1 .. t2,
    matches_any = false,
    is_range = true
  }
end


-- Info record for a trailing x patch component (2.4.x), or nil.
local function wildcard_range(version)
  local wildcard_prefix = version:match('^([%d%.]+)[xX]$')
  if not wildcard_prefix then return nil end
  return {
    version = nil,
    update = nil,
    from = wildcard_prefix .. '0',
    to = wildcard_prefix .. '9999999999',
    matches_any = false,
    is_range = true
  }
end


-- Info record for a numeric version such as 4.3, 4.3p1 or 4.3.1sp1, or nil.
local function numeric_info(version, cpe_update)
  local p1, p2 = version:match('^([%d%.]+)(.*)$')
  if not p1 then return nil end
  p2 = strip_build_suffix(p2)
  if p2:sub(1, 1) == '-' then
    p1 = p1 .. p2
    p2 = ''
  end
  if cpe_update and cpe_update ~= '' and cpe_update ~= '*'
      and cpe_update ~= '-' then
    p2 = cpe_update
  elseif is_blank(p2) then
    p2 = cpe_update == '-' and '-' or '*'
  end
  return {
    version = p1,
    update = p2,
    from = nil,
    to = nil,
    matches_any = false,
    is_range = false
  }
end


--- Return the product and the parsed info record for a version.
local function parse_nmap_version(product, version, cpe_update)
  version = clean_version(version)
  if version == '-' then
    return product, unknown_info()
  end
  if is_blank(version) or version == '*' then
    return product, any_info()
  end
  local info = range_info(version)
      or wildcard_range(version)
      or numeric_info(version, cpe_update)
  return product, info or any_info()
end


local function prefer_version(cpe_version, nmap_version)
  if is_blank(nmap_version) or nmap_version == '*' then
    return cpe_version, 'nmap_cpe'
  end
  if is_blank(cpe_version) or cpe_version == '*' then
    return nmap_version, 'nmap_version'
  end
  if nmap_version:match('^(.-)%s+%-%s+(.+)$') then
    return nmap_version, 'nmap_version'
  end
  if nmap_version:sub(1, #cpe_version + 1) == cpe_version .. '.' then
    return nmap_version, 'nmap_version'
  end
  return cpe_version, 'nmap_cpe'
end


--- Return vendor, product, info and source for a CPE and a version.
local function parse_cpe_version(cpe, version)
  local _, _, _, vendor, product, cpe_version, cpe_update = split_cpe(cpe)
  if not product then return nil, nil, nil end

  local source
  cpe_version, source = prefer_version(cpe_version, version)
  if source == 'nmap_version' then
    cpe_update = nil
  end

  local parsed_product, info = parse_nmap_version(product, cpe_version, cpe_update)
  return vendor, parsed_product, info, source
end


local function split_version(str)
  local parts = {}
  for part in string.gmatch(str, "([^.]+)") do
    table.insert(parts, part)
  end
  return parts
end


-- Memoized parses of version strings, reset when they grow too large.
local PARSED = {}
local parsed_count = 0


--- Return the parse of a version, cached by its string form.
-- The parse has the numeric prefix or false, the numeric parts and the
-- lower-case suffix without build tags.
local function parse_version(value)
  local text = tostring(value)
  local cached = PARSED[text]
  if cached then return cached end
  local numeric = text:match('^[%d%.]+')
  if not numeric or not numeric:find('%d') then numeric = false end
  local parsed = { numeric = numeric, nums = {}, suffix = '' }
  if numeric then
    for i, part in ipairs(split_version(numeric)) do
      parsed.nums[i] = tonumber(part) or 0
    end
    parsed.suffix = strip_build_suffix(text:sub(#numeric + 1):lower())
  end
  if parsed_count > 20000 then
    PARSED = {}
    parsed_count = 0
  end
  PARSED[text] = parsed
  parsed_count = parsed_count + 1
  return parsed
end


--- Return -1, 0 or 1 comparing two versions, or nil when not comparable.
local function compare_version(version1, version2)
  if version1 == nil or version2 == nil then return nil end
  if version1 == version2 and (version1 == '-' or version1 == '*') then
    return 0
  end
  local parsed1 = parse_version(version1)
  local parsed2 = parse_version(version2)
  if not parsed1.numeric or not parsed2.numeric then
    return nil
  end
  local nums1 = parsed1.nums
  local nums2 = parsed2.nums
  local max_len = math.max(#nums1, #nums2)
  for i = 1, max_len do
    local num1 = nums1[i] or 0
    local num2 = nums2[i] or 0
    if num1 < num2 then
      return -1
    elseif num1 > num2 then
      return 1
    end
  end

  local suffix1 = parsed1.suffix
  local suffix2 = parsed2.suffix
  if suffix1 == suffix2 then return 0 end

  local function prerelease(suffix)
    suffix = suffix:gsub('^[%._%-]+', '')
    return suffix:match('^a%d[%d%.%-]*$') ~= nil
        or suffix:match('^alpha[%d%.%-]*$') ~= nil
        or suffix:match('^b%d[%d%.%-]*$') ~= nil
        or suffix:match('^beta[%d%.%-]*$') ~= nil
        or suffix:match('^pre[%d%.%-]*$') ~= nil
        or suffix:match('^preview[%d%.%-]*$') ~= nil
        or suffix:match('^rc[%d%.%-]*$') ~= nil
        or suffix:match('^dev[%d%.%-]*$') ~= nil
  end
  if suffix1 == '' then return prerelease(suffix2) and 1 or -1 end
  if suffix2 == '' then return prerelease(suffix1) and -1 or 1 end
  local normalized1 = suffix1:gsub('^[%._%-]+', '')
  local normalized2 = suffix2:gsub('^[%._%-]+', '')
  local name1, number1 = normalized1:match('^([%a]+)(%d+)$')
  local name2, number2 = normalized2:match('^([%a]+)(%d+)$')
  if name1 ~= nil and name1 == name2 and number1 and number2 then
    number1 = number1:gsub('^0+', '')
    number2 = number2:gsub('^0+', '')
    if #number1 < #number2 then return -1 end
    if #number1 > #number2 then return 1 end
    if number1 < number2 then return -1 end
    if number1 > number2 then return 1 end
    return 0
  end
  if suffix1 < suffix2 then return -1 end
  return 1
end


--- Return the version, or the default when it is nil or empty.
local function version_or_default(version, default)
  if version == nil or version == '' then
    return default
  else
    return version
  end
end


-- Return 'x.y' when Nmap reported a two-part series without update, such
-- as 5.5. Any other version shape yields nil.
local function series_prefix(info)
  if info.matches_any or info.is_range then return nil end
  local ver = info.version
  if type(ver) ~= 'string' or not ver:match('^%d+%.%d+$') then
    return nil
  end
  if not is_blank(info.update) and info.update ~= '*' then return nil end
  return ver
end


--- True when a range spans different major.minor series (3.X - 4.X).
local function spans_series(from, to)
  local major_from, minor_from = (from or ''):match('^(%d+)%.?(%d*)')
  local major_to, minor_to = (to or ''):match('^(%d+)%.?(%d*)')
  return major_from ~= major_to or minor_from ~= minor_to
end


--- Return whether the Nmap version is precise, so no probe is needed.
-- Empty and '*' versions are never precise.
local function is_precise_nmap_version(version)
  if is_blank(version) or version == '*' then return false end
  -- A bare major number such as '4' or 'NTP v4' is a series, not a version.
  if version:match('^[%a ]*[vV]?%d+$') then return false end
  return is_precise_version(version)
end


M.display_version = display_version
M.is_series_version = is_series_version
M.is_precise_version = is_precise_version
M.parse_nmap_version = parse_nmap_version
M.parse_cpe_version = parse_cpe_version
M.compare_version = compare_version
M.version_or_default = version_or_default
M.series_prefix = series_prefix
M.spans_series = spans_series
M.is_precise_nmap_version = is_precise_nmap_version


return M
