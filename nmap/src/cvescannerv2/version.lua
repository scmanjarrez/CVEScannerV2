-- SPDX-License-Identifier: GPL-3.0-or-later
-- Version parsing and comparison for the cvescannerv2 NSE script.

local M = {}


local util = require 'cvescannerv2.util'
local split_cpe = require('cvescannerv2.cpe').split_cpe
local empty = util.empty


local function correct_version(info)
  if not info.range then
    return info.ver, info.vup
  else
    return info.from .. " - " .. info.to, "*"
  end
end


local function is_series_version(version)
  return version:match('^%d+%.%d+$') ~= nil
    or version:match('%.[xX]$') ~= nil
    or version:match('%.%*$') ~= nil
end

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


local function version_parser(product, version, cpe_update)
  if version then
    -- remove Nmap comment of version
    version = version:gsub('for_windows_', '')
    -- remove a leading 'v' before the number (v1.2.3 -> 1.2.3)
    version = version:gsub('^[vV](%d)', '%1')
  end

  -- if Nmap could not detect version, assume all versions and vupdates possible
  if version == '-' then
    return product, {
      ver = '-',
      vup = '-',
      from = nil,
      to = nil,
      empty = false,
      range = false
    }
  end
  if empty(version) or version == '*' then
    return product, {
      ver = '*',
      vup = '*',
      from = nil,
      to = nil,
      empty = true,
      range = false
    }
  end

  -- if version matches patterns: 3.x - 4.x | 3.3.x - 3.4.x ...
  local p1, p2 = version:match('^(.-)%s+%-%s+(.+)$')
  if not empty(p1) and not empty(p2) then
    local f1, f2 = p1:match('([^%a]*)(.*)')
    local t1, t2 = p2:match('([^%a]*)(.*)')
    return product, {
      ver = nil,
      vup = nil,
      from = f1 .. f2,
      to = t1 .. t2,
      empty = false,
      range = true
    }
  end

  -- Treat a trailing x as an unknown patch component (for example, 2.4.x).
  local wildcard_prefix = version:match('^([%d%.]+)[xX]$')
  if wildcard_prefix then
    return product, {
      ver = nil,
      vup = nil,
      from = wildcard_prefix .. '0',
      to = wildcard_prefix .. '9999999999',
      empty = false,
      range = true
    }
  end

  -- If version matches patterns: 4.3 | 4.3p1 | 4.3.1sp1 ...
  p1, p2 = version:match('^([%d%.]+)(.*)$')
  if p1 then
    p2 = strip_build_suffix(p2)
    if p2:sub(1, 1) == '-' then
      p1 = p1 .. p2
      p2 = ''
    end
    if cpe_update and cpe_update ~= '' and cpe_update ~= '*'
        and cpe_update ~= '-' then
      p2 = cpe_update
    elseif empty(p2) then
      p2 = cpe_update == '-' and '-' or '*'
    end
    return product, {
      ver = p1,
      vup = p2,
      from = nil,
      to = nil,
      empty = false,
      range = false
    }
  end

  return product, {
    ver = '*',
    vup = '*',
    from = nil,
    to = nil,
    empty = true,
    range = false
  }
end


local function prefer_version(cpe_version, nmap_version)
  if empty(nmap_version) or nmap_version == '*' then
    return cpe_version, 'nmap_cpe'
  end
  if empty(cpe_version) or cpe_version == '*' then
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


local function cpe_parser(cpe, version)
  local _, _, _, vendor, product, cpe_version, cpe_update = split_cpe(cpe)
  if not product then return nil, nil, nil end

  local source
  cpe_version, source = prefer_version(cpe_version, version)
  if source == 'nmap_version' then
    cpe_update = nil
  end

  local parsed_product, info = version_parser(product, cpe_version, cpe_update)
  return vendor, parsed_product, info, source
end


local function split_version(str)
  local parts = {}
  for part in string.gmatch(str, "([^.]+)") do
    table.insert(parts, part)
  end
  return parts
end


local function compare_version(version1, version2)
  if version1 == nil or version2 == nil then return nil end
  if version1 == version2 and (version1 == '-' or version1 == '*') then
    return 0
  end
  local numeric1 = tostring(version1):match('^[%d%.]+')
  local numeric2 = tostring(version2):match('^[%d%.]+')
  if not numeric1 or not numeric1:find('%d')
      or not numeric2 or not numeric2:find('%d') then
    return nil
  end
  local parts1 = split_version(numeric1)
  local parts2 = split_version(numeric2)
  local max_len = math.max(#parts1, #parts2)
  for i = 1, max_len do
    local num1 = tonumber(parts1[i]) or 0
    local num2 = tonumber(parts2[i]) or 0
    if num1 < num2 then
      return -1
    elseif num1 > num2 then
      return 1
    end
  end

  local suffix1 = strip_build_suffix(
    tostring(version1):sub(#numeric1 + 1):lower())
  local suffix2 = strip_build_suffix(
    tostring(version2):sub(#numeric2 + 1):lower())
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


local function default_version(version, default)
  if version == nil or version == '' then
    return default
  else
    return version
  end
end


-- Return 'x.y' when Nmap reported a two-part series without update, such
-- as 5.5. Any other version shape yields nil.
local function series_prefix(info)
  if info.empty or info.range then return nil end
  local ver = info.ver
  if type(ver) ~= 'string' or not ver:match('^%d+%.%d+$') then
    return nil
  end
  if not empty(info.vup) and info.vup ~= '*' then return nil end
  return ver
end


-- True when a range spans different major.minor series (3.X - 4.X).
local function spans_series(from, to)
  local major_from, minor_from = (from or ''):match('^(%d+)%.?(%d*)')
  local major_to, minor_to = (to or ''):match('^(%d+)%.?(%d*)')
  return major_from ~= major_to or minor_from ~= minor_to
end


--- Return whether the Nmap version is precise, so no probe is needed.
-- Empty and '*' versions are never precise.
local function nmap_version_precise(version)
  if empty(version) or version == '*' then return false end
  -- A bare major number such as '4' or 'NTP v4' is a series, not a version.
  if version:match('^[%a ]*[vV]?%d+$') then return false end
  return is_precise_version(version)
end


M.correct_version = correct_version
M.is_series_version = is_series_version
M.is_precise_version = is_precise_version
M.PRERELEASE_WORDS = PRERELEASE_WORDS
M.strip_build_suffix = strip_build_suffix
M.version_parser = version_parser
M.prefer_version = prefer_version
M.cpe_parser = cpe_parser
M.split_version = split_version
M.compare_version = compare_version
M.default_version = default_version
M.series_prefix = series_prefix
M.spans_series = spans_series
M.nmap_version_precise = nmap_version_precise


return M
