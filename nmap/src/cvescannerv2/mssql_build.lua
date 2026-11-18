-- SPDX-License-Identifier: GPL-3.0-or-later
-- Refines Microsoft SQL Server CPEs from the build number.  (Layer L1)
--
-- Maps a build such as 12.00.6329 to its service pack, or to its year
-- for releases without a service pack table, and returns the CPE list.
-- Pure computation: no network, file, database, state or config access.

local M = {}


local split_cpe = require('cvescannerv2.cpe').split_cpe


-- Releases keyed by 'major.minor' with two decimals, as in 12.00.
-- sps lists the base build of each service pack in increasing order.
-- Releases without sps (2017 and later) have no service pack table.
local RELEASES = {
  ['8.00'] = { year = '2000', sps = { 384, 532, 760, 2039 } },
  ['9.00'] = { year = '2005', sps = { 2047, 3042, 4035, 5000 } },
  ['10.00'] = { year = '2008', sps = { 2531, 4000, 5500, 6000 } },
  ['10.50'] = { year = '2008', r2 = true, sps = { 2500, 4000, 6000 } },
  ['11.00'] = { year = '2012', sps = { 3000, 5058, 6020, 7001 } },
  ['12.00'] = { year = '2014', sps = { 4100, 5000, 6024 } },
  ['13.00'] = { year = '2016', build = true, sps = { 4001, 5026, 6300 } },
  ['14.00'] = { year = '2017', build = true },
  ['15.00'] = { year = '2019', build = true },
  ['16.00'] = { year = '2022', build = true },
  ['17.00'] = { year = '2025', build = true },
}


--- Return the 'major.minor' key, major, integer build and revision, or nil.
-- The revision is the optional 4th component, or nil when absent.
-- Accepts an optional '; SP1' style suffix after the version.
-- Every component must fit in a Lua integer, else the version is nil.
local function parse_version(version)
  if type(version) ~= 'string' then return nil end
  local major, minor, build, rest =
    version:match('^%s*(%d+)%.(%d+)%.(%d+)(.*)$')
  if not major then return nil end
  local rev = nil
  local rev_digits, tail = rest:match('^%.(%d+)(.*)$')
  if rev_digits then
    rev = math.tointeger(tonumber(rev_digits))
    if not rev then return nil end
    rest = tail
  end
  if rest ~= '' and not rest:match('^[;%s]') then return nil end
  major = math.tointeger(tonumber(major))
  minor = math.tointeger(tonumber(minor))
  build = math.tointeger(tonumber(build))
  if not (major and minor and build) then return nil end
  local key = string.format('%d.%02d', major, minor)
  return key, major, build, rev
end


--- Return the highest service pack whose base build is reached, or nil.
local function service_pack(sps, build)
  local sp = nil
  for i, base in ipairs(sps) do
    if build >= base then sp = i end
  end
  return sp
end


--- Return the CPE naming a service pack of a release.
local function sp_cpe(release, sp)
  local tag = release.r2 and 'r2_sp' or 'sp'
  return string.format('cpe:/a:microsoft:sql_server:%s:%s%d',
    release.year, tag, sp)
end


--- Return the CPE naming the exact build, as sql_server_<year>.
-- The revision is appended only when it is known (4 component version).
local function build_cpe(release, major, build, rev)
  local name = string.format('cpe:/a:microsoft:sql_server_%s:%d.0.%d',
    release.year, major, build)
  if rev == nil then return name end
  return string.format('%s.%d', name, rev)
end


--- Return true when the CPE carries no product version (year).
local function unversioned(cpe_version)
  return cpe_version == nil or cpe_version == ''
    or cpe_version == '*' or cpe_version == '-'
end


--- Return true when the CPE update names an actual update.
local function significant(update)
  return update ~= nil and update ~= '' and update ~= '*' and update ~= '-'
end


--- Return true when the CPE year and update agree with the release.
-- A CPE without year is not a conflict: refine completes it with the
-- release year. A year other than the release year is not trusted.
-- Within the same year, an 'r2' update needs an R2 release, and an
-- 'spN' update on an R2 release is 2008 (not R2), so it is not trusted.
local function cpe_trusted(release, cpe_version, update)
  if unversioned(cpe_version) then return true end
  if cpe_version ~= release.year then return false end
  if update and update:match('^r2') and not release.r2 then return false end
  if release.r2 and update and update:match('^sp%d') then return false end
  return true
end


--- Return the list of CPEs for a SQL Server CPE and version.
-- A CPE without product version (nil, '', '*' or '-') is completed with
-- the release year, keeping its update when that update is coherent with
-- the release (R2 rules, see cpe_trusted).
-- A CPE with a year has its year and update trusted only when they agree
-- with the build (see cpe_trusted). An untrusted CPE is treated as having
-- neither update nor year: its generic CPE is the bare year, or the
-- service pack CPE when the build reaches one.
-- Element 1 is the generic CPE: 'cpe:/a:microsoft:sql_server:<year>' with
-- the update when completed; the original one when its year and update are
-- trusted; the service pack CPE when the build reaches one and there is no
-- update; otherwise the bare year when untrusted.
-- Element 2, when the release has build = true, is the sql_server_<year>
-- build CPE. Falls back to { cpe } when the CPE or the version is not
-- refinable. Never raises an error for any version string.
function M.refine(cpe, version)
  local _, _, _, vendor, product, cpe_version, update =
    split_cpe(cpe)
  if vendor ~= 'microsoft' or product ~= 'sql_server' then
    return { cpe }
  end

  local key, major, build, rev = parse_version(version)
  local release = key and RELEASES[key]
  if not release then
    return { cpe }
  end

  local generic
  local has_update
  if unversioned(cpe_version) then
    generic = 'cpe:/a:microsoft:sql_server:' .. release.year
    has_update = significant(update)
      and cpe_trusted(release, release.year, update)
    if has_update then generic = generic .. ':' .. update end
  elseif cpe_trusted(release, cpe_version, update) then
    generic = cpe
    has_update = update and update ~= '' and update ~= '*'
  else
    generic = 'cpe:/a:microsoft:sql_server:' .. release.year
    has_update = false
  end
  if release.sps and not has_update then
    local sp = service_pack(release.sps, build)
    if sp then generic = sp_cpe(release, sp) end
  end

  local result = { generic }
  if release.build then
    result[2] = build_cpe(release, major, build, rev)
  end
  return result
end


return M
