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
  ['13.00'] = { year = '2016', sps = { 4001, 5026, 6300 } },
  ['14.00'] = { year = '2017' },
  ['15.00'] = { year = '2019' },
  ['16.00'] = { year = '2022' },
  ['17.00'] = { year = '2025' },
}


--- Return the 'major.minor' key, major and integer build, or nil.
-- Accepts an optional 4th component and an optional '; SP1' style suffix.
-- Only the first three components are used.
local function parse_version(version)
  if type(version) ~= 'string' then return nil end
  local major, minor, build, rest =
    version:match('^%s*(%d+)%.(%d+)%.(%d+)(.*)$')
  if not major then return nil end
  local tail = rest:match('^%.%d+(.*)$')
  if tail then rest = tail end
  if rest ~= '' and not rest:match('^[;%s]') then return nil end
  local key = string.format('%d.%02d', tonumber(major), tonumber(minor))
  local number = math.tointeger(tonumber(build))
  if not number then return nil end
  return key, tonumber(major), number
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
local function build_cpe(release, major, build)
  return string.format('cpe:/a:microsoft:sql_server_%s:%d.0.%d',
    release.year, major, build)
end


--- Return the list of CPEs for a SQL Server CPE and version.
-- Falls back to { cpe } when the CPE or the version is not refinable.
function M.refine(cpe, version)
  local _, _, _, vendor, product, _, update = split_cpe(cpe)
  if vendor ~= 'microsoft' or product ~= 'sql_server' then
    return { cpe }
  end
  if update and update ~= '' and update ~= '*' then
    return { cpe }
  end

  local key, major, build = parse_version(version)
  local release = key and RELEASES[key]
  if not release then
    return { cpe }
  end

  -- 2017 and later: only the exact build CPE.
  if not release.sps then
    return { build_cpe(release, major, build) }
  end

  local sp = service_pack(release.sps, build)
  -- 2016 also keeps the build CPE, after the service pack (or original).
  if release.year == '2016' then
    local first = sp and sp_cpe(release, sp) or cpe
    return { first, build_cpe(release, major, build) }
  end

  if not sp then
    return { cpe }
  end
  return { sp_cpe(release, sp) }
end


return M
