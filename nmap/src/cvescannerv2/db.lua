-- SPDX-License-Identifier: GPL-3.0-or-later
-- SQLite access for the cvescannerv2 NSE script.

-- The connection lives in the state module and is read on every call, so
-- tests can replace state.conn with a fake connection.

local util = require 'cvescannerv2.util'
local state = require 'cvescannerv2.state'

local M = {}

local fmt = util.fmt
local fmtn = util.fmtn

-- Recent Nmap versions drop Lua's C-module searcher, so `require` cannot load
-- luasql.sqlite3 from package.cpath. Fall back to locating the .so by hand.
local function load_luasql()
  local ok, mod = pcall(require, 'luasql.sqlite3')
  if ok then
    return mod
  end
  local ver = _VERSION:match('%d+%.%d+') or '5.4'
  local libdirs = {}
  for _, arch in ipairs({'x86_64-linux-gnu', 'aarch64-linux-gnu', 'arm-linux-gnueabihf', ''}) do
    for _, prefix in ipairs({'/usr/local/lib', '/usr/lib', '/usr/lib64', '/usr/local/lib64'}) do
      libdirs[#libdirs + 1] = prefix .. (arch ~= '' and '/' .. arch or '') .. '/lua/' .. ver
    end
  end
  local cpath = package.cpath .. ';' .. (os.getenv('LUA_CPATH') or '')
  for _, dir in ipairs(libdirs) do
    cpath = cpath .. ';' .. dir .. '/?.so'
  end
  local path = package.searchpath('luasql.sqlite3', cpath)
  if not path then
    error("module 'luasql.sqlite3' not found; install lua-sql-sqlite3 (see README)")
  end
  local opener, err = package.loadlib(path, 'luaopen_luasql_sqlite3')
  if not opener then
    error("cannot load " .. path .. ": " .. tostring(err))
  end
  return opener()
end

local sql = load_luasql()

local function query(qtype)
  if qtype == 'cve_score' then
    return [[
             SELECT cvss_v2, cvss_v3
             FROM cves
             WHERE cve_id = '%s'
             ]]
  elseif qtype == 'exploit_info' then
    return [[
             SELECT exploits.exploit_id, exploits.name
             FROM referenced_exploit
             INNER JOIN exploits ON referenced_exploit.exploit_id = exploits.exploit_id
             WHERE referenced_exploit.cve_id = '%s'
             ]]
  elseif qtype == 'metasploit_info' then
    return [[
             SELECT metasploits.name
             FROM referenced_metasploit
             INNER JOIN metasploits ON referenced_metasploit.metasploit_id = metasploits.metasploit_id
             WHERE referenced_metasploit.cve_id = '%s'
             ]]
  elseif qtype == 'multiaffected' then
    return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
             multiaffected.versionStartIncluding, multiaffected.versionStartExcluding,
             multiaffected.versionEndIncluding, multiaffected.versionEndExcluding,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
             FROM multiaffected
             INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
             WHERE product_id IN
             (SELECT product_id FROM products WHERE vendor IN (${v}) AND product = '${p}' AND version = '*')
             ]]
  elseif qtype == 'multiaffected_empty' then
    return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
             multiaffected.versionStartIncluding, multiaffected.versionStartExcluding,
             multiaffected.versionEndIncluding, multiaffected.versionEndExcluding,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
             FROM multiaffected
             INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
             WHERE product_id IN
             (SELECT product_id FROM products WHERE vendor IN (${v}) AND product = '${p}' AND version = '*' and version_update = '*')
             AND versionStartIncluding IS NULL AND versionStartExcluding IS NULL
             AND versionEndIncluding IS NULL AND versionEndExcluding IS NULL
             ]]
  elseif qtype == 'product_vendors' then
    return [[
             SELECT DISTINCT vendor FROM products
             WHERE product = '${p}'
             ]]
  elseif qtype == 'series_children' then
    return [[
             SELECT EXISTS (SELECT 1 FROM products
             WHERE vendor IN (${v}) AND product = '${p}'
             AND version LIKE '${s}.%')
             ]]
  elseif qtype == 'platform_conditions' then
    return [[
             SELECT DISTINCT conditions.cve_id, conditions.config_idx,
             conditions.part, conditions.vendor, conditions.product
             FROM conditions
             INNER JOIN products ON conditions.product_id = products.product_id
             WHERE products.vendor IN (${v}) AND products.product = '${p}'
             ]]
  elseif qtype == 'affected' then
    return [[
             SELECT affected.cve_id, cves.cvss_v2, cves.cvss_v3,
             products.version, products.version_update,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = affected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = affected.cve_id)) as msf
             FROM products
             INNER JOIN affected ON products.product_id = affected.product_id
             INNER JOIN cves ON affected.cve_id = cves.cve_id
             WHERE products.vendor IN (${v}) AND products.product = '${p}'
             ]]
  end
end

-- Distinct vendors that have rows for product in the database.
local function product_vendors(product)
  local cur = state.conn:execute(
    fmtn(query('product_vendors'), { p = product }))
  local names = {}
  local name = cur:fetch()
  while name do
    table.insert(names, name)
    name = cur:fetch()
  end
  cur:close()
  return names
end

-- Vendor names to query: Nmap's vendor plus its NVD aliases. When none of
-- them has this product, every vendor with the product is used instead,
-- which is the same as searching by product alone.
local function vendor_scope(vendor, product)
  local names = { vendor }
  local aliases = state.vendor_aliases[vendor]
  if type(aliases) == 'table' then
    for _, alias in ipairs(aliases) do
      table.insert(names, alias)
    end
  end
  local known = product_vendors(product)
  local present = {}
  for _, name in ipairs(known) do
    present[name] = true
  end
  for _, name in ipairs(names) do
    if present[name] then return names end
  end
  for _, name in ipairs(known) do
    table.insert(names, name)
  end
  return names
end

-- True when the database has rows 'series.%' for the product.
local function series_has_children(vendors, product, series)
  local cur = state.conn:execute(fmtn(query('series_children'),
    { v = vendors, p = product, s = series }))
  local found = cur:fetch()
  cur:close()
  return tonumber(found) == 1
end

-- Return true when the database has the conditions table. Checked once.
-- Nothing is logged here; the caller decides how to report a missing table.
local function has_conditions()
  if state.has_conditions == nil then
    local cur = state.conn:execute(
      "SELECT name FROM sqlite_master "
      .. "WHERE type = 'table' AND name = 'conditions'")
    state.has_conditions = cur:fetch() ~= nil
    cur:close()
  end
  return state.has_conditions
end


-- Return the CVSS v2 and v3 scores of a CVE, nil when unknown.
local function cve_score(vuln)
  local cur = state.conn:execute(fmt(query('cve_score'), vuln))
  local cvssv2, cvssv3 = cur:fetch()
  cur:close()
  return cvssv2, cvssv3
end


-- Return the Exploit-DB entries of a CVE as {id, name} in query order.
local function exploitdb(vuln)
  local cur = state.conn:execute(fmt(query('exploit_info'), vuln))
  local list = {}
  local exploit, name = cur:fetch()
  while exploit do
    list[#list + 1] = { id = exploit, name = name }
    exploit, name = cur:fetch()
  end
  cur:close()
  return list
end


-- Return the Metasploit module names of a CVE in query order.
local function metasploit(vuln)
  local cur = state.conn:execute(fmt(query('metasploit_info'), vuln))
  local names = {}
  local name = cur:fetch()
  while name do
    names[#names + 1] = name
    name = cur:fetch()
  end
  cur:close()
  return names
end


-- Return the CVEs affecting a range of versions of the product.
-- Each row is a table with the id, scores, range bounds and the flags
-- ExploitDB and Metasploit. With empty true, only the rows without range
-- bounds are returned.
local function affected_multi(vendors, product, empty)
  local qtype = empty and 'multiaffected_empty' or 'multiaffected'
  local cur = state.conn:execute(
    fmtn(query(qtype), { v = vendors, p = product }))
  local rows = {}
  local vuln, cvssv2, cvssv3, st_in, st_ex, en_in, en_ex, exploitdb_flag,
    metasploit_flag = cur:fetch()
  while vuln do
    rows[#rows + 1] = {
      id = vuln,
      CVSSV2 = cvssv2,
      CVSSV3 = cvssv3,
      StartInc = st_in,
      StartExc = st_ex,
      EndInc = en_in,
      EndExc = en_ex,
      ExploitDB = exploitdb_flag,
      Metasploit = metasploit_flag,
    }
    vuln, cvssv2, cvssv3, st_in, st_ex, en_in, en_ex, exploitdb_flag,
      metasploit_flag = cur:fetch()
  end
  cur:close()
  return rows
end


-- Return the CVEs affecting an exact version of the product.
-- Each row is a table with the id, scores, the version and update fields
-- and the flags ExploitDB and Metasploit.
local function affected_exact(vendors, product)
  local cur = state.conn:execute(
    fmtn(query('affected'), { v = vendors, p = product }))
  local rows = {}
  local vuln, cvssv2, cvssv3, pr_v, pr_vu, exploitdb_flag,
    metasploit_flag = cur:fetch()
  while vuln do
    rows[#rows + 1] = {
      id = vuln,
      CVSSV2 = cvssv2,
      CVSSV3 = cvssv3,
      version = pr_v,
      version_update = pr_vu,
      ExploitDB = exploitdb_flag,
      Metasploit = metasploit_flag,
    }
    vuln, cvssv2, cvssv3, pr_v, pr_vu, exploitdb_flag,
      metasploit_flag = cur:fetch()
  end
  cur:close()
  return rows
end


-- Return the platform conditions of the product, grouped by CVE id.
-- Each group is a list of tables with config_idx, part, vendor and product.
local function platform_rows(vendors, product)
  local cur = state.conn:execute(fmtn(query('platform_conditions'),
    { v = vendors, p = product }))
  local rows_by_cve = {}
  local cve, config_idx, part, vendor, name = cur:fetch()
  while cve do
    rows_by_cve[cve] = rows_by_cve[cve] or {}
    table.insert(rows_by_cve[cve], {
      config_idx = config_idx,
      part = part,
      vendor = vendor,
      product = name,
    })
    cve, config_idx, part, vendor, name = cur:fetch()
  end
  cur:close()
  return rows_by_cve
end


-- Open the database file at path and keep the connection in the state.
function M.open(path)
  state.env = sql.sqlite3()
  state.conn = state.env:connect(path)
end


-- Close the shared connection and environment.
-- Return closed, err: err holds the message when closing the connection
-- failed. Nothing is logged here.
function M.close()
  local closed, err = pcall(state.conn.close, state.conn)
  state.env:close()
  return closed, err
end


M.query = query
M.vendor_scope = vendor_scope
M.series_has_children = series_has_children
M.has_conditions = has_conditions
M.cve_score = cve_score
M.exploitdb = exploitdb
M.metasploit = metasploit
M.affected_multi = affected_multi
M.affected_exact = affected_exact
M.platform_rows = platform_rows

return M
