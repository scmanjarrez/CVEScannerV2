-- SPDX-License-Identifier: GPL-3.0-or-later
-- SQLite access for the cvescannerv2 NSE script.  (Layer L2)
--
-- Opens and closes the luasql connection and runs the catalogue queries.
-- Its only I/O is the SQLite file. It reads state.vendor_aliases and
-- writes state.db_env, state.db_conn, state.has_conditions and
-- state.has_cvss_v4.
-- The connection lives in the state module and is read on every call, so
-- tests can replace state.db_conn with a fake connection.

local util = require 'cvescannerv2.util'
local state = require 'cvescannerv2.state'

local M = {}

local fmt = util.fmt
local format_sql_named = util.format_sql_named

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

--- Return the SQL template for name, nil when name is unknown.
local function sql_template(name)
  if name == 'exploit_refs' then
    return [[
             SELECT exploits.exploit_id, exploits.name
             FROM referenced_exploit
             INNER JOIN exploits ON referenced_exploit.exploit_id = exploits.exploit_id
             WHERE referenced_exploit.cve_id = '%s'
             ]]
  elseif name == 'metasploit_refs' then
    return [[
             SELECT metasploits.name
             FROM referenced_metasploit
             INNER JOIN metasploits ON referenced_metasploit.metasploit_id = metasploits.metasploit_id
             WHERE referenced_metasploit.cve_id = '%s'
             ]]
  elseif name == 'range_affected' then
    return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3, ${c4},
             multiaffected.versionStartIncluding, multiaffected.versionStartExcluding,
             multiaffected.versionEndIncluding, multiaffected.versionEndExcluding,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
             FROM multiaffected
             INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
             WHERE product_id IN
             (SELECT product_id FROM products WHERE vendor IN (${v}) AND product = '${p}' AND version = '*')
             ]]
  elseif name == 'range_affected_unbounded' then
    return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3, ${c4},
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
  elseif name == 'product_vendors' then
    return [[
             SELECT DISTINCT vendor FROM products
             WHERE product = '${p}'
             ]]
  elseif name == 'series_children' then
    return [[
             SELECT EXISTS (SELECT 1 FROM products
             WHERE vendor IN (${v}) AND product = '${p}'
             AND version LIKE '${s}.%')
             ]]
  elseif name == 'platform_conditions' then
    return [[
             SELECT DISTINCT conditions.cve_id, conditions.config_idx,
             conditions.part, conditions.vendor, conditions.product
             FROM conditions
             INNER JOIN products ON conditions.product_id = products.product_id
             WHERE products.vendor IN (${v}) AND products.product = '${p}'
             ]]
  elseif name == 'exact_affected' then
    return [[
             SELECT affected.cve_id, cves.cvss_v2, cves.cvss_v3, ${c4},
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
  local cur = state.db_conn:execute(
    format_sql_named(sql_template('product_vendors'), { p = product }))
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

--- True when the database has rows 'series.%' for the product.
local function series_has_children(vendors, product, series)
  local cur = state.db_conn:execute(format_sql_named(sql_template('series_children'),
    { v = vendors, p = product, s = series }))
  local found = cur:fetch()
  cur:close()
  return tonumber(found) == 1
end

-- Return true when the database has the conditions table. Checked once.
-- Nothing is logged here; the caller decides how to report a missing table.
local function has_conditions()
  if state.has_conditions == nil then
    local cur = state.db_conn:execute(
      "SELECT name FROM sqlite_master "
      .. "WHERE type = 'table' AND name = 'conditions'")
    state.has_conditions = cur:fetch() ~= nil
    cur:close()
  end
  return state.has_conditions
end


-- Return true when the cves table has the cvss_v4 column. Checked once.
-- Databases built before CVSSv4 support lack it. Nothing is logged here.
local function has_cvss_v4()
  if state.has_cvss_v4 == nil then
    local cur = state.db_conn:execute(
      "SELECT name FROM pragma_table_info('cves') "
      .. "WHERE name = 'cvss_v4'")
    state.has_cvss_v4 = cur:fetch() ~= nil
    cur:close()
  end
  return state.has_cvss_v4
end


-- SQL expression that selects the CVSSv4 score, NULL on older databases.
local function cvss_v4_column()
  return has_cvss_v4() and 'cves.cvss_v4' or 'NULL'
end


--- Return the Exploit-DB entries of a CVE as {id, name} in query order.
local function exploitdb_refs(vuln)
  local cur = state.db_conn:execute(fmt(sql_template('exploit_refs'), vuln))
  local list = {}
  local exploit, name = cur:fetch()
  while exploit do
    list[#list + 1] = { id = exploit, name = name }
    exploit, name = cur:fetch()
  end
  cur:close()
  return list
end


--- Return the Metasploit module names of a CVE in query order.
local function metasploit_refs(vuln)
  local cur = state.db_conn:execute(fmt(sql_template('metasploit_refs'), vuln))
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
-- ExploitDB and Metasploit. With matches_any true, only the rows without
-- range bounds are returned.
local function range_affected_rows(vendors, product, matches_any)
  local name = matches_any and 'range_affected_unbounded' or 'range_affected'
  local cur = state.db_conn:execute(
    format_sql_named(sql_template(name),
      { v = vendors, p = product, c4 = cvss_v4_column() }))
  local rows = {}
  local vuln, cvssv2, cvssv3, cvssv4, st_in, st_ex, en_in, en_ex, exploitdb_flag,
    metasploit_flag = cur:fetch()
  while vuln do
    rows[#rows + 1] = {
      id = vuln,
      CVSSV2 = cvssv2,
      CVSSV3 = cvssv3,
      CVSSV4 = cvssv4,
      StartInc = st_in,
      StartExc = st_ex,
      EndInc = en_in,
      EndExc = en_ex,
      ExploitDB = exploitdb_flag,
      Metasploit = metasploit_flag,
    }
    vuln, cvssv2, cvssv3, cvssv4, st_in, st_ex, en_in, en_ex,
      exploitdb_flag, metasploit_flag = cur:fetch()
  end
  cur:close()
  return rows
end


-- Return the CVEs affecting an exact version of the product.
-- Each row is a table with the id, scores, the version and update fields
-- and the flags ExploitDB and Metasploit.
local function exact_affected_rows(vendors, product)
  local cur = state.db_conn:execute(
    format_sql_named(sql_template('exact_affected'),
      { v = vendors, p = product, c4 = cvss_v4_column() }))
  local rows = {}
  local vuln, cvssv2, cvssv3, cvssv4, pr_v, row_update, exploitdb_flag,
    metasploit_flag = cur:fetch()
  while vuln do
    rows[#rows + 1] = {
      id = vuln,
      CVSSV2 = cvssv2,
      CVSSV3 = cvssv3,
      CVSSV4 = cvssv4,
      version = pr_v,
      version_update = row_update,
      ExploitDB = exploitdb_flag,
      Metasploit = metasploit_flag,
    }
    vuln, cvssv2, cvssv3, cvssv4, pr_v, row_update, exploitdb_flag,
      metasploit_flag = cur:fetch()
  end
  cur:close()
  return rows
end


-- Return the platform conditions of the product, grouped by CVE id.
-- Each group is a list of tables with config_idx, part, vendor and product.
local function platform_condition_rows(vendors, product)
  local cur = state.db_conn:execute(format_sql_named(sql_template('platform_conditions'),
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


--- Open the database file at path and keep the connection in the state.
function M.open(path)
  state.db_env = sql.sqlite3()
  state.db_conn = state.db_env:connect(path)
end


-- Close the shared connection and environment.
-- Return closed, err: err holds the message when closing the connection
-- failed. Nothing is logged here.
function M.close()
  local closed, err = pcall(state.db_conn.close, state.db_conn)
  state.db_env:close()
  return closed, err
end


M.sql_template = sql_template
M.vendor_scope = vendor_scope
M.series_has_children = series_has_children
M.has_conditions = has_conditions
M.has_cvss_v4 = has_cvss_v4
M.exploitdb_refs = exploitdb_refs
M.metasploit_refs = metasploit_refs
M.range_affected_rows = range_affected_rows
M.exact_affected_rows = exact_affected_rows
M.platform_condition_rows = platform_condition_rows

return M
