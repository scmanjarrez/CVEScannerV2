-- SPDX-License-Identifier: GPL-3.0-or-later
-- Temporary SQLite databases with the db-manager schema for the Lua tests.
--
-- create() writes only the rows given in its spec. It never imitates a query,
-- so the scanner's real SQL runs against the data.

local M = {}

-- Table name, number of columns, and DDL. The conditions and aliases tables
-- exist only when the spec has a list for them, which models a database
-- that has them.
local OPTIONAL = { conditions = true, product_aliases = true }

local SCHEMA = {
  {
    name = 'cves',
    width = 5,
    ddl = [[CREATE TABLE cves (cve_id TEXT PRIMARY KEY,
    cvss_v2 TEXT, cvss_v3 TEXT, published INTEGER, cvss_v4 TEXT)]],
    -- Databases built before CVSSv4 have no cvss_v4 column.
    legacy_width = 4,
    legacy_ddl = [[CREATE TABLE cves (cve_id TEXT PRIMARY KEY,
    cvss_v2 TEXT, cvss_v3 TEXT, published INTEGER)]]
  },
  {
    name = 'products',
    width = 5,
    ddl = [[CREATE TABLE products (
    product_id INTEGER PRIMARY KEY, vendor TEXT, product TEXT, version TEXT,
    version_update TEXT, UNIQUE (vendor, product, version, version_update))]]
  },
  {
    name = 'affected',
    width = 2,
    ddl = [[CREATE TABLE affected (
    cve_id TEXT, product_id INTEGER, PRIMARY KEY (cve_id, product_id))]]
  },
  {
    name = 'multiaffected',
    width = 6,
    ddl = [[CREATE TABLE multiaffected (
    cve_id TEXT, product_id INTEGER, versionStartIncluding TEXT,
    versionStartExcluding TEXT, versionEndIncluding TEXT,
    versionEndExcluding TEXT)]]
  },
  {
    name = 'conditions',
    width = 6,
    ddl = [[CREATE TABLE conditions (
    cve_id TEXT, product_id INTEGER, config_idx INTEGER, part TEXT,
    vendor TEXT, product TEXT, PRIMARY KEY (cve_id, product_id, config_idx,
    part, vendor, product))]]
  },
  {
    name = 'product_aliases',
    width = 4,
    ddl = [[CREATE TABLE product_aliases (
    old_vendor TEXT, old_product TEXT, new_vendor TEXT, new_product TEXT,
    PRIMARY KEY (old_vendor, old_product, new_vendor, new_product))]]
  },
  {
    name = 'exploits',
    width = 2,
    ddl = [[CREATE TABLE exploits (
    exploit_id INTEGER PRIMARY KEY, name TEXT)]]
  },
  {
    name = 'metasploits',
    width = 2,
    ddl = [[CREATE TABLE metasploits (
    metasploit_id INTEGER PRIMARY KEY, name TEXT UNIQUE)]]
  },
  {
    name = 'referenced_exploit',
    width = 2,
    ddl = [[CREATE TABLE
    referenced_exploit (cve_id TEXT, exploit_id INTEGER,
    PRIMARY KEY (cve_id, exploit_id))]]
  },
  {
    name = 'referenced_metasploit',
    width = 2,
    ddl = [[CREATE TABLE
    referenced_metasploit (cve_id TEXT, metasploit_id INTEGER,
    PRIMARY KEY (cve_id, metasploit_id))]]
  },
}

--- Return the luasql.sqlite3 module, nil when it is not installed.
function M.load_sqlite()
  package.loaded['luasql.sqlite3'] = nil
  local ok, sqlite = pcall(require, 'luasql.sqlite3')
  if ok and type(sqlite) == 'table' and sqlite.sqlite3 then
    return sqlite
  end
  return nil
end

local function sql_value(value)
  if value == nil then return 'NULL' end
  if type(value) == 'number' then return tostring(value) end
  return "'" .. tostring(value):gsub("'", "''") .. "'"
end

local function insert(conn, tbl, row, width)
  local values = {}
  for i = 1, width do values[i] = sql_value(row[i]) end
  assert(conn:execute(('INSERT INTO %s VALUES (%s)')
    :format(tbl, table.concat(values, ', '))))
end

--- Create a temporary database with the rows of spec and return its path.
-- Each spec key is a table name holding a list of rows in column order.
-- spec.legacy_cves = true builds the cves table without cvss_v4.
-- The caller removes the file.
function M.create(spec, sqlite)
  local path = os.tmpname()
  local env = assert(sqlite.sqlite3())
  local conn = assert(env:connect(path))
  for _, def in ipairs(SCHEMA) do
    if not OPTIONAL[def.name] or spec[def.name] ~= nil then
      local ddl, width = def.ddl, def.width
      if def.legacy_ddl and spec.legacy_cves then
        ddl, width = def.legacy_ddl, def.legacy_width
      end
      assert(conn:execute(ddl))
      for _, row in ipairs(spec[def.name] or {}) do
        insert(conn, def.name, row, width)
      end
    end
  end
  conn:close()
  env:close()
  return path
end

--- Open a connection to the database at path and return env and conn.
function M.open(path, sqlite)
  local env = assert(sqlite.sqlite3())
  local conn = assert(env:connect(path))
  return env, conn
end

return M
