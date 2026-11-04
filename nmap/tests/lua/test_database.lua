-- SPDX-License-Identifier: GPL-3.0-or-later
-- End-to-end portaction() runs against a temporary SQLite fixture database.
--
-- The fixture uses the db-manager schema. Real CVE identifiers are used when
-- the case reproduces a real detection; CVE-2999-* identifiers are synthetic.

local t = require 'harness'

t.suite('portaction against SQLite fixture')

-- Earlier suites install a stub under this name; load the real module.
package.loaded['luasql.sqlite3'] = nil
local ok, sqlite = pcall(require, 'luasql.sqlite3')
if not ok or type(sqlite) ~= 'table' or not sqlite.sqlite3 then
  t.skip('database integration', 'luasql.sqlite3 is not installed')
  return
end

local SCHEMA = {
  [[CREATE TABLE cves (cve_id TEXT PRIMARY KEY, cvss_v2 TEXT, cvss_v3 TEXT,
    published INTEGER)]],
  [[CREATE TABLE products (product_id INTEGER PRIMARY KEY, vendor TEXT,
    product TEXT, version TEXT, version_update TEXT,
    UNIQUE (vendor, product, version, version_update))]],
  [[CREATE TABLE affected (cve_id TEXT, product_id INTEGER,
    PRIMARY KEY (cve_id, product_id))]],
  [[CREATE TABLE multiaffected (cve_id TEXT, product_id INTEGER,
    versionStartIncluding TEXT, versionStartExcluding TEXT,
    versionEndIncluding TEXT, versionEndExcluding TEXT)]],
  [[CREATE TABLE exploits (exploit_id INTEGER PRIMARY KEY, name TEXT)]],
  [[CREATE TABLE metasploits (metasploit_id INTEGER PRIMARY KEY,
    name TEXT UNIQUE)]],
  [[CREATE TABLE referenced_exploit (cve_id TEXT, exploit_id INTEGER,
    PRIMARY KEY (cve_id, exploit_id))]],
  [[CREATE TABLE referenced_metasploit (cve_id TEXT, metasploit_id INTEGER,
    PRIMARY KEY (cve_id, metasploit_id))]],
}

local CVES = {
  { 'CVE-2010-0425', '10.0', nil },   -- apache 2.2.8 exact
  { 'CVE-2017-1000118', '5.0', '7.5' }, -- akka http_server (other vendor)
  { 'CVE-2999-0001', '5.0', '9.8' },  -- apache, all versions
  { 'CVE-2999-0002', '4.3', '6.1' },  -- apache [2.4.0, 2.4.50)
  { 'CVE-2014-0160', '5.0', '7.5' },  -- openssl [1.0.1, 1.0.1g)
  { 'CVE-2013-0169', '2.6', '5.9' },  -- openssl [1.0.1, 1.0.1d]
  { 'CVE-2999-0003', '5.0', '7.5' },  -- sfackler openssl crate
  { 'CVE-2999-0004', '7.5', '9.8' },  -- openssh 4.7 p1
  { 'CVE-2999-0005', '7.5', '9.8' },  -- openssh 4.7 p2
  { 'CVE-2999-0006', '5.0', '5.3' },  -- openssh < 7.4
  { 'CVE-2011-2523', '10.0', '9.8' }, -- vsftpd 2.3.4 backdoor (beasts)
  { 'CVE-2012-0075', '1.7', nil },    -- mysql 5.5.20
  { 'CVE-2999-0007', '5.0', nil },    -- product name with a quote
  { 'CVE-2999-0008', '5.0', nil },    -- iis 7.5 through alias
}

-- id, vendor, product, version, update
local PRODUCTS = {
  { 1, 'apache', 'http_server', '2.2.8', '*' },
  { 2, 'akka', 'http_server', '2.2.8', '*' },
  { 3, 'apache', 'http_server', '*', '*' },
  { 4, 'openssl', 'openssl', '*', '*' },
  { 5, 'openbsd', 'openssh', '4.7', 'p1' },
  { 6, 'openbsd', 'openssh', '4.7', 'p2' },
  { 7, 'openbsd', 'openssh', '*', '*' },
  { 8, 'beasts', 'vsftpd', '2.3.4', '*' },
  { 9, 'mysql', 'mysql', '5.5.20', '*' },
  { 10, 'example', "o'prod", '1.0', '*' },
  { 11, 'sfackler', 'openssl', '*', '*' },
  { 12, 'microsoft', 'internet_information_services', '7.5', '*' },
}

local AFFECTED = {
  { 'CVE-2010-0425', 1 }, { 'CVE-2017-1000118', 2 },
  { 'CVE-2999-0004', 5 }, { 'CVE-2999-0005', 6 },
  { 'CVE-2011-2523', 8 }, { 'CVE-2012-0075', 9 },
  { 'CVE-2999-0007', 10 }, { 'CVE-2999-0008', 12 },
}

-- cve, product, start incl, start excl, end incl, end excl
local MULTI = {
  { 'CVE-2999-0001', 3 },
  { 'CVE-2999-0002', 3, '2.4.0', nil, nil, '2.4.50' },
  { 'CVE-2014-0160', 4, '1.0.1', nil, nil, '1.0.1g' },
  { 'CVE-2013-0169', 4, '1.0.1', nil, '1.0.1d', nil },
  { 'CVE-2999-0003', 11 },
  { 'CVE-2999-0006', 7, nil, nil, nil, '7.4' },
}

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

local function create_fixture()
  local path = os.tmpname()
  local env = assert(sqlite.sqlite3())
  local conn = assert(env:connect(path))
  for _, statement in ipairs(SCHEMA) do assert(conn:execute(statement)) end
  for _, row in ipairs(CVES) do
    insert(conn, 'cves', { row[1], row[2], row[3], 2000 }, 4)
  end
  for _, row in ipairs(PRODUCTS) do insert(conn, 'products', row, 5) end
  for _, row in ipairs(AFFECTED) do insert(conn, 'affected', row, 2) end
  for _, row in ipairs(MULTI) do insert(conn, 'multiaffected', row, 6) end
  insert(conn, 'exploits', { 11650, 'Apache mod_isapi Dangling Pointer' }, 2)
  insert(conn, 'referenced_exploit', { 'CVE-2010-0425', 11650 }, 2)
  insert(conn, 'metasploits',
    { 1, 'auxiliary/scanner/ssl/openssl_heartbleed' }, 2)
  insert(conn, 'referenced_metasploit', { 'CVE-2014-0160', 1 }, 2)
  conn:close()
  env:close()
  return path
end

local DB_PATH = create_fixture()
local HOST = { ip = '192.0.2.10' }

-- Build a scanner connected to the fixture with in-memory log and JSON.
local function scanner_for(args, aliases, vendor_aliases)
  local scanner = t.load_scanner({ sql = sqlite, args = args })
  local registry = scanner.registry
  registry.env = assert(sqlite.sqlite3())
  registry.conn = assert(registry.env:connect(DB_PATH))
  registry.log_lines = {}
  registry.logger = {
    write = function(_, line) table.insert(registry.log_lines, line) end
  }
  registry.json_out = {}
  registry.cache = {}
  registry.aliases = aliases or {}
  registry.vendor_aliases = vendor_aliases or {}
  return scanner
end

local function port(number, cpe, version, service)
  return { number = number, protocol = 'tcp', service = service or 'svc',
    version = { cpe = { cpe }, version = version } }
end

-- Run one port and return its output lines and reported CVE ids.
local function scan(cpe, version, opts)
  opts = opts or {}
  local scanner = opts.scanner
      or scanner_for(opts.args, opts.aliases, opts.vendor_aliases)
  local number = opts.port or 80
  local output = scanner.portaction(HOST, port(number, cpe, version))
  local cves = {}
  local host = scanner.registry.json_out[HOST.ip]
  local entry = host and host.ports[number .. '/tcp']
  for _, service in ipairs(entry and entry.services or {}) do
    for id in pairs(service.vulnerabilities.cves or {}) do cves[id] = true end
  end
  return output, cves, scanner
end

t.case('apache 2.2.8: exact plus all-versions CVEs', function()
  local _, cves = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8')
  t.keys_eq(cves, { 'CVE-2010-0425', 'CVE-2999-0001' })
end)

t.case('same product name from another vendor is not reported', function()
  local _, cves = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8')
  t.eq(cves['CVE-2017-1000118'], nil)
end)

t.case('output lists vendor, product and CVEs sorted by CVSS', function()
  local output = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8')
  t.eq({ output[1], output[2], output[3], output[4], output[5], output[6] }, {
    'vendor: apache', 'product: http_server', 'version: 2.2.8',
    'vupdate: *', 'version_source: nmap_cpe', 'cves: 2' })
  t.truthy(output[7]:find('CVE ID', 1, true), 'header line')
  t.truthy(output[7]:find('Conf', 1, true), 'confidence column')
  t.truthy(output[8]:find('CVE-2010-0425', 1, true), 'highest confidence first')
  t.truthy(output[8]:find('HIGH', 1, true), 'exact version is high')
  t.truthy(output[8]:find('Yes', 1, true), 'ExploitDB flag')
  t.truthy(output[9]:find('CVE-2999-0001', 1, true))
end)

t.case('minconf=medium hides low CVEs from the table, not the JSON', function()
  local output, _, scanner = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8',
    { args = { minconf = 'medium' } })
  t.eq(output[6], 'cves: 1 (total 2)')
  t.eq(table.concat(output, '\n'):find('CVE-2999-0001', 1, true), nil)
  local cves = scanner.registry.json_out[HOST.ip].ports['80/tcp']
      .services[1].vulnerabilities.cves
  t.eq(cves['CVE-2999-0001'].confidence, 'low')
  t.eq(cves['CVE-2010-0425'].confidence, 'high')
end)

t.case('invalid minconf falls back to low', function()
  local output = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8',
    { args = { minconf = 'bogus' } })
  t.eq(output[6], 'cves: 2')
end)

t.case('JSON output carries Exploit-DB and Metasploit details', function()
  local _, _, scanner = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8')
  local service = scanner.registry.json_out[HOST.ip].ports['80/tcp']
      .services[1]
  t.eq(service.vendor, 'apache')
  t.eq(service.vulnerabilities.total, 2)
  t.eq(service.vulnerabilities.cves['CVE-2010-0425'].exploitdb[1].url,
    'https://www.exploit-db.com/exploits/11650')
  local _, _, ssl = scan('cpe:/a:openssl:openssl:1.0.1e', '1.0.1e')
  t.eq(ssl.registry.json_out[HOST.ip].ports['80/tcp'].services[1]
    .vulnerabilities.cves['CVE-2014-0160'].metasploit[1].name,
    'auxiliary/scanner/ssl/openssl_heartbleed')
end)

t.case('Nmap 2.4.x wildcard reports overlapping ranges', function()
  local _, cves = scan('cpe:/a:apache:http_server', '2.4.x')
  t.keys_eq(cves, { 'CVE-2999-0001', 'CVE-2999-0002' })
end)

t.case('unknown version reports only unbounded CVEs', function()
  local _, cves = scan('cpe:/a:apache:http_server', nil)
  t.keys_eq(cves, { 'CVE-2999-0001' })
end)

t.case('openssl 1.0.1e: Heartbleed yes, 1.0.1d-bounded CVE no', function()
  local _, cves = scan('cpe:/a:openssl:openssl:1.0.1e', '1.0.1e')
  t.keys_eq(cves, { 'CVE-2014-0160' })
end)

t.case('openssl 1.0.1g: fixed version returns no output', function()
  local output, cves = scan('cpe:/a:openssl:openssl:1.0.1g', '1.0.1g')
  t.eq(output, nil)
  t.keys_eq(cves, {})
end)

t.case('openssh 4.7p1: matching update and range only', function()
  local _, cves = scan('cpe:/a:openbsd:openssh:4.7p1',
    '4.7p1 Debian 8ubuntu1')
  t.keys_eq(cves, { 'CVE-2999-0004', 'CVE-2999-0006' })
end)

t.case('quoted product names do not break SQL', function()
  local _, cves = scan("cpe:/a:example:o'prod:1.0", '1.0')
  t.keys_eq(cves, { 'CVE-2999-0007' })
end)

t.case('product aliases are queried', function()
  local _, cves = scan('cpe:/a:microsoft:iis:7.5', '7.5',
    { aliases = { iis = { 'internet_information_services' } } })
  t.keys_eq(cves, { 'CVE-2999-0008' })
end)

t.case('second port with the same product uses the cache', function()
  local scanner = scanner_for()
  scan('cpe:/a:apache:http_server:2.2.8', '2.2.8', { scanner = scanner })
  local output = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8',
    { scanner = scanner, port = 8080 })
  local service = scanner.registry.json_out[HOST.ip].ports['8080/tcp']
      .services[1]
  t.eq(service.vulnerabilities.info, 'cache')
  t.eq(service.vulnerabilities.total, 2)
  t.eq(output[6], 'cves: 2')
end)

t.case('maxcve limits printed rows but not JSON', function()
  local output, cves = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8',
    { args = { maxcve = '1' } })
  t.eq(#output, 9)
  t.keys_eq(cves, { 'CVE-2010-0425', 'CVE-2999-0001' })
end)

t.case('service argument restricts the analysed products', function()
  local args = { service = 'openssh' }
  local output = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8',
    { args = args })
  t.eq(output, nil)
  local _, cves = scan('cpe:/a:openbsd:openssh:4.7p1', '4.7p1',
    { args = args })
  t.keys_eq(cves, { 'CVE-2999-0004', 'CVE-2999-0006' })
end)

t.case('vsftpd CPE from Nmap finds the NVD vendor beasts', function()
  local _, cves = scan('cpe:/a:vsftpd:vsftpd:2.3.4', '2.3.4',
    { vendor_aliases = { vsftpd = { 'beasts', 'vsftpd_project' } } })
  t.keys_eq(cves, { 'CVE-2011-2523' })
end)

t.case('shipped vendor aliases list beasts for vsftpd', function()
  local file = assert(io.open('data/vendor-aliases.json', 'r'))
  local body = file:read('*all')
  file:close()
  t.truthy(body:find('"vsftpd"%s*:%s*%[%s*"beasts"'),
    'data/vendor-aliases.json lacks the vsftpd -> beasts alias')
end)

t.case('unknown vendor falls back to a product-only search', function()
  local _, cves = scan('cpe:/a:unknown:http_server:2.2.8', '2.2.8')
  t.keys_eq(cves, { 'CVE-2010-0425', 'CVE-2017-1000118', 'CVE-2999-0001' })
end)

t.case('MySQL 5.5.20-log matches exact 5.5.20', function()
  local _, cves = scan('cpe:/a:mysql:mysql:5.5.20-log', '5.5.20-log')
  t.keys_eq(cves, { 'CVE-2012-0075' })
end)

t.case('openssl 1.0.1b is affected by both 1.0.1 ranges', function()
  local _, cves = scan('cpe:/a:openssl:openssl:1.0.1b', '1.0.1b')
  t.keys_eq(cves, { 'CVE-2014-0160', 'CVE-2013-0169' })
end)

t.case('all cursors are closed after a scan', function()
  local _, _, scanner = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8')
  t.eq(scanner.registry.conn:close(), true,
    'conn:close() fails while cursors remain open')
end)

-- postaction() closes the connection before writing the JSON report. LuaSQL
-- 2.6 raises while cursors are open, so the report is lost unless the garbage
-- collector happened to finalise every unclosed cursor first (verified: an
-- explicit collectgarbage() makes this pass). The outcome is not
-- deterministic in real scans.
t.case('postaction writes the JSON report after a scan', function()
  local json_path = os.tmpname()
  os.remove(json_path)
  local scanner = scanner_for({ json = json_path })
  scanner.stubs.json.generate = function() return '{"ok":true}' end
  scanner.registry.logger.close = function() end
  scan('cpe:/a:apache:http_server:2.2.8', '2.2.8', { scanner = scanner })
  local ran, err = pcall(scanner.postaction)
  local file = io.open(json_path, 'r')
  local body = file and file:read('*all')
  if file then file:close() end
  os.remove(json_path)
  t.truthy(ran, 'postaction raised: ' .. tostring(err))
  t.eq(body, '{"ok":true}\n')
end)

os.remove(DB_PATH)
