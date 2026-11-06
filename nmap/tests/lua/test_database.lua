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
  local registry = scanner.modules.state
  registry.db_env = assert(sqlite.sqlite3())
  registry.db_conn = assert(registry.db_env:connect(DB_PATH))
  registry.log_lines = {}
  registry.log_file = {
    write = function(_, line) table.insert(registry.log_lines, line) end
  }
  registry.json_report = {}
  registry.json_hosts = {}
  registry.service_cache = {}
  registry.product_aliases = aliases or {}
  registry.vendor_aliases = vendor_aliases or {}
  return scanner
end

local function port(number, cpe, version, service)
  return { number = number, protocol = 'tcp', service = service or 'svc',
    version = { cpe = { cpe }, version = version } }
end

-- First product of a TCP port of ip in the JSON report hosts, or nil.
local function find_product(report, ip, port_number)
  for _, host in ipairs(report or {}) do
    if host.ip == ip then
      for _, entry in ipairs(host.ports) do
        if entry.port == port_number and entry.protocol == 'tcp' then
          return entry.products[1]
        end
      end
    end
  end
  return nil
end

-- CVE entry with the given id in a JSON product, or nil.
local function cve_of(product, id)
  for _, cve in ipairs(product and product.cves or {}) do
    if cve.id == id then return cve end
  end
  return nil
end

-- True when some output line contains text.
local function has_line(output, text)
  for _, line in ipairs(output or {}) do
    if line:find(text, 1, true) then return true end
  end
  return false
end

-- Split the Nmap text returned by portaction into lines. The text opens
-- with a newline, so the first line is empty and is dropped.
local function split_lines(text)
  local lines = {}
  if type(text) ~= 'string' then return nil end
  for line in (text .. '\n'):gmatch('([^\n]*)\n') do
    lines[#lines + 1] = line
  end
  table.remove(lines, 1)
  return lines
end

-- Run one port and return its output lines, the reported CVE ids (every
-- CVE of the product, not only the printed ones) and the scanner.
local function scan(cpe, version, opts)
  opts = opts or {}
  local scanner = opts.scanner
      or scanner_for(opts.args, opts.aliases, opts.vendor_aliases)
  local number = opts.port or 80
  -- portaction returns the structured rows first and the Nmap text second.
  local _, text = scanner.portaction(HOST, port(number, cpe, version))
  local output = split_lines(text)
  local cves = {}
  local product = find_product(scanner.modules.state.json_report, HOST.ip,
    number)
  for _, cve in ipairs(product and product.cves or {}) do
    cves[cve.id] = true
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

t.case('output lists product, counts and CVEs sorted by confidence', function()
  local output = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8')
  assert(output, 'no Nmap output for apache 2.2.8')
  t.truthy(output[1]:find('apache http_server 2.2.8', 1, true), 'product')
  t.truthy(output[1]:find('source: nmap_cpe', 1, true), 'version source')
  t.eq(output[2], 'CVEs: 2  high: 1  medium: 0  low: 1')
  t.truthy(output[3]:find('CVE', 1, true) and output[3]:find('CONF', 1, true),
      'table header')
  t.truthy(output[4]:find('CVE-2010-0425', 1, true),
      'highest confidence first')
  t.truthy(output[4]:find('HIGH', 1, true), 'exact version is high')
  t.truthy(output[4]:find('EDB', 1, true), 'Exploit-DB flag')
  t.truthy(output[4]:find('v2:10.0', 1, true), 'CVSS column')
  t.truthy(output[5]:find('CVE-2999-0001', 1, true))
  t.truthy(output[5]:find('LOW', 1, true), 'all-versions CVE is low')
end)

t.case('minconf=medium hides low CVEs from the table, not the JSON', function()
  local output, _, scanner = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8',
    { args = { minconf = 'medium' } })
  t.truthy(has_line(output, '1 below minconf=medium'), 'hidden count line')
  t.eq(has_line(output, 'CVE-2999-0001'), false)
  local product = find_product(scanner.modules.state.json_report, HOST.ip, 80)
  t.eq(cve_of(product, 'CVE-2999-0001').confidence, 'low')
  t.eq(cve_of(product, 'CVE-2010-0425').confidence, 'high')
end)

t.case('invalid minconf falls back to low', function()
  local output = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8',
    { args = { minconf = 'bogus' } })
  assert(output, 'no Nmap output for minconf=bogus')
  t.eq(output[2], 'CVEs: 2  high: 1  medium: 0  low: 1')
  t.eq(has_line(output, 'below minconf'), false)
end)

t.case('JSON output carries Exploit-DB and Metasploit details', function()
  local _, _, scanner = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8')
  local product = find_product(scanner.modules.state.json_report, HOST.ip, 80)
  assert(product, 'no JSON product for apache on port 80')
  t.eq(product.vendor, 'apache')
  t.eq(product.counts.total, 2)
  t.eq(cve_of(product, 'CVE-2010-0425').exploitdb[1].url,
    'https://www.exploit-db.com/exploits/11650')
  local _, _, ssl = scan('cpe:/a:openssl:openssl:1.0.1e', '1.0.1e')
  local ssl_product = find_product(ssl.modules.state.json_report, HOST.ip, 80)
  t.eq(cve_of(ssl_product, 'CVE-2014-0160').metasploit[1],
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
  assert(output, 'no Nmap output for the second port')
  local first = find_product(scanner.modules.state.json_report, HOST.ip, 80)
  local second = find_product(scanner.modules.state.json_report, HOST.ip, 8080)
  assert(first, 'no JSON product on port 80')
  assert(second, 'no JSON product on port 8080')
  t.eq(first.cached, false)
  t.eq(second.cached, true)
  t.eq(second.counts.total, 2)
  t.eq(#second.cves, 2, 'cached service keeps the full CVE list')
  t.eq(output[2], 'CVEs: 2  high: 1  medium: 0  low: 1')
end)

-- Number of products in the JSON report for a TCP port of HOST.
local function product_count(report, port_number)
  local count = 0
  for _, host in ipairs(report or {}) do
    if host.ip == HOST.ip then
      for _, entry in ipairs(host.ports) do
        if entry.port == port_number and entry.protocol == 'tcp' then
          count = count + #entry.products
        end
      end
    end
  end
  return count
end

-- Replace the collected matches of a port with entries of the form
-- { origin, cpe, version }, so one port can show several origins.
local function use_matches(scanner, entries)
  local collect = scanner.modules.port_matches
  collect.collect_port_matches = function()
    local matches = collect.new_match_table()
    for _, entry in ipairs(entries) do
      local bucket = matches.data[entry[1]]
      bucket[entry[2]] = bucket[entry[2]] or {}
      bucket[entry[2]][entry[3]] = true
      matches.size = matches.size + 1
    end
    return matches
  end
end

t.case('same product from two origins on one port is reported once', function()
  local cpe = 'cpe:/a:apache:http_server:2.2.8'
  local scanner = scanner_for()
  scanner.modules.state.totals = { hosts = 0, services = 0, cves = 0 }
  use_matches(scanner, {
    { 'nmap', cpe, '2.2.8' },
    { 'http', cpe, '2.2.8' },
  })
  local _, text = scanner.portaction(HOST, port(80, cpe, '2.2.8'))
  local report = scanner.modules.state.json_report
  t.eq(product_count(report, 80), 1, 'one JSON entry for the port')
  t.eq(scanner.modules.state.totals.services, 1, 'one service in totals')
  t.eq(scanner.modules.state.totals.cves, 2, 'CVEs counted once')
  local lines = split_lines(text)
  local summaries = 0
  for _, line in ipairs(lines or {}) do
    if line:find('CVEs: ', 1, true) == 1 then summaries = summaries + 1 end
  end
  t.eq(summaries, 1, 'one Nmap summary line')
end)

t.case('same product on two ports gives one entry per port', function()
  local cpe = 'cpe:/a:apache:http_server:2.2.8'
  local scanner = scanner_for()
  scanner.modules.state.totals = { hosts = 0, services = 0, cves = 0 }
  scan(cpe, '2.2.8', { scanner = scanner })
  scan(cpe, '2.2.8', { scanner = scanner, port = 8080 })
  local report = scanner.modules.state.json_report
  t.eq(product_count(report, 80), 1, 'first port entry')
  t.eq(product_count(report, 8080), 1, 'second port entry')
  t.eq(scanner.modules.state.totals.services, 2, 'two services in totals')
  t.eq(find_product(report, HOST.ip, 8080).cached, true)
end)

t.case('maxcve limits printed rows but not JSON', function()
  local output, cves = scan('cpe:/a:apache:http_server:2.2.8', '2.2.8',
    { args = { maxcve = '1' } })
  t.eq(#output, 5)
  t.truthy(has_line(output, 'CVE-2010-0425'), 'first row printed')
  t.eq(has_line(output, 'CVE-2999-0001'), false)
  t.truthy(has_line(output, '+1 more (maxcve=1)'), 'hidden count line')
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
  t.eq(scanner.modules.state.db_conn:close(), true,
    'conn:close() fails while cursors remain open')
end)

-- postaction() closes the connection before writing the JSON report. LuaSQL
-- 2.6 raises while cursors are open, so the report is lost unless the garbage
-- collector happened to finalise every unclosed cursor first (verified: an
-- explicit collectgarbage() makes this pass). The outcome is not
-- deterministic in real scans.
t.case('portaction returns the Nmap text as a string', function()
  local scanner = scanner_for()
  local structured, text = scanner.portaction(HOST,
    port(80, 'cpe:/a:apache:http_server:2.2.8', '2.2.8'))
  t.eq(type(structured), 'table', 'structured rows')
  t.eq(type(text), 'string', 'second return value')
  t.eq(text:sub(1, 1), '\n', 'text opens on its own line')
  t.truthy(text:sub(-1) ~= '\n', 'text has no trailing newline')
  t.truthy(text:find('CVE-2010-0425', 1, true), 'expected CVE in text')
  t.eq(text:find('table:', 1, true), nil, 'no Lua table dump')
end)

t.case('postaction writes the JSON report after a scan', function()
  local json_path = os.tmpname()
  os.remove(json_path)
  local scanner = scanner_for({ json = json_path })
  scanner.stubs.json.generate = function() return '{"ok":true}' end
  scanner.modules.state.log_file.close = function() end
  scanner.modules.state.totals = { hosts = 0, services = 0, cves = 0 }
  scanner.modules.state.script_version = 'x'
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
