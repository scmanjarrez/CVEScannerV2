-- SPDX-License-Identifier: GPL-3.0-or-later
-- Golden tests of the rendering modules: text_output and json_report.
--
-- The results are fixed tables, so no database is needed. The real nselib
-- json module needs lpeg, which is not always installed, so the JSON cases
-- use a small encoder with the same NULL and make_array contract.

local t = require 'harness'

-- Encoder that writes object keys sorted, arrays as [] and NULL as null.
local ARRAYS = setmetatable({}, { __mode = 'k' })
local NULL = setmetatable({}, { __tostring = function() return 'NULL' end })

local function quote(str)
  return '"' .. str:gsub('["\\]', '\\%0') .. '"'
end

local function encode(value)
  if value == nil or value == NULL then return 'null' end
  local kind = type(value)
  if kind == 'boolean' or kind == 'number' then return tostring(value) end
  if kind == 'string' then return quote(value) end
  if ARRAYS[value] or value[1] ~= nil then
    local parts = {}
    for i, item in ipairs(value) do parts[i] = encode(item) end
    return '[' .. table.concat(parts, ',') .. ']'
  end
  local keys = {}
  for key in pairs(value) do keys[#keys + 1] = key end
  table.sort(keys)
  if #keys == 0 then return '{}' end
  local parts = {}
  for i, key in ipairs(keys) do
    parts[i] = quote(key) .. ':' .. encode(value[key])
  end
  return '{' .. table.concat(parts, ',') .. '}'
end

local JSON = {
  NULL = NULL,
  make_array = function(list)
    ARRAYS[list] = true
    return list
  end,
  generate = encode,
}

local s = t.load_scanner({ json = JSON })
local text = s.modules.text_output
local report = s.modules.json_report
local state = s.modules.state

-- Build a result table; counts are derived from the CVE entries.
local function result_of(cves, over)
  local counts = { total = #cves, high = 0, medium = 0, low = 0, shown = 0 }
  for _, cve in ipairs(cves) do
    counts[cve.confidence] = counts[cve.confidence] + 1
    if cve.visible then counts.shown = counts.shown + 1 end
  end
  local result = {
    cpe = 'cpe:/a:apache:http_server:2.2.8',
    vendor = 'apache',
    product = 'http_server',
    version = '2.2.8',
    update = nil,
    version_source = 'nmap_cpe',
    os_context = {},
    warnings = {},
    counts = counts,
    cves = cves,
  }
  for key, value in pairs(over or {}) do result[key] = value end
  return result
end

-- One CVE entry in the shape of service_cves.find_service_cves.
local function cve(id, cvss, confidence, opts)
  opts = opts or {}
  return {
    id = id,
    cvss = { v4 = cvss.v4, v3 = cvss.v3, v2 = cvss.v2 },
    confidence = confidence,
    reasons = opts.reasons or {},
    visible = opts.visible ~= false,
    exploitdb = opts.exploitdb or {},
    metasploit = opts.metasploit or {},
  }
end

local EDB_1 = {
  id = '11650',
  name = 'Apache mod_isapi Dangling Pointer',
  url = 'https://www.exploit-db.com/exploits/11650'
}
local EDB_2 = { id = '1', url = 'https://www.exploit-db.com/exploits/1' }

-- Four CVEs, sorted by confidence: A EDB, C EDB MSF, B MSF, D none.
local CVE_A = cve('CVE-2010-0425', { v2 = 10.0 }, 'high',
  { reasons = { 'exact_version' }, exploitdb = { EDB_1 } })
local CVE_C = cve('CVE-2999-0003', { v4 = 9.3 }, 'high',
  {
    reasons = { 'exact_version' },
    exploitdb = { EDB_2 },
    metasploit = { 'exploit/x/y' }
  })
local CVE_B = cve('CVE-2999-0002', { v3 = 9.8, v2 = 5.0 }, 'medium',
  {
    reasons = { 'range_overlap', 'platform_mismatch:windows' },
    metasploit = { 'auxiliary/x/z' }
  })
local CVE_D = cve('CVE-2999-0001', { v3 = 5.0 }, 'low',
  { reasons = { 'nvd_unbounded' } })

-- Same four CVEs, but D is hidden by minconf=medium.
local function all_visible()
  return result_of({ CVE_A, CVE_C, CVE_B, CVE_D })
end

local function one_hidden()
  local hidden = cve('CVE-2999-0001', { v3 = 5.0 }, 'low',
    { reasons = { 'nvd_unbounded' }, visible = false })
  return result_of({ CVE_A, CVE_C, CVE_B, hidden })
end

local function cfg(maxcve, minconf)
  return { maxcve = maxcve, minconf = minconf, json = 'cvescannerv2.json' }
end

-- Golden lines of the Nmap table of the four-CVE result.
local L1 = 'apache http_server 2.2.8 (cpe:/a:apache:http_server:2.2.8)'
    .. '  source: nmap_cpe'
local COUNTS = 'CVEs: 4  high: 2  medium: 1  low: 1'
local HEAD = '  CVE              CONF  EXPLOITS  CVSS'
local ROW_A = '  CVE-2010-0425    HIGH  EDB       v2:10.0'
local ROW_C = '  CVE-2999-0003    HIGH  EDB MSF   v4:9.3'
local ROW_B = '  CVE-2999-0002    MED   MSF       v3:9.8 v2:5.0'
local ROW_D = '  CVE-2999-0001    LOW   -         v3:5.0'
local FULL = '. Full list: cvescannerv2.json'

-- Lines of nmap_lines for result and cfg, as one string for comparison.
local function nmap(result, cfg_table)
  return text.nmap_lines(result, cfg_table)
end

-- True when no line of the list contains the substring nil.
local function no_nil(lines)
  for _, line in ipairs(lines) do
    if line:find('nil', 1, true) then return false end
  end
  return true
end

t.suite('cvss_text and exploit_text')

t.case('cvss_text lists v4, v3, v2 when present', function()
  t.eq(text.cvss_text({ v4 = 9.3, v3 = 9.8, v2 = 7.5 }),
    'v4:9.3 v3:9.8 v2:7.5')
end)

t.case('cvss_text with only v4', function()
  t.eq(text.cvss_text({ v4 = 9.3 }), 'v4:9.3')
end)

t.case('cvss_text with only v2', function()
  t.eq(text.cvss_text({ v2 = 7.5 }), 'v2:7.5')
end)

t.case('cvss_text without scores is a dash', function()
  t.eq(text.cvss_text({}), '-')
end)

t.case('exploit_text: EDB MSF, EDB, MSF and dash', function()
  t.eq(text.exploit_text(CVE_C), 'EDB MSF')
  t.eq(text.exploit_text(CVE_A), 'EDB')
  t.eq(text.exploit_text(CVE_B), 'MSF')
  t.eq(text.exploit_text(CVE_D), '-')
end)

t.suite('nmap_lines golden')

t.case('all CVEs shown: no hidden line', function()
  t.eq(nmap(all_visible(), cfg(10, 'low')), {
    L1, COUNTS, HEAD, ROW_A, ROW_C, ROW_B, ROW_D,
  })
end)

t.case('only maxcve hides rows', function()
  t.eq(nmap(all_visible(), cfg(2, 'low')), {
    L1, COUNTS, HEAD, ROW_A, ROW_C,
    '+2 more (maxcve=2)' .. FULL,
  })
end)

t.case('only minconf hides rows', function()
  t.eq(nmap(one_hidden(), cfg(10, 'medium')), {
    L1, COUNTS, HEAD, ROW_A, ROW_C, ROW_B,
    '1 below minconf=medium' .. FULL,
  })
end)

t.case('maxcve and minconf both hide rows', function()
  t.eq(nmap(one_hidden(), cfg(2, 'medium')), {
    L1, COUNTS, HEAD, ROW_A, ROW_C,
    '+1 more (maxcve=2); 1 below minconf=medium' .. FULL,
  })
end)

t.case('distro_backport warning sits before the table header', function()
  local result = all_visible()
  result.warnings = { 'distro_backport' }
  t.eq(nmap(result, cfg(10, 'low')), {
    L1, COUNTS,
    'warning: distro_backport - fixes may be backported by the distro',
    HEAD, ROW_A, ROW_C, ROW_B, ROW_D,
  })
end)

t.case('vendor shown only when it differs from the product', function()
  local result = result_of({}, {
    vendor = 'nginx',
    product = 'nginx',
    version = '1.18.0',
    cpe = 'cpe:/a:nginx:nginx:1.18.0'
  })
  t.eq(nmap(result, cfg(10, 'low')), {
    'nginx 1.18.0 (cpe:/a:nginx:nginx:1.18.0)  source: nmap_cpe',
    'CVEs: 0  high: 0  medium: 0  low: 0',
  })
end)

t.case('update shown when it is not nil', function()
  local result = result_of({}, {
    vendor = 'openbsd',
    product = 'openssh',
    version = '4.7',
    update = 'p1',
    cpe = 'cpe:/a:openbsd:openssh:4.7'
  })
  t.eq(nmap(result, cfg(10, 'low'))[1],
    'openbsd openssh 4.7 update p1 (cpe:/a:openbsd:openssh:4.7)'
    .. '  source: nmap_cpe')
end)

t.suite('log_lines golden')

local CTX = { ip = '10.0.0.1', port_proto = '80/tcp', service = 'http' }

t.case('normal service: header, scores, CVEs with reasons and exploits', function()
  local result = all_visible()
  result.os_context = { family = 'linux', source = 'probe:smb_os' }
  t.eq(text.log_lines(result, CTX), {
    '[10.0.0.1 80/tcp http] apache http_server 2.2.8',
    '  cpe: cpe:/a:apache:http_server:2.2.8  source: nmap_cpe'
    .. '  os: linux (probe:smb_os)',
    '  ' .. COUNTS,
    '  CVE-2010-0425   HIGH  v2:10.0              exact_version',
    '      EDB  11650  https://www.exploit-db.com/exploits/11650'
    .. '  Apache mod_isapi Dangling Pointer',
    '  CVE-2999-0003   HIGH  v4:9.3               exact_version',
    '      MSF  exploit/x/y',
    '      EDB  1  https://www.exploit-db.com/exploits/1',
    '  CVE-2999-0002   MED   v3:9.8 v2:5.0        range_overlap, platform_mismatch:windows',
    '      MSF  auxiliary/x/z',
    '  CVE-2999-0001   LOW   v3:5.0               nvd_unbounded',
  })
end)

t.case('cached service: one line naming the first report', function()
  local ctx = {
    ip = '10.0.0.1',
    port_proto = '80/tcp',
    service = 'http',
    cached_from = '10.0.0.2 80/tcp'
  }
  t.eq(text.log_lines(all_visible(), ctx), {
    '[10.0.0.1 80/tcp http] apache http_server 2.2.8',
    '  cached: same result as 10.0.0.2 80/tcp',
  })
end)

t.case('service without CVEs: counts line only', function()
  local result = result_of({}, { os_context = {} })
  result.version_source = nil
  t.eq(text.log_lines(result, CTX), {
    '[10.0.0.1 80/tcp http] apache http_server 2.2.8',
    '  cpe: cpe:/a:apache:http_server:2.2.8  source: -  os: -',
    '  CVEs: 0  high: 0  medium: 0  low: 0',
  })
end)

t.suite('log header and footer')

t.case('log_header writes the run line, the arguments and a blank line', function()
  t.eq(text.log_header('v4.0.0', '2026-11-05T10:00:00Z',
    { minconf = 'low', maxcve = 10, db = 'cve.db' }), {
    '=== cvescannerv2 v4.0.0  2026-11-05T10:00:00Z ===',
    'args: minconf=low maxcve=10 db=cve.db',
    '',
  })
end)

t.case('log_footer writes hosts, services and CVEs', function()
  t.eq(text.log_footer({ hosts = 1, services = 2, cves = 7 }), {
    '=== end  hosts: 1  services: 2  CVEs: 7 ===',
  })
end)

t.suite('structured_output')

t.case('keeps only the CVSS versions present and cuts to maxcve', function()
  local out = text.structured_output(all_visible(), cfg(2, 'low'))
  t.eq(out.product, 'http_server')
  t.eq(out.version, '2.2.8')
  t.eq(out.source, 'nmap_cpe')
  t.eq(#out.cves, 2)
  t.eq(out.cves[1].id, 'CVE-2010-0425')
  t.eq(out.cves[1].cvss, { v2 = 10.0 })
  t.eq(out.cves[2].id, 'CVE-2999-0003')
  t.eq(out.cves[2].cvss, { v4 = 9.3 })
end)

t.suite('json_report')

-- Reset the report state, fill it with build and return the JSON text.
local function json_body(build)
  state.json_report = {}
  state.json_hosts = {}
  state.run_timestamp = '2026-11-05T10:00:00Z'
  build()
  local path = os.tmpname()
  os.remove(path)
  report.write(path, { version = 'v4.0.0', minconf = 'low', maxcve = 10 })
  local file = assert(io.open(path, 'r'))
  local body = file:read('*all')
  file:close()
  os.remove(path)
  return body
end

local PORT = { number = 80, protocol = 'tcp', service = 'http' }

t.case('record has schema_version 2 and one line', function()
  local body = json_body(function()
    report.add_service('10.0.0.1', PORT, all_visible(), false)
  end)
  t.truthy(body:find('"schema_version":2', 1, true), 'schema version')
  t.eq(select(2, body:gsub('\n', '')), 1, 'one JSON Lines record')
end)

t.case('CVSS keeps the three keys, nulls included', function()
  local body = json_body(function()
    report.add_service('10.0.0.1', PORT, all_visible(), false)
  end)
  t.truthy(body:find('"cvss":{"v2":10.0,"v3":null,"v4":null}', 1, true),
    'v2 only CVE keeps null v3 and v4')
end)

t.case('empty warnings is an empty array and update is null', function()
  local body = json_body(function()
    report.add_service('10.0.0.1', PORT, all_visible(), false)
  end)
  t.truthy(body:find('"warnings":[]', 1, true), 'warnings []')
  t.truthy(body:find('"update":null', 1, true), 'update null')
end)

t.case('host without products keeps ports as an empty array', function()
  local body = json_body(function()
    report.ensure_host('10.0.0.9')
  end)
  t.truthy(body:find('{"ip":"10.0.0.9","ports":[]}', 1, true),
    'host without ports')
end)

t.case('cached service is marked and keeps every CVE', function()
  local body = json_body(function()
    report.add_service('10.0.0.1', PORT, all_visible(), true)
  end)
  t.truthy(body:find('"cached":true', 1, true), 'cached flag')
  for _, id in ipairs({ 'CVE-2010-0425', 'CVE-2999-0003', 'CVE-2999-0002',
    'CVE-2999-0001' }) do
    t.truthy(body:find('"id":"' .. id .. '"', 1, true), id)
  end
end)

t.suite('no nil in text output')

t.case('nmap, log and cvss text never print the word nil', function()
  local hidden = one_hidden()
  local empty = result_of({}, { os_context = {} })
  empty.version_source = nil
  local lines = {}
  for _, result in ipairs({ all_visible(), hidden, empty }) do
    for _, line in ipairs(nmap(result, cfg(1, 'medium'))) do
      table.insert(lines, line)
    end
    for _, line in ipairs(text.log_lines(result, CTX)) do
      table.insert(lines, line)
    end
  end
  table.insert(lines, text.cvss_text({}))
  table.insert(lines, text.cvss_text({ v2 = 7.5 }))
  t.truthy(no_nil(lines), 'a text line contains nil')
end)
