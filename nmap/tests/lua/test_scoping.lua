-- SPDX-License-Identifier: GPL-3.0-or-later
-- Version scoping against NVD rows, CVSS ordering, and SQL formatting.

local t = require 'harness'
local s = t.load_scanner()

-- Run scoped_multi_versions for one observed version or range.
local function multi(rows, from, to, unknown)
  local result = {}
  s.scoped_multi_versions(rows, from, to or from, result, unknown)
  return result
end

-- Run scoped_versions for one observed version, update, or range.
local function exact(rows, from, to, upd)
  local result = {}
  s.scoped_versions(rows, from, to or from, upd or '*', result)
  return result
end

local heartbleed = { id = 'R1', StartInc = '1.0.1', EndExc = '1.0.1g' }

t.suite('scoped_multi_versions (NVD ranges)')

t.case('inclusive start and exclusive end', function()
  t.keys_eq(multi({ heartbleed }, '1.0.1'), { 'R1' })
  t.keys_eq(multi({ heartbleed }, '1.0.1e'), { 'R1' })
  t.keys_eq(multi({ heartbleed }, '1.0.1g'), {})
  t.keys_eq(multi({ heartbleed }, '1.0.0'), {})
end)

t.case('inclusive end', function()
  local rows = { { id = 'R2', EndInc = '2.0' } }
  t.keys_eq(multi(rows, '2.0'), { 'R2' })
  t.keys_eq(multi(rows, '2.0.1'), {})
end)

t.case('exclusive start', function()
  local rows = { { id = 'R3', StartExc = '1.0' } }
  t.keys_eq(multi(rows, '1.0'), {})
  t.keys_eq(multi(rows, '1.0.1'), { 'R3' })
end)

t.case('unbounded row applies to every version', function()
  t.keys_eq(multi({ { id = 'R4' } }, '0.1'), { 'R4' })
end)

t.case('update suffix is honoured at the boundary', function()
  local rows = { { id = 'R5', EndExc = '7.4p1' } }
  t.keys_eq(multi(rows, '7.4'), { 'R5' })
  t.keys_eq(multi(rows, '7.4p1'), {})
end)

t.case('observed range overlaps the NVD interval', function()
  local rows = {
    { id = 'IN', StartInc = '2.4.10', EndExc = '2.4.20' },
    { id = 'OUT', EndExc = '2.2.0' },
  }
  t.keys_eq(multi(rows, '2.4.0', '2.4.9999999999'), { 'IN' })
end)

t.case('unknown version keeps all rows (query pre-filters)', function()
  t.keys_eq(multi({ heartbleed, { id = 'R4' } }, '*', '*', true),
    { 'R1', 'R4' })
end)

t.case('non-comparable bounds never match', function()
  t.keys_eq(multi({ { id = 'BAD', EndExc = 'unknown' } }, '1.0'), {})
end)

t.case('OpenSSL 1.0.1b is inside [1.0.1, 1.0.1g)', function()
  t.keys_eq(multi({ heartbleed }, '1.0.1b'), { 'R1' })
end)

t.case('MySQL 5.5.20-log is inside (, 5.5.20]', function()
  t.keys_eq(multi({ { id = 'M', EndInc = '5.5.20' } }, '5.5.20-log'),
    { 'M' })
end)

t.suite('scoped_versions (exact NVD products)')

t.case('exact version without update', function()
  local rows = { { id = 'E1', version = '2.2.8', version_update = '*' } }
  t.keys_eq(exact(rows, '2.2.8'), { 'E1' })
  t.keys_eq(exact(rows, '2.2.9'), {})
end)

t.case('update must match when both are known', function()
  local rows = {
    { id = 'P1', version = '4.7', version_update = 'p1' },
    { id = 'P2', version = '4.7', version_update = 'p2' },
    { id = 'ANY', version = '4.7', version_update = '*' },
  }
  t.keys_eq(exact(rows, '4.7', nil, 'p1'), { 'P1', 'ANY' })
end)

t.case('unknown observed update keeps every update', function()
  local rows = { { id = 'P2', version = '4.7', version_update = 'p2' } }
  t.keys_eq(exact(rows, '4.7', nil, '*'), { 'P2' })
end)

t.case('update stored inside the NVD version field', function()
  local rows = {
    { id = 'IN', version = '4.7p1', version_update = '*' },
    { id = 'OUT', version = '4.7p2', version_update = '*' },
  }
  t.keys_eq(exact(rows, '4.7', nil, 'p1'), { 'IN' })
end)

t.case('NA update in NVD does not match a concrete update', function()
  local rows = { { id = 'NA', version = '4.7', version_update = '-' } }
  t.keys_eq(exact(rows, '4.7', nil, 'p1'), {})
end)

t.case('exact products inside an observed range', function()
  local rows = {
    { id = 'IN', version = '2.4.7', version_update = '*' },
    { id = 'OUT', version = '2.2.8', version_update = '*' },
  }
  t.keys_eq(exact(rows, '2.4.0', '2.4.9999999999'), { 'IN' })
end)

t.case('exact 5.5.20 matches the observed 5.5.20-log', function()
  local rows = { { id = 'E', version = '5.5.20', version_update = '*' } }
  t.keys_eq(exact(rows, '5.5.20-log'), { 'E' })
end)

t.case('letter release split by the parser still matches exactly', function()
  -- version_parser turns 1.0.1a into ver=1.0.1, vup=a.
  local rows = { { id = 'A', version = '1.0.1a', version_update = '*' } }
  t.keys_eq(exact(rows, '1.0.1', nil, 'a'), { 'A' })
  t.keys_eq(exact(rows, '1.0.1', nil, 'b'), {})
end)

t.suite('cvss_comparator')

t.case('sort by CVSSv3, then CVSSv2, then CVE id', function()
  local rows = {
    { 'CVE-A', '5.0', nil },
    { 'CVE-B', '10.0', nil },
    { 'CVE-F', nil, '9.8' },
    { 'CVE-E', '7.5', nil },
    { 'CVE-C', nil, '7.5' },
    { 'CVE-D', nil, nil },
  }
  table.sort(rows, s.cvss_comparator)
  local order = {}
  for _, row in ipairs(rows) do table.insert(order, row[1]) end
  t.eq(order, { 'CVE-B', 'CVE-F', 'CVE-C', 'CVE-E', 'CVE-A', 'CVE-D' })
end)

t.case('numeric, not lexicographic, comparison', function()
  t.truthy(s.cvss_comparator({ 'X', '10.0', nil }, { 'Y', '9.0', nil }))
end)

t.suite('SQL formatting')

t.case('fmtn escapes single quotes', function()
  t.eq((s.fmtn("p = '${p}'", { p = "o'reilly" })), "p = 'o''reilly'")
end)

t.case('fmtn renders missing values as nil', function()
  t.eq((s.fmtn("v = '${v}'", {})), "v = 'nil'")
end)

t.case('product queries are scoped by vendor', function()
  for _, name in ipairs({ 'affected', 'multiaffected',
    'multiaffected_empty' }) do
    t.truthy(s.query(name):find("vendor IN (${v})", 1, true),
      name .. ' must filter by vendor')
  end
end)

t.suite('two-part series expansion')

-- Cursor over fixed rows, as returned by registry.conn:execute.
local function cursor(rows)
  local i = 0
  return {
    fetch = function()
      i = i + 1
      if rows[i] == nil then return nil end
      return table.unpack(rows[i])
    end,
    close = function() end,
  }
end

-- Fake connection answering each product query from the fixture table.
local function fake_conn(db)
  return {
    execute = function(_, sql)
      if sql:find('sqlite_master', 1, true) then
        return cursor(db.conditions_table and { { 'conditions' } } or {})
      elseif sql:find('FROM conditions', 1, true) then
        return cursor(db.platform or {})
      elseif sql:find('SELECT EXISTS (SELECT 1 FROM products', 1, true) then
        return cursor({ { db.children and 1 or 0 } })
      elseif sql:find('SELECT DISTINCT vendor', 1, true) then
        return cursor({ { 'apache' } })
      elseif sql:find('FROM multiaffected', 1, true) then
        return cursor({})
      elseif sql:find('INNER JOIN affected', 1, true) then
        return cursor(db.affected)
      end
      return cursor({})
    end,
  }
end

-- Install a fake database and run vulnerabilities for one observed info.
local function scan(db, info, ctx)
  local reg = s.registry
  reg.conn = fake_conn(db)
  reg.logger = { write = function() end }
  reg.json_out = { ['10.0.0.1'] = { ports = {} } }
  local host = { ip = '10.0.0.1' }
  local port = { number = 80, protocol = 'tcp', service = 'http' }
  local out, meta = s.vulnerabilities(host, port,
    'cpe:/a:apache:tomcat:5.5', 'apache', 'tomcat', info, ctx)
  return out[1], table.concat(out, '\n'), meta
end

local function info_of(ver)
  return { ver = ver, vup = '*', from = nil, to = nil, empty = false,
    range = false }
end

local rows = {
  { 'CVE-EXACT', '5.0', nil, '5.5', '*', 0, 0 },
  { 'CVE-CHILD', '5.0', nil, '5.5.3', '*', 0, 0 },
  { 'CVE-LATER', '5.0', nil, '5.5.4', '*', 0, 0 },
}

t.case('series 5.5 expands to children when the database has them', function()
  local n, text = scan({ children = true, affected = rows }, info_of('5.5'))
  t.eq(n, 3)
  t.truthy(text:find('CVE-LATER', 1, true))
end)

t.case('series 5.5 without children keeps the exact match only', function()
  local n, text = scan({ children = false, affected = rows }, info_of('5.5'))
  t.eq(n, 1)
  t.truthy(text:find('CVE-EXACT', 1, true))
end)

t.case('specific version 5.5.3 is not expanded', function()
  local n = scan({ children = true, affected = rows }, info_of('5.5.3'))
  t.eq(n, 1)
end)

t.case('Nmap range is not changed by series expansion', function()
  local info = { ver = nil, vup = nil, from = '5.5.0',
    to = '5.5.9999999999', empty = false, range = true }
  local without = scan({ children = false, affected = rows }, info)
  local with = scan({ children = true, affected = rows }, info)
  t.eq(with, without)
end)

t.case('series_prefix accepts only x.y without update', function()
  t.eq(s.series_prefix(info_of('5.5')), '5.5')
  t.eq(s.series_prefix(info_of('5.5.3')), nil)
  t.eq(s.series_prefix({ ver = '5.5', vup = 'sp1', empty = false,
    range = false }), nil)
  t.eq(s.series_prefix({ ver = nil, vup = nil, empty = false,
    range = true }), nil)
end)

t.case('series_has_children reads the EXISTS result', function()
  s.registry.conn = fake_conn({ children = true })
  t.truthy(s.series_has_children({ 'apache' }, 'tomcat', '5.5'))
  s.registry.conn = fake_conn({ children = false })
  t.eq(s.series_has_children({ 'apache' }, 'tomcat', '5.5'), false)
end)

t.case('merge_series marks added CVEs and keeps existing ones', function()
  local vulns = { KEEP = { CVSSV2 = '1.0' } }
  s.merge_series({
    KEEP = { CVSSV2 = '9.9' },
    NEW = { CVSSV2 = '5.0' },
  }, vulns)
  t.eq(vulns.KEEP.CVSSV2, '1.0')
  t.eq(vulns.KEEP.series_expanded, nil)
  t.eq(vulns.NEW.series_expanded, true)
end)

t.suite('platform conditions')

local FAMILIES = {
  linux = 'linux', suse = 'linux', canonical = 'linux', redhat = 'linux',
  microsoft = 'windows',
}

-- Fresh scanner with platform families, a fake database and a log list.
local function platform_scanner(db, args)
  local sc = t.load_scanner({ args = args })
  local logged = {}
  sc.registry.platform_families = FAMILIES
  sc.registry.conn = fake_conn(db)
  sc.registry.json_out = { ['10.0.0.1'] = { ports = {} } }
  sc.registry.logger = {
    write = function(_, msg) table.insert(logged, msg) end,
  }
  return sc, logged
end

-- One platform row of a CVE configuration.
local function plat(config_idx, part, vendor)
  return { config_idx = config_idx, part = part, vendor = vendor,
    product = 'x' }
end

t.case('AND Windows CVE with linux context is a platform mismatch', function()
  local sc = platform_scanner({})
  t.eq(sc.evaluate_platform({ plat(0, 'o', 'microsoft') },
    { family = 'linux' }), 'platform_mismatch:windows')
end)

t.case('same family, other distro names the required vendor', function()
  local sc = platform_scanner({})
  t.eq(sc.evaluate_platform({ plat(0, 'o', 'redhat') },
    { family = 'linux', distro = 'ubuntu' }), 'platform_mismatch:redhat')
end)

t.case('other family names the required family', function()
  local sc = platform_scanner({})
  t.eq(sc.evaluate_platform({ plat(0, 'o', 'microsoft') },
    { family = 'linux', distro = 'ubuntu' }), 'platform_mismatch:windows')
end)

t.case('unknown context gives requires_platform', function()
  local sc = platform_scanner({})
  t.eq(sc.evaluate_platform({ plat(0, 'o', 'microsoft') }, {}),
    'requires_platform')
end)

t.case('distro vendor with linux but no distro needs the platform', function()
  local sc = platform_scanner({})
  t.eq(sc.evaluate_platform({ plat(0, 'o', 'suse') },
    { family = 'linux' }), 'requires_platform')
end)

t.case('generic linux vendor on linux is compatible', function()
  local sc = platform_scanner({})
  t.eq(sc.evaluate_platform({ plat(0, 'o', 'linux') },
    { family = 'linux' }), nil)
end)

t.case('known distro matches its platform vendor', function()
  local sc = platform_scanner({})
  t.eq(sc.evaluate_platform({ plat(0, 'o', 'canonical') },
    { family = 'linux', distro = 'ubuntu' }), nil)
end)

t.case('one compatible configuration clears the reason', function()
  local sc = platform_scanner({})
  local rows = { plat(0, 'o', 'microsoft'), plat(1, 'o', 'linux') }
  t.eq(sc.evaluate_platform(rows, { family = 'linux' }), nil)
end)

t.case('application-only configuration requires a component', function()
  local sc = platform_scanner({})
  t.eq(sc.evaluate_platform({ plat(0, 'a', 'apache') },
    { family = 'linux' }), 'requires_component')
end)

t.case('CVE without platform rows has no reason', function()
  local sc = platform_scanner({})
  t.eq(sc.evaluate_platform({}, {}), nil)
end)

t.case('add_platform_reasons stores reasons and keeps every CVE', function()
  local sc = platform_scanner({ conditions_table = true, platform = {
    { 'CVE-W', 0, 'o', 'microsoft', 'windows' },
    { 'CVE-N', 0, 'o', 'linux', 'linux' },
  } })
  local vulns = { ['CVE-W'] = {}, ['CVE-N'] = {}, ['CVE-U'] = {} }
  sc.add_platform_reasons(vulns, "'apache'", 'tomcat', { family = 'linux' })
  t.keys_eq(vulns, { 'CVE-W', 'CVE-N', 'CVE-U' })
  t.eq(vulns['CVE-W'].reasons, { 'platform_mismatch:windows' })
  t.eq(vulns['CVE-N'].reasons, {})
  t.eq(vulns['CVE-U'].reasons, {})
end)

t.case('database without conditions table gives no reasons, one warning',
  function()
    local rows = { { 'CVE-EXACT', '5.0', nil, '5.5', '*', 0, 0 } }
    local sc, logged = platform_scanner({ affected = rows,
      platform = { { 'CVE-EXACT', 0, 'o', 'microsoft', 'windows' } } })
    local ctx = { os = { family = 'linux' } }
    local host = { ip = '10.0.0.1' }
    local port = { number = 80, protocol = 'tcp', service = 'http' }
    local cpe = 'cpe:/a:apache:tomcat:5.5'
    local first = sc.vulnerabilities(host, port, cpe, 'apache', 'tomcat',
      info_of('5.5'), ctx)
    local second = sc.vulnerabilities(host, port, cpe, 'apache', 'tomcat',
      info_of('5.5'), ctx)
    t.eq(first[1], 1)
    t.eq(second[1], 1)
    local warnings = 0
    for _, line in ipairs(logged) do
      if line:find('conditions table', 1, true) then
        warnings = warnings + 1
      end
    end
    t.eq(warnings, 1)
    local vulns = { ['CVE-EXACT'] = {} }
    sc.add_platform_reasons(vulns, "'apache'", 'tomcat', { family = 'linux' })
    t.eq(vulns['CVE-EXACT'].reasons, {})
  end)

t.suite('confidence reasons')

t.case('exact_version: same version and update in the NVD row', function()
  local rows = { { id = 'EV', version = '4.7', version_update = 'p1' } }
  t.eq(exact(rows, '4.7', nil, 'p1').EV.reasons, { 'exact_version' })
end)

t.case('update_unknown: concrete NVD update, observed update unknown',
  function()
    local rows = { { id = 'UU', version = '4.7', version_update = 'p2' } }
    t.eq(exact(rows, '4.7', nil, '*').UU.reasons, { 'update_unknown' })
  end)

t.case('range_contains: NVD interval holds the observed version', function()
  t.eq(multi({ heartbleed }, '1.0.1b').R1.reasons, { 'range_contains' })
end)

t.case('range_overlap: NVD interval overlaps only part of the range',
  function()
    local rows = { { id = 'IN', StartInc = '2.4.10', EndExc = '2.4.20' } }
    t.eq(multi(rows, '2.4.0', '2.4.9999999999').IN.reasons,
      { 'range_overlap' })
  end)

t.case('nvd_unbounded: NVD row without any bound', function()
  t.eq(multi({ { id = 'R4' } }, '0.1').R4.reasons, { 'nvd_unbounded' })
end)

t.case('series_expanded replaces the reasons of merged CVEs', function()
  local vulns = {}
  s.merge_series({ NEW = { reasons = { 'range_contains' } } }, vulns)
  t.eq(vulns.NEW.reasons, { 'series_expanded' })
end)

t.case('observed_range: a wide scan marks every CVE low', function()
  local range = { ver = nil, vup = nil, from = '5.0.0',
    to = '5.9.9999999999', empty = false, range = true }
  local n, _, meta = scan({ children = false, affected = rows }, range)
  t.truthy(n > 0, 'the range must match at least one CVE')
  t.eq(meta.summary.low, n)
  t.eq(meta.summary.high, 0)
end)

t.case('observed_range: narrow range is not marked', function()
  local range = { ver = nil, vup = nil, from = '5.5.0',
    to = '5.5.9999999999', empty = false, range = true }
  local n, _, meta = scan({ children = false, affected = rows }, range)
  t.truthy(n > 0, 'the range must match at least one CVE')
  t.eq(meta.summary.low, 0)
end)

t.case('platform reasons are appended to the existing reasons', function()
  local sc, _ = platform_scanner({ conditions_table = true, platform = {
    { 'CVE-W', 0, 'o', 'microsoft', 'windows' },
    { 'CVE-U', 0, 'o', 'suse', 'suse' },
  } })
  local vulns = {
    ['CVE-W'] = { reasons = { 'range_overlap' } },
    ['CVE-U'] = { reasons = { 'exact_version' } },
  }
  sc.add_platform_reasons(vulns, "'apache'", 'tomcat', { family = 'linux' })
  t.eq(vulns['CVE-W'].reasons,
    { 'range_overlap', 'platform_mismatch:windows' })
  t.eq(vulns['CVE-U'].reasons, { 'exact_version', 'requires_platform' })
end)

t.case('confidence_of takes the lowest level of the reasons', function()
  t.eq(s.confidence_of({}), 'high')
  t.eq(s.confidence_of({ 'exact_version', 'range_contains' }), 'high')
  t.eq(s.confidence_of({ 'exact_version', 'requires_platform' }), 'medium')
  t.eq(s.confidence_of({ 'requires_component' }), 'medium')
  t.eq(s.confidence_of({ 'update_unknown', 'observed_range' }), 'low')
  t.eq(s.confidence_of({ 'series_expanded' }), 'medium')
  t.eq(s.confidence_of({ 'nvd_unbounded' }), 'low')
  t.eq(s.confidence_of({ 'range_overlap' }), 'medium')
  t.eq(s.confidence_of({ 'platform_mismatch:windows' }), 'low')
end)

t.case('range_overlap with platform_mismatch is low', function()
  t.eq(s.confidence_of({ 'range_overlap', 'platform_mismatch:windows' }),
    'low')
end)

t.suite('confidence summary')

t.case('exact scan counts one high CVE', function()
  local _, _, meta = scan({ children = false, affected = rows }, info_of('5.5'))
  t.eq(meta.summary, { high = 1, medium = 0, low = 0 })
end)

t.case('series expansion counts the children as medium', function()
  local _, _, meta = scan({ children = true, affected = rows }, info_of('5.5'))
  t.eq(meta.summary, { high = 1, medium = 2, low = 0 })
end)

t.case('distro_backport warning only when the context asks for it', function()
  local _, _, plain = scan({ children = false, affected = rows },
    info_of('5.5'))
  local _, _, backport = scan({ children = false, affected = rows },
    info_of('5.5'), { backport = true, os = {} })
  t.eq(plain.warnings, {})
  t.eq(backport.warnings, { 'distro_backport' })
end)

t.suite('confidence output')

-- Run vulnerabilities with script arguments; return output, meta, scanner.
local function scan_args(args, db, info, ctx)
  local sc = platform_scanner(db, args)
  local host = { ip = '10.0.0.1' }
  local port = { number = 80, protocol = 'tcp', service = 'http' }
  local out, meta = sc.vulnerabilities(host, port,
    'cpe:/a:apache:tomcat:5.5', 'apache', 'tomcat', info, ctx)
  return out, meta, sc
end

-- First service recorded in the JSON report of the fake scanner.
local function json_service(sc)
  return sc.registry.json_out['10.0.0.1'].ports['80/tcp'].services[1]
end

local range_info = { ver = nil, vup = nil, from = '5.0.0',
  to = '5.9.9999999999', empty = false, range = true }

t.case('minconf=medium hides low rows; count and JSON keep them', function()
  local out, meta, sc = scan_args({ minconf = 'medium' },
    { children = false, affected = rows }, range_info)
  t.truthy(out[1] > 0, 'the range must match at least one CVE')
  t.eq(#out, 1)
  t.eq(meta.shown, 0)
  t.eq(meta.summary.low, out[1])
  local count = 0
  for _ in pairs(json_service(sc).vulnerabilities.cves) do
    count = count + 1
  end
  t.eq(count, out[1])
end)

t.case('invalid minconf value behaves as low', function()
  local out, meta = scan_args({ minconf = 'bogus' },
    { children = false, affected = rows }, range_info)
  t.eq(meta.shown, out[1])
end)

t.case('rows sort by confidence before CVSS, with the label', function()
  local out, _, sc = scan_args({}, { children = true, affected = rows },
    info_of('5.5'))
  t.truthy(out[2]:find('CVE-EXACT', 1, true), 'high row first')
  t.truthy(out[2]:find('HIGH', 1, true))
  t.truthy(out[3]:find('MED', 1, true), 'medium rows after')
  local cves = json_service(sc).vulnerabilities.cves
  t.eq(cves['CVE-CHILD'].confidence, 'medium')
  t.eq(cves['CVE-CHILD'].reasons, { 'series_expanded' })
end)

t.case('maxcve limits rows after the confidence sort', function()
  local out = scan_args({ maxcve = '1' }, { children = true, affected = rows },
    info_of('5.5'))
  t.eq(#out, 2)
  t.truthy(out[2]:find('CVE-EXACT', 1, true))
end)

t.case('JSON service carries version source and confidence summary', function()
  local out, meta, sc = scan_args({}, { children = true, affected = rows },
    info_of('5.5'), { version_source = 'nmap_cpe', os = {} })
  t.eq(meta.version_source, 'nmap_cpe')
  local service = json_service(sc)
  t.eq(service.version_source, 'nmap_cpe')
  t.eq(service.summary, { high = 1, medium = 2, low = 0 })
  t.eq(service.warnings, {})
end)

t.case('cpe_parser returns where the version came from', function()
  local _, _, _, from_version = s.cpe_parser('cpe:/a:apache:tomcat:5.5',
    '5.5.20')
  t.eq(from_version, 'nmap_version')
  local _, _, _, from_cpe = s.cpe_parser('cpe:/a:apache:tomcat:5.5', nil)
  t.eq(from_cpe, 'nmap_cpe')
end)

t.suite('version source')

-- Run analysis for one version found under the given matches origin.
local function analysis_source(origin, cpe, version)
  local sc = platform_scanner({ children = false, affected = rows }, {})
  sc.registry.cache = {}
  local matches = { data = { nmap = {}, http = {}, smb = {} }, size = 0 }
  sc.add_cpe_version(cpe, version, matches, origin)
  local host = { ip = '10.0.0.1' }
  local port = { number = 80, protocol = 'tcp', service = 'http' }
  sc.analysis(host, port, matches, { os = {} })
  return json_service(sc).version_source
end

t.case('version found only by an HTTP probe is reported as http', function()
  t.eq(analysis_source('http', 'cpe:/a:apache:tomcat:5.5', '5.5'), 'http')
end)

t.case('version found by SMB is reported as smb', function()
  t.eq(analysis_source('smb', 'cpe:/a:apache:tomcat:5.5', '5.5'), 'smb')
end)

t.case('version found by Nmap keeps the cpe_parser source', function()
  local cpe = 'cpe:/a:apache:tomcat:5.5'
  local _, _, _, expected = s.cpe_parser(cpe, '5.5')
  t.eq(analysis_source('nmap', cpe, '5.5'), expected)
end)
