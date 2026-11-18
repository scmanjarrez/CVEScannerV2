-- SPDX-License-Identifier: GPL-3.0-or-later
-- Version scoping against NVD rows, CVSS ordering, and SQL formatting.

local t = require 'harness'
local fixture = require 'fixture'
local s = t.load_scanner()

-- Real luasql module for the database cases; nil when it is not installed.
local sqlite = fixture.load_sqlite()

-- Run a database case, or skip it when luasql.sqlite3 is not installed.
local function db_case(name, fn)
  if sqlite then
    t.case(name, fn)
  else
    t.skip(name, 'luasql.sqlite3 is not installed')
  end
end

-- Run scoped_multi_versions for one observed version or range.
local function multi(rows, from, to, unknown)
  local result = {}
  s.modules.version_scope.scoped_multi_versions(rows, from, to or from, result,
    unknown)
  return result
end

-- Run scoped_versions for one observed version, update, or range.
local function exact(rows, from, to, observed_update)
  local result = {}
  s.modules.version_scope.scoped_versions(rows, from, to or from,
    observed_update or '*', result)
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
    { id = 'IN',  StartInc = '2.4.10', EndExc = '2.4.20' },
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
    { id = 'P1',  version = '4.7', version_update = 'p1' },
    { id = 'P2',  version = '4.7', version_update = 'p2' },
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
    { id = 'IN',  version = '4.7p1', version_update = '*' },
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
    { id = 'IN',  version = '2.4.7', version_update = '*' },
    { id = 'OUT', version = '2.2.8', version_update = '*' },
  }
  t.keys_eq(exact(rows, '2.4.0', '2.4.9999999999'), { 'IN' })
end)

t.case('exact 5.5.20 matches the observed 5.5.20-log', function()
  local rows = { { id = 'E', version = '5.5.20', version_update = '*' } }
  t.keys_eq(exact(rows, '5.5.20-log'), { 'E' })
end)

t.case('letter release split by the parser still matches exactly', function()
  -- parse_nmap_version turns 1.0.1a into version=1.0.1, update=a.
  local rows = { { id = 'A', version = '1.0.1a', version_update = '*' } }
  t.keys_eq(exact(rows, '1.0.1', nil, 'a'), { 'A' })
  t.keys_eq(exact(rows, '1.0.1', nil, 'b'), {})
end)

t.suite('cvss_comparator')

t.case('sort by main score (v4, v3, v2), then id', function()
  local rows = {
    { id = 'CVE-A', cvss = { v3 = 5.0 } },
    { id = 'CVE-B', cvss = { v3 = 10.0 } },
    { id = 'CVE-F', cvss = { v2 = 9.8 } },
    { id = 'CVE-E', cvss = { v3 = 7.5 } },
    { id = 'CVE-C', cvss = { v2 = 7.5 } },
    { id = 'CVE-D', cvss = {} },
    { id = 'CVE-G', cvss = { v4 = 9.3, v3 = 2.0 } },
  }
  table.sort(rows, s.modules.confidence.cvss_comparator)
  local order = {}
  for _, row in ipairs(rows) do table.insert(order, row.id) end
  t.eq(order, { 'CVE-B', 'CVE-F', 'CVE-G', 'CVE-C', 'CVE-E', 'CVE-A',
    'CVE-D' })
end)

t.case('numeric, not lexicographic, comparison', function()
  t.truthy(s.modules.confidence.cvss_comparator(
    { id = 'X', cvss = { v3 = 10.0 } }, { id = 'Y', cvss = { v3 = 9.0 } }))
end)

t.suite('SQL formatting')

t.case('format_sql_named escapes single quotes', function()
  t.eq((s.modules.util.format_sql_named("p = '${p}'", { p = "o'reilly" })),
    "p = 'o''reilly'")
end)

t.case('format_sql_named renders missing values as nil', function()
  t.eq((s.modules.util.format_sql_named("v = '${v}'", {})), "v = 'nil'")
end)

t.case('product queries are scoped by vendor', function()
  for _, name in ipairs({ 'exact_affected', 'range_affected',
    'range_affected_unbounded' }) do
    t.truthy(s.modules.db.sql_template(name):find("vendor IN (${v})", 1, true),
      name .. ' must filter by vendor')
  end
end)

t.suite('two-part series expansion')

-- Temporary database files, removed at the end of the file.
local PATHS = {}

-- Build the fixture spec for the apache tomcat rows described by db.
-- db.affected rows: CVE, CVSSv2, CVSSv3, version, update, edb, msf.
-- db.platform rows: CVE, config index, part, vendor, product.
-- db.children adds a 5.5.x product row, as a real database would have.
local function spec_of(db)
  local spec = { cves = {}, products = {}, affected = {} }
  spec.legacy_cves = db.legacy_cves
  local ids = {}
  local function product(version, update)
    local key = version .. '|' .. update
    if ids[key] == nil then
      ids[key] = #spec.products + 1
      table.insert(spec.products,
        { ids[key], 'apache', 'tomcat', version, update })
    end
    return ids[key]
  end
  -- Product 1 is the base row that conditions rows reference.
  local base = product('*', '*')
  for _, row in ipairs(db.affected or {}) do
    -- row[8] is the optional CVSSv4 score of the CVE.
    table.insert(spec.cves, { row[1], row[2], row[3], 2000, row[8] })
    table.insert(spec.affected, { row[1], product(row[4], row[5]) })
  end
  if db.children then product('5.5.3', '*') end
  if db.conditions_table then
    spec.conditions = {}
    for _, row in ipairs(db.platform or {}) do
      table.insert(spec.conditions,
        { row[1], base, row[2], row[3], row[4], row[5] })
    end
  end
  return spec
end

-- Create a database for db and return the env and conn of an open copy.
local function connect(db)
  if sqlite == nil then return nil, nil end
  local path = fixture.create(spec_of(db), sqlite)
  table.insert(PATHS, path)
  return fixture.open(path, sqlite)
end

-- Install a real database and return the result for one observed info.
local function scan(db, info, scan_ctx)
  local reg = s.modules.state
  reg.db_env, reg.db_conn = connect(db)
  reg.log_file = { write = function() end }
  local host = { ip = '10.0.0.1' }
  local port = { number = 80, protocol = 'tcp', service = 'http' }
  return s.modules.service_cves.find_service_cves(host, port,
    'cpe:/a:apache:tomcat:5.5', 'apache', 'tomcat', info, scan_ctx)
end

-- CVE ids of a result, in result order.
local function ids_of(result)
  local ids = {}
  for _, cve in ipairs(result.cves) do table.insert(ids, cve.id) end
  return ids
end

-- Entry of one CVE in a result, or nil when it is not there.
local function entry_of(result, id)
  for _, cve in ipairs(result.cves) do
    if cve.id == id then return cve end
  end
  return nil
end

-- Confidence counters of a result as a table.
local function summary_of(result)
  return {
    high = result.counts.high,
    medium = result.counts.medium,
    low = result.counts.low
  }
end

local function info_of(ver)
  return {
    version = ver,
    update = '*',
    from = nil,
    to = nil,
    matches_any = false,
    is_range = false
  }
end

local rows = {
  { 'CVE-EXACT', '5.0', nil, '5.5',   '*', 0, 0 },
  { 'CVE-CHILD', '5.0', nil, '5.5.3', '*', 0, 0 },
  { 'CVE-LATER', '5.0', nil, '5.5.4', '*', 0, 0 },
}

-- Without child versions in the database, series expansion finds nothing.
local EXACT = { rows[1] }

db_case('series 5.5 expands to children when the database has them', function()
  local result = scan({ children = true, affected = rows }, info_of('5.5'))
  t.eq(result.counts.total, 3)
  t.truthy(entry_of(result, 'CVE-LATER'))
end)

db_case('series 5.5 without children keeps the exact match only', function()
  local result = scan({ children = false, affected = EXACT }, info_of('5.5'))
  t.eq(ids_of(result), { 'CVE-EXACT' })
end)

db_case('specific version 5.5.3 is not expanded', function()
  local result = scan({ children = true, affected = rows }, info_of('5.5.3'))
  t.eq(result.counts.total, 1)
end)

db_case('Nmap range is not changed by series expansion', function()
  local info = {
    version = nil,
    update = nil,
    from = '5.5.0',
    to = '5.5.9999999999',
    matches_any = false,
    is_range = true
  }
  local without = scan({ children = false, affected = rows }, info)
  local with = scan({ children = true, affected = rows }, info)
  t.eq(ids_of(with), ids_of(without))
end)

t.case('series_prefix accepts only x.y without update', function()
  t.eq(s.modules.version.series_prefix(info_of('5.5')), '5.5')
  t.eq(s.modules.version.series_prefix(info_of('5.5.3')), nil)
  t.eq(s.modules.version.series_prefix({
    version = '5.5',
    update = 'sp1',
    matches_any = false,
    is_range = false
  }), nil)
  t.eq(s.modules.version.series_prefix({
    version = nil,
    update = nil,
    matches_any = false,
    is_range = true
  }), nil)
end)

db_case('series_has_children reads the EXISTS result', function()
  s.modules.state.db_env, s.modules.state.db_conn = connect({ children = true })
  t.truthy(s.modules.db.series_has_children({ 'apache' }, 'tomcat', '5.5'))
  s.modules.state.db_env, s.modules.state.db_conn = connect({ children = false })
  t.eq(s.modules.db.series_has_children({ 'apache' }, 'tomcat', '5.5'), false)
end)

t.case('merge_series marks added CVEs and keeps existing ones', function()
  local vulns = { KEEP = { CVSSV2 = '1.0' } }
  s.modules.version_scope.merge_series({
    KEEP = { CVSSV2 = '9.9' },
    NEW = { CVSSV2 = '5.0' },
  }, vulns)
  t.eq(vulns.KEEP.CVSSV2, '1.0')
  t.eq(vulns.KEEP.series_expanded, nil)
  t.eq(vulns.NEW.series_expanded, true)
end)

t.suite('platform conditions')

local FAMILIES = {
  linux = 'linux',
  suse = 'linux',
  canonical = 'linux',
  redhat = 'linux',
  microsoft = 'windows',
  freebsd = 'bsd',
  openbsd = 'bsd',
}

-- Fresh scanner with platform families, a fake database and a log list.
local function platform_scanner(db, args)
  local sc = t.load_scanner({ args = args, sql = sqlite })
  local logged = {}
  sc.modules.state.platform_families = FAMILIES
  sc.modules.state.db_env, sc.modules.state.db_conn = connect(db)
  sc.modules.state.log_file = {
    write = function(_, msg) table.insert(logged, msg) end,
  }
  return sc, logged
end

-- One platform row of a CVE configuration.
local function plat(config_idx, part, vendor)
  return {
    config_idx = config_idx,
    part = part,
    vendor = vendor,
    product = 'x'
  }
end

t.case('AND Windows CVE with linux context is a platform mismatch', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'microsoft') },
    { family = 'linux' }), 'platform_mismatch:windows')
end)

t.case('same family, other distro names the required vendor', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'redhat') },
    { family = 'linux', distro = 'ubuntu' }), 'platform_mismatch:redhat')
end)

t.case('other family names the required family', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'microsoft') },
    { family = 'linux', distro = 'ubuntu' }), 'platform_mismatch:windows')
end)

t.case('unknown context gives requires_platform', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'microsoft') },
      {}),
    'requires_platform')
end)

t.case('distro vendor with linux but no distro needs the platform', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'suse') },
    { family = 'linux' }), 'requires_platform')
end)

t.case('generic linux vendor on linux is compatible', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'linux') },
    { family = 'linux' }), nil)
end)

t.case('known distro matches its platform vendor', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'canonical') },
    { family = 'linux', distro = 'ubuntu' }), nil)
end)

t.case('one compatible configuration clears the reason', function()
  local sc = platform_scanner({})
  local plat_rows = { plat(0, 'o', 'microsoft'), plat(1, 'o', 'linux') }
  t.eq(sc.modules.platform_match.evaluate_platform(plat_rows,
    { family = 'linux' }), nil)
end)

t.case('application-only configuration requires a component', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'a', 'apache') },
    { family = 'linux' }), 'requires_component')
end)

t.case('sole vendor of its family needs no distro (microsoft on windows)', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'microsoft') },
    { family = 'windows' }), nil)
end)

t.case('linux distro vendor without distro needs the platform', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'suse') },
    { family = 'linux' }), 'requires_platform')
end)

t.case('bsd vendor without distro needs the platform (several vendors)', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({ plat(0, 'o', 'freebsd') },
    { family = 'bsd' }), 'requires_platform')
end)

t.case('OS row AND application row on compatible host requires component', function()
  local sc = platform_scanner({})
  local platform_rows = { plat(0, 'o', 'linux'), plat(0, 'a', 'otra') }
  t.eq(sc.modules.platform_match.evaluate_platform(platform_rows,
    { family = 'linux' }), 'requires_component')
end)

t.case('CVE without platform rows has no reason', function()
  local sc = platform_scanner({})
  t.eq(sc.modules.platform_match.evaluate_platform({}, {}), nil)
end)

db_case('add_platform_reasons stores reasons and keeps every CVE', function()
  local sc = platform_scanner({
    conditions_table = true,
    platform = {
      { 'CVE-W', 0, 'o', 'microsoft', 'windows' },
      { 'CVE-N', 0, 'o', 'linux',     'linux' },
    }
  })
  local vulns = { ['CVE-W'] = {}, ['CVE-N'] = {}, ['CVE-U'] = {} }
  sc.modules.service_cves.add_platform_reasons(vulns, { 'apache' }, 'tomcat',
    { family = 'linux' })
  t.keys_eq(vulns, { 'CVE-W', 'CVE-N', 'CVE-U' })
  t.eq(vulns['CVE-W'].reasons, { 'platform_mismatch:windows' })
  t.eq(vulns['CVE-N'].reasons, {})
  t.eq(vulns['CVE-U'].reasons, {})
end)

db_case('database without conditions table gives no reasons, one warning',
  function()
    local exact_rows = { { 'CVE-EXACT', '5.0', nil, '5.5', '*', 0, 0 } }
    local sc, logged = platform_scanner({
      affected = exact_rows,
      platform = { { 'CVE-EXACT', 0, 'o', 'microsoft', 'windows' } }
    })
    local scan_ctx = { os = { family = 'linux' } }
    local host = { ip = '10.0.0.1' }
    local port = { number = 80, protocol = 'tcp', service = 'http' }
    local cpe = 'cpe:/a:apache:tomcat:5.5'
    local first = sc.modules.service_cves.find_service_cves(host, port,
      cpe, 'apache', 'tomcat', info_of('5.5'), scan_ctx)
    local second = sc.modules.service_cves.find_service_cves(host, port,
      cpe, 'apache', 'tomcat', info_of('5.5'), scan_ctx)
    t.eq(first.counts.total, 1)
    t.eq(second.counts.total, 1)
    local warnings = 0
    for _, line in ipairs(logged) do
      if line:find('conditions table', 1, true) then
        warnings = warnings + 1
      end
    end
    t.eq(warnings, 1)
    local vulns = { ['CVE-EXACT'] = {} }
    sc.modules.service_cves.add_platform_reasons(vulns, { 'apache' }, 'tomcat',
      { family = 'linux' })
    t.eq(vulns['CVE-EXACT'].reasons, {})
  end)

t.suite('confidence reasons')

t.case('exact_version: same version and update in the NVD row', function()
  local exact_rows = { { id = 'EV', version = '4.7', version_update = 'p1' } }
  t.eq(exact(exact_rows, '4.7', nil, 'p1').EV.reasons, { 'exact_version' })
end)

t.case('update_unknown: concrete NVD update, observed update unknown',
  function()
    local uu_rows = { { id = 'UU', version = '4.7', version_update = 'p2' } }
    t.eq(exact(uu_rows, '4.7', nil, '*').UU.reasons, { 'update_unknown' })
  end)

t.case('range_contains: NVD interval holds the observed version', function()
  t.eq(multi({ heartbleed }, '1.0.1b').R1.reasons, { 'range_contains' })
end)

t.case('range_overlap: NVD interval overlaps only part of the range',
  function()
    local range_rows = { { id = 'IN', StartInc = '2.4.10', EndExc = '2.4.20' } }
    t.eq(multi(range_rows, '2.4.0', '2.4.9999999999').IN.reasons,
      { 'range_overlap' })
  end)

t.case('nvd_unbounded: NVD row without any bound', function()
  t.eq(multi({ { id = 'R4' } }, '0.1').R4.reasons, { 'nvd_unbounded' })
end)

t.case('series_expanded replaces the reasons of merged CVEs', function()
  local vulns = {}
  s.modules.version_scope.merge_series({ NEW = { reasons = { 'range_contains' } } },
    vulns)
  t.eq(vulns.NEW.reasons, { 'series_expanded' })
end)

db_case('observed_range: a wide scan marks every CVE low', function()
  local range = {
    version = nil,
    update = nil,
    from = '5.0.0',
    to = '5.9.9999999999',
    matches_any = false,
    is_range = true
  }
  local result = scan({ children = false, affected = rows }, range)
  t.truthy(result.counts.total > 0, 'the range must match at least one CVE')
  t.eq(result.counts.low, result.counts.total)
  t.eq(result.counts.high, 0)
end)

db_case('observed_range: narrow range is not marked', function()
  local range = {
    version = nil,
    update = nil,
    from = '5.5.0',
    to = '5.5.9999999999',
    matches_any = false,
    is_range = true
  }
  local result = scan({ children = false, affected = rows }, range)
  t.truthy(result.counts.total > 0, 'the range must match at least one CVE')
  t.eq(result.counts.low, 0)
end)

db_case('platform reasons are appended to the existing reasons', function()
  local sc, _ = platform_scanner({
    conditions_table = true,
    platform = {
      { 'CVE-W', 0, 'o', 'microsoft', 'windows' },
      { 'CVE-U', 0, 'o', 'suse',      'suse' },
    }
  })
  local vulns = {
    ['CVE-W'] = { reasons = { 'range_overlap' } },
    ['CVE-U'] = { reasons = { 'exact_version' } },
  }
  sc.modules.service_cves.add_platform_reasons(vulns, { 'apache' }, 'tomcat',
    { family = 'linux' })
  t.eq(vulns['CVE-W'].reasons,
    { 'range_overlap', 'platform_mismatch:windows' })
  t.eq(vulns['CVE-U'].reasons, { 'exact_version', 'requires_platform' })
end)

t.case('confidence_of takes the lowest level of the reasons', function()
  t.eq(s.modules.confidence.confidence_of({}), 'high')
  t.eq(s.modules.confidence.confidence_of({ 'exact_version',
    'range_contains' }), 'high')
  t.eq(s.modules.confidence.confidence_of({ 'exact_version',
    'requires_platform' }), 'medium')
  t.eq(s.modules.confidence.confidence_of({ 'requires_component' }), 'medium')
  t.eq(s.modules.confidence.confidence_of({ 'update_unknown',
    'observed_range' }), 'low')
  t.eq(s.modules.confidence.confidence_of({ 'series_expanded' }), 'medium')
  t.eq(s.modules.confidence.confidence_of({ 'nvd_unbounded' }), 'low')
  t.eq(s.modules.confidence.confidence_of({ 'range_overlap' }), 'medium')
  t.eq(s.modules.confidence.confidence_of({ 'platform_mismatch:windows' }),
    'low')
end)

t.case('range_overlap with platform_mismatch is low', function()
  t.eq(s.modules.confidence.confidence_of({ 'range_overlap',
      'platform_mismatch:windows' }),
    'low')
end)

t.suite('confidence summary')

db_case('exact scan counts one high CVE', function()
  local result = scan({ children = false, affected = EXACT }, info_of('5.5'))
  t.eq(summary_of(result), { high = 1, medium = 0, low = 0 })
end)

db_case('series expansion counts the children as medium', function()
  local result = scan({ children = true, affected = rows }, info_of('5.5'))
  t.eq(summary_of(result), { high = 1, medium = 2, low = 0 })
end)

db_case('distro_backport warning only when the context asks for it', function()
  local plain = scan({ children = false, affected = rows }, info_of('5.5'))
  local backport = scan({ children = false, affected = rows },
    info_of('5.5'), { backport = true, os = {} })
  t.eq(plain.warnings, {})
  t.eq(backport.warnings, { 'distro_backport' })
end)

t.suite('confidence output')

-- Run find_service_cves with script arguments; return the result and the
-- scanner, whose text_output module renders it.
local function scan_args(args, db, info, scan_ctx)
  local sc = platform_scanner(db, args)
  local host = { ip = '10.0.0.1' }
  local port = { number = 80, protocol = 'tcp', service = 'http' }
  local result = sc.modules.service_cves.find_service_cves(host, port,
    'cpe:/a:apache:tomcat:5.5', 'apache', 'tomcat', info, scan_ctx)
  return result, sc
end

-- Nmap table lines of a result, rendered with the given configuration.
local function render(sc, result, cfg)
  return table.concat(sc.modules.text_output.nmap_lines(result, cfg), '\n')
end

local range_info = {
  version = nil,
  update = nil,
  from = '5.0.0',
  to = '5.9.9999999999',
  matches_any = false,
  is_range = true
}

local ALL_LOW = { maxcve = 10, minconf = 'low', json = 'out.json' }

db_case('minconf=medium hides low rows; result keeps them', function()
  local result = scan_args({ minconf = 'medium' },
    { children = false, affected = rows }, range_info)
  t.truthy(result.counts.total > 0, 'the range must match at least one CVE')
  t.eq(#result.cves, result.counts.total)
  t.eq(result.counts.shown, 0)
  t.truthy(result.counts.shown < result.counts.total)
  t.eq(result.counts.low, result.counts.total)
end)

db_case('invalid minconf value behaves as medium', function()
  local result = scan_args({ minconf = 'bogus' },
    { children = false, affected = rows }, range_info)
  t.truthy(result.counts.total > 0)
  t.eq(result.counts.shown, 0)
end)

db_case('rows sort by confidence before CVSS, with the label', function()
  local result, sc = scan_args({}, { children = true, affected = rows },
    info_of('5.5'))
  t.eq(result.cves[1].id, 'CVE-EXACT', 'high row first')
  t.eq(result.cves[1].confidence, 'high')
  t.eq(result.cves[2].confidence, 'medium')
  t.eq(result.cves[3].confidence, 'medium', 'medium rows after')
  local text = render(sc, result, ALL_LOW)
  t.truthy(text:find('HIGH', 1, true))
  t.truthy(text:find('MED', 1, true))
  local child = entry_of(result, 'CVE-CHILD')
  assert(child, 'CVE-CHILD missing from result')
  t.eq(child.confidence, 'medium')
  t.eq(child.reasons, { 'series_expanded' })
end)

db_case('maxcve limits the printed rows, not the result', function()
  local result, sc = scan_args({}, { children = true, affected = rows },
    info_of('5.5'))
  t.eq(#result.cves, 3)
  local text = render(sc, result, {
    maxcve = 1,
    minconf = 'low',
    json = 'out.json'
  })
  t.truthy(text:find('CVE-EXACT', 1, true), 'high row printed')
  t.eq(text:find('CVE-CHILD', 1, true), nil)
end)

db_case('result carries version source and confidence counts', function()
  local result = scan_args({}, { children = true, affected = rows },
    info_of('5.5'), { version_source = 'nmap_cpe', os = {} })
  t.eq(result.version_source, 'nmap_cpe')
  t.eq(summary_of(result), { high = 1, medium = 2, low = 0 })
  t.eq(result.warnings, {})
end)

db_case('CVSSv4 9.3 alone ranks above CVSSv2 7.5 at equal confidence',
  function()
    local v4_rows = {
      { 'CVE-V2', '7.5', nil, '5.5', '*', 0, 0 },
      { 'CVE-V4', nil,   nil, '5.5', '*', 0, 0, '9.3' },
    }
    local result = scan({ children = false, affected = v4_rows },
      info_of('5.5'))
    t.eq(ids_of(result), { 'CVE-V4', 'CVE-V2' })
    t.eq(result.cves[1].cvss, { v4 = 9.3, v3 = nil, v2 = nil })
    t.eq(result.cves[2].cvss.v2, 7.5)
  end)

t.case('parse_cpe_version returns where the version came from', function()
  local _, _, _, from_version = s.modules.version.parse_cpe_version(
    'cpe:/a:apache:tomcat:5.5', '5.5.20')
  t.eq(from_version, 'nmap_version')
  local _, _, _, from_cpe =
      s.modules.version.parse_cpe_version('cpe:/a:apache:tomcat:5.5', nil)
  t.eq(from_cpe, 'nmap_cpe')
end)

t.suite('legacy databases')

db_case('database without cvss_v4 gives v4 nil and warns once', function()
  local sc, logged = platform_scanner({
    legacy_cves = true,
    affected = {
      { 'CVE-LEG', '7.5', nil, '5.5', '*', 0, 0, '9.3' },
    }
  })
  local host = { ip = '10.0.0.1' }
  local port = { number = 80, protocol = 'tcp', service = 'http' }
  local cpe = 'cpe:/a:apache:tomcat:5.5'
  local scan_ctx = { os = { family = 'linux' } }
  local first = sc.modules.service_cves.find_service_cves(host, port, cpe,
    'apache', 'tomcat', info_of('5.5'), scan_ctx)
  local second = sc.modules.service_cves.find_service_cves(host, port, cpe,
    'apache', 'tomcat', info_of('5.5'), scan_ctx)
  t.eq(first.cves[1].cvss.v4, nil)
  t.eq(first.cves[1].cvss.v2, 7.5)
  t.eq(second.cves[1].cvss.v4, nil)
  local warnings = 0
  for _, line in ipairs(logged) do
    if line:find('cvss_v4', 1, true) then warnings = warnings + 1 end
  end
  t.eq(warnings, 1)
end)

t.suite('version source')

-- Run analysis for one version found under the given matches origin and
-- return the version source of the cached service result.
local function analysis_source(origin, cpe, version)
  local sc = platform_scanner({ children = false, affected = rows }, {})
  sc.modules.state.service_cache = {}
  local matches = { data = { nmap = {}, http = {}, smb = {} }, size = 0 }
  sc.modules.match_table.add_cpe_version(cpe, version, matches, origin)
  local host = { ip = '10.0.0.1' }
  local port = { number = 80, protocol = 'tcp', service = 'http' }
  sc.modules.port_analysis.analyze_port(host, port, matches, { os = {} })
  for _, cached in pairs(sc.modules.state.service_cache) do
    return cached.result.version_source
  end
  return nil
end

db_case('version found only by an HTTP probe is reported as http', function()
  t.eq(analysis_source('http', 'cpe:/a:apache:tomcat:5.5', '5.5'), 'http')
end)

db_case('version found by SMB is reported as smb', function()
  t.eq(analysis_source('smb', 'cpe:/a:apache:tomcat:5.5', '5.5'), 'smb')
end)

db_case('version found by Nmap keeps the parse_cpe_version source', function()
  local cpe = 'cpe:/a:apache:tomcat:5.5'
  local _, _, _, expected = s.modules.version.parse_cpe_version(cpe, '5.5')
  t.eq(analysis_source('nmap', cpe, '5.5'), expected)
end)

db_case('port analysis output is stable across origin insertion orders', function()
  local cpe = 'cpe:/a:apache:tomcat:5.5'
  local origins = { 'http', 'nmap', 'zzz' }
  local baseline
  for run = 1, 20 do
    local sc = platform_scanner({ children = false, affected = rows }, {})
    sc.modules.state.service_cache = {}
    local matches = { data = {}, size = 0 }
    for i = 0, #origins - 1 do
      local origin = origins[(i + run) % #origins + 1]
      matches.data[origin] = {}
      sc.modules.match_table.add_cpe_version(cpe, '5.5', matches, origin)
    end
    local host = { ip = '10.0.0.1' }
    local port = { number = 80, protocol = 'tcp', service = 'http' }
    local structured, lines = sc.modules.port_analysis.analyze_port(host, port,
      matches, { os = {} })
    if baseline == nil then
      baseline = { structured = structured, lines = lines }
    end
    t.eq(structured, baseline.structured, 'structured rows, run ' .. run)
    t.eq(lines, baseline.lines, 'lines, run ' .. run)
  end
end)

-- Remove the temporary databases created by the database cases.
for _, path in ipairs(PATHS) do os.remove(path) end


t.suite('product aliases (renamed products)')

-- Database with Tomcat renamed from Catalina and a three-step chain.
local ALIAS_PRODUCTS = {
  { 1, 'apache', 'tomcat',   '5.5', '*' },
  { 2, 'apache', 'catalina', '5.5', '*' },
  { 3, 'apache', 'alpha',    '5.5', '*' },
  { 4, 'apache', 'beta',     '5.5', '*' },
  { 5, 'apache', 'gamma',    '5.5', '*' },
}

local function alias_spec(affected, aliases)
  local cves = {}
  local seen = {}
  for _, row in ipairs(affected) do
    if not seen[row[1]] then
      seen[row[1]] = true
      table.insert(cves, { row[1], '5.0', nil, 2000, nil })
    end
  end
  return {
    cves = cves,
    products = ALIAS_PRODUCTS,
    affected = affected,
    product_aliases = aliases,
  }
end

-- Scan product 5.5 against a fresh scanner and the given database spec.
local function alias_scan(spec, product)
  local sc = t.load_scanner({ sql = sqlite })
  local path = fixture.create(spec, sqlite)
  table.insert(PATHS, path)
  local reg = sc.modules.state
  reg.db_env, reg.db_conn = fixture.open(path, sqlite)
  reg.log_file = { write = function() end }
  return sc.modules.service_cves.find_service_cves({ ip = '10.0.0.1' },
    { number = 80, protocol = 'tcp', service = 'http' },
    'cpe:/a:apache:' .. product .. ':5.5', 'apache', product, info_of('5.5'),
    nil)
end

local RENAME = { { 'apache', 'catalina', 'apache', 'tomcat' } }

db_case('old product name finds the CVEs filed under the new name', function()
  local result = alias_scan(alias_spec({
    { 'CVE-OLD', 1 }, { 'CVE-NEW', 2 },
  }, RENAME), 'tomcat')
  -- High confidence first, then the alias match.
  t.eq(ids_of(result), { 'CVE-OLD', 'CVE-NEW' })
end)

db_case('alias CVEs get alias_product and medium confidence', function()
  local result = alias_scan(alias_spec({
    { 'CVE-OWN', 1 }, { 'CVE-ALIAS', 2 },
  }, RENAME), 'tomcat')
  t.eq(entry_of(result, 'CVE-OWN').confidence, 'high')
  local alias = entry_of(result, 'CVE-ALIAS')
  assert(alias, 'CVE-ALIAS missing')
  t.eq(alias.confidence, 'medium')
  t.eq(alias.reasons, { 'exact_version', 'alias_product' })
end)

db_case('forward lookup: renamed name finds CVEs of the new name', function()
  local result = alias_scan(alias_spec({
    { 'CVE-OWN', 2 }, { 'CVE-NEW', 1 },
  }, RENAME), 'catalina')
  t.eq(entry_of(result, 'CVE-OWN').confidence, 'high')
  t.eq(entry_of(result, 'CVE-NEW').confidence, 'medium')
end)

db_case('a CVE under both names keeps its own confidence', function()
  local result = alias_scan(alias_spec({
    { 'CVE-BOTH', 1 }, { 'CVE-BOTH', 2 },
  }, RENAME), 'tomcat')
  t.eq(result.counts.total, 1)
  t.eq(entry_of(result, 'CVE-BOTH').reasons, { 'exact_version' })
end)

db_case('forward lookup follows a chain of renames', function()
  local chain = {
    { 'apache', 'alpha', 'apache', 'beta' },
    { 'apache', 'beta',  'apache', 'gamma' },
  }
  local affected = { { 'CVE-A', 3 }, { 'CVE-B', 4 }, { 'CVE-C', 5 } }
  t.eq(ids_of(alias_scan(alias_spec(affected, chain), 'alpha')),
    { 'CVE-A', 'CVE-B', 'CVE-C' })
  -- Backwards only the previous name is searched, not the whole chain.
  t.eq(ids_of(alias_scan(alias_spec(affected, chain), 'gamma')),
    { 'CVE-C', 'CVE-B' })
end)

db_case('a database without product_aliases behaves as before', function()
  local result = alias_scan(alias_spec({
    { 'CVE-OWN', 1 }, { 'CVE-OTHER', 2 },
  }, nil), 'tomcat')
  t.eq(ids_of(result), { 'CVE-OWN' })
end)

t.case('merge_alias appends the reason and keeps existing CVEs', function()
  local vulns = { KEEP = { reasons = { 'exact_version' } } }
  s.modules.version_scope.merge_alias({
    KEEP = { reasons = { 'range_overlap' } },
    NEW = { reasons = { 'range_contains' } },
  }, vulns)
  t.eq(vulns.KEEP.reasons, { 'exact_version' })
  t.eq(vulns.NEW.reasons, { 'range_contains', 'alias_product' })
end)

t.case('alias_product lowers a high match to medium only', function()
  local confidence_of = s.modules.confidence.confidence_of
  t.eq(confidence_of({ 'exact_version', 'alias_product' }), 'medium')
  t.eq(confidence_of({ 'nvd_unbounded', 'alias_product' }), 'low')
end)

db_case('alias conditions apply only to CVEs found through the alias', function()
  local sc = t.load_scanner({ sql = sqlite })
  local reg = sc.modules.state
  reg.platform_families = FAMILIES
  reg.log_file = { write = function() end }
  local path = fixture.create({
    cves = {},
    products = ALIAS_PRODUCTS,
    affected = {},
    conditions = {
      { 'CVE-OWN',   2, 0, 'o', 'microsoft', 'windows' },
      { 'CVE-ALIAS', 2, 0, 'o', 'microsoft', 'windows' },
    },
    product_aliases = RENAME,
  }, sqlite)
  table.insert(PATHS, path)
  reg.db_env, reg.db_conn = fixture.open(path, sqlite)
  local vulns = {
    ['CVE-OWN'] = { reasons = { 'exact_version' } },
    ['CVE-ALIAS'] = { reasons = { 'exact_version', 'alias_product' } },
  }
  sc.modules.service_cves.add_platform_reasons(vulns, { 'apache' }, 'tomcat',
    { family = 'linux' })
  t.eq(vulns['CVE-OWN'].reasons, { 'exact_version' })
  t.eq(vulns['CVE-ALIAS'].reasons,
    { 'exact_version', 'alias_product', 'platform_mismatch:windows' })
end)

t.suite('mssql build refinement')

-- Temporary database files of the SQL Server cases, removed at the end.
local MSSQL_PATHS = {}

-- SQL Server products: 2014 sp1, sp3 and any update, a 2016 build product
-- with a 13.0.x range, a 2016 sp3 product, the 2019 year product and the
-- 2019 build product with a range, the 2022 year product and the 2022 build
-- product with a range.
local MSSQL_PRODUCTS = {
  { 1, 'microsoft', 'sql_server',      '2014', 'sp1' },
  { 2, 'microsoft', 'sql_server',      '2014', 'sp3' },
  { 3, 'microsoft', 'sql_server',      '2014', '*' },
  { 4, 'microsoft', 'sql_server_2016', '*',    '*' },
  { 5, 'microsoft', 'sql_server',      '2016', 'sp3' },
  { 6, 'microsoft', 'sql_server',      '2019', '*' },
  { 7, 'microsoft', 'sql_server_2019', '*',    '*' },
  { 8, 'microsoft', 'sql_server',      '2022', '*' },
  { 9, 'microsoft', 'sql_server_2022', '*',    '*' },
}

-- Database spec with one CVE per 2014 update, the 2016 range CVEs (the
-- 13.0.6300.2 edges, the sp3 CVE), the 2019 year and range CVEs, and the
-- 2022 year and range CVEs.
local function mssql_spec()
  local cves = {}
  for _, id in ipairs({ 'CVE-2014-SP1', 'CVE-2014-SP3', 'CVE-2014-ANY',
    'CVE-2016-RANGE', 'CVE-2016-SP3', 'CVE-2016-EDGE-START',
    'CVE-2016-EDGE-END', 'CVE-2019-YEAR', 'CVE-2019-RANGE',
    'CVE-2022-YEAR', 'CVE-2022-RANGE' }) do
    table.insert(cves, { id, '7.5', nil, 2000, nil })
  end
  return {
    cves = cves,
    products = MSSQL_PRODUCTS,
    affected = {
      { 'CVE-2014-SP1', 1 },
      { 'CVE-2014-SP3', 2 },
      { 'CVE-2014-ANY', 3 },
      { 'CVE-2016-SP3', 5 },
      { 'CVE-2019-YEAR', 6 },
      { 'CVE-2022-YEAR', 8 },
    },
    multiaffected = {
      { 'CVE-2016-RANGE', 4, nil, '13.0.0', nil, '13.1.0' },
      -- [13.0.6300.2, 13.0.6441.1)
      { 'CVE-2016-EDGE-START', 4, '13.0.6300.2', nil, nil, '13.0.6441.1' },
      -- [13.0.0, 13.0.6300.2)
      { 'CVE-2016-EDGE-END', 4, '13.0.0', nil, nil, '13.0.6300.2' },
      -- [15.0.4003.23, 15.0.4100.0)
      { 'CVE-2019-RANGE', 7, '15.0.4003.23', nil, nil, '15.0.4100.0' },
      -- [16.0.0.0, 16.0.4000.0)
      { 'CVE-2022-RANGE', 9, '16.0.0.0', nil, nil, '16.0.4000.0' },
    },
  }
end

-- Analyze one CPE and version as a port match and return the CVE ids of the
-- cached results, with the reasons of each CVE. service is the value of the
-- service script argument (nil keeps the default 'all').
local function mssql_found(cpe, version_str, service)
  local sc = t.load_scanner({ sql = sqlite, args = { service = service } })
  local path = fixture.create(mssql_spec(), sqlite)
  table.insert(MSSQL_PATHS, path)
  local reg = sc.modules.state
  reg.db_env, reg.db_conn = fixture.open(path, sqlite)
  reg.log_file = { write = function() end }
  reg.service_cache = {}
  local matches = { data = { nmap = {}, http = {}, smb = {} }, size = 0 }
  sc.modules.match_table.add_cpe_version(cpe, version_str, matches, 'nmap')
  local host = { ip = '10.0.0.1' }
  local port = { number = 1433, protocol = 'tcp', service = 'ms-sql-s' }
  sc.modules.port_analysis.analyze_port(host, port, matches, { os = {} })
  local found, reasons = {}, {}
  for _, cached in pairs(reg.service_cache) do
    for _, cve in ipairs(cached.result.cves) do
      found[cve.id] = true
      reasons[cve.id] = cve.reasons
    end
  end
  return found, reasons
end

db_case('2014 build 12.00.6329 keeps the sp3 and any-update CVEs only', function()
  local found, reasons = mssql_found('cpe:/a:microsoft:sql_server:2014',
    '12.00.6329')
  t.keys_eq(found, { 'CVE-2014-SP3', 'CVE-2014-ANY' })
  t.eq(reasons['CVE-2014-SP3'], { 'exact_version' })
end)

db_case('2016 build 13.00.6300 finds the sql_server_2016 range CVE', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server:2016', '13.00.6300')
  t.truthy(found['CVE-2016-RANGE'], 'CVE-2016-RANGE missing')
end)

db_case('D1: 4 component build keeps the inclusive start and drops the exclusive end', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server:2016', '13.00.6300.2')
  t.truthy(found['CVE-2016-EDGE-START'], 'inclusive start 13.0.6300.2 missing')
  t.eq(found['CVE-2016-EDGE-END'], nil, 'exclusive end 13.0.6300.2 matched')
end)

db_case('D2: year CPE with a 4 component build finds the year and the build range CVEs', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server:2019', '15.00.4003.23')
  t.keys_eq(found, { 'CVE-2019-YEAR', 'CVE-2019-RANGE' })
end)

db_case('D3: service=sql_server selects the year and the build product', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server:2019', '15.00.4003.23',
    'sql_server')
  t.keys_eq(found, { 'CVE-2019-YEAR', 'CVE-2019-RANGE' })
end)

db_case('D3: service=sql_server_2019 selects only the build product', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server:2019', '15.00.4003.23',
    'sql_server_2019')
  t.keys_eq(found, { 'CVE-2019-RANGE' })
end)

db_case('D4: sp3 CPE with a 4 component build finds the sp3 and the range CVEs', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server:2016:sp3', '13.00.6300.2')
  t.keys_eq(found, { 'CVE-2016-SP3', 'CVE-2016-RANGE', 'CVE-2016-EDGE-START' })
end)

db_case('D5: 2019 year CPE on a 2022 build keeps the 2022 CVEs only', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server:2019', '16.00.1000.00; RTM')
  t.keys_eq(found, { 'CVE-2022-YEAR', 'CVE-2022-RANGE' })
end)

db_case('D5: service=sql_server on a 2022 build selects the 2022 year and build CVEs', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server:2019', '16.00.1000.00; RTM',
    'sql_server')
  t.keys_eq(found, { 'CVE-2022-YEAR', 'CVE-2022-RANGE' })
end)

db_case('E2: CPE without year finds the year and the build range CVEs', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server', '15.00.4003.23')
  t.keys_eq(found, { 'CVE-2019-YEAR', 'CVE-2019-RANGE' })
end)

db_case('E2: CPE with * as year finds the year and the build range CVEs', function()
  local found = mssql_found('cpe:/a:microsoft:sql_server:*', '15.00.4003.23')
  t.keys_eq(found, { 'CVE-2019-YEAR', 'CVE-2019-RANGE' })
end)

db_case('E1: overflowing build or revision does not abort the port analysis', function()
  for _, version in ipairs({ '999999999999999999999999.0.1',
    '13.00.6300.99999999999999999999' }) do
    local ok, found = pcall(mssql_found, 'cpe:/a:microsoft:sql_server:2016', version)
    t.truthy(ok, 'analyze_port raised for ' .. version)
    t.eq(type(found), 'table', 'no result for ' .. version)
  end
end)

for _, path in ipairs(MSSQL_PATHS) do os.remove(path) end
