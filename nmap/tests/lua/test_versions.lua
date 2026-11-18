-- SPDX-License-Identifier: GPL-3.0-or-later
-- Version comparison, version parsing, and CPE parsing.

local t = require 'harness'
local s = t.load_scanner()

t.suite('compare_version')

local ordered = {
  { '1.2.3',    '1.2.3',  0 },
  { '1.2',      '1.2.0',  0 },
  { '1.10',     '1.9',    1 },
  { '2.4.7',    '2.4.10', -1 },
  { '4.7p1',    '4.7p2',  -1 },
  { '4.7p1',    '4.7',    1 },
  { '7.4p10',   '7.4p9',  1 },
  { '1.0rc1',   '1.0',    -1 },
  { '1.0',      '1.0rc1', 1 },
  { '1.0rc1',   '1.0rc2', -1 },
  { '1.0beta2', '1.0',    -1 },
  { '1.0.1e',   '1.0.1g', -1 },
  { '1.0.1g',   '1.0.1e', 1 },
  { '5.5.20',   '5.5.21', -1 },
  { '-',        '-',      0 },
  { '*',        '*',      0 },
}
for _, row in ipairs(ordered) do
  t.case(string.format('%s vs %s = %d', row[1], row[2], row[3]), function()
    t.eq(s.modules.version.compare_version(row[1], row[2]), row[3])
  end)
end

t.case('non-numeric versions are not comparable', function()
  t.eq(s.modules.version.compare_version('abc', '1.0'), nil)
  t.eq(s.modules.version.compare_version('1.0', 'abc'), nil)
  t.eq(s.modules.version.compare_version(nil, '1.0'), nil)
  t.eq(s.modules.version.compare_version('*', '1.0'), nil)
end)

t.case('OpenSSL letter release 1.0.1a is newer than 1.0.1', function()
  t.eq(s.modules.version.compare_version('1.0.1', '1.0.1a'), -1)
  t.eq(s.modules.version.compare_version('1.0.1b', '1.0.1'), 1)
  t.eq(s.modules.version.compare_version('0.9.8a', '0.9.8b'), -1)
end)

t.case('build suffix -log equals the base version', function()
  t.eq(s.modules.version.compare_version('5.5.20-log', '5.5.20'), 0)
end)

t.case('distro suffix -3ubuntu5 does not change ordering', function()
  t.eq(s.modules.version.compare_version('5.0.51a-3ubuntu5', '5.0.51a'), 0)
end)

t.suite('parse_nmap_version')

local function parse(version, update)
  local _, info = s.modules.version.parse_nmap_version('product', version, update)
  return info
end

t.case('plain version', function()
  t.eq(parse('2.4.7'), {
    version = '2.4.7',
    update = '*',
    matches_any = false,
    is_range = false
  })
end)

t.case('update embedded in version', function()
  local info = parse('4.7p1')
  t.eq({ info.version, info.update }, { '4.7', 'p1' })
end)

t.case('CPE update overrides the version suffix', function()
  local info = parse('4.7', 'p1')
  t.eq({ info.version, info.update }, { '4.7', 'p1' })
end)

t.case('missing, empty and wildcard versions are unknown', function()
  t.eq(parse(nil).matches_any, true)
  t.eq(parse('').matches_any, true)
  t.eq(parse('*').matches_any, true)
end)

t.case('NA version is kept as a concrete value', function()
  local info = parse('-')
  t.eq({ info.version, info.update, info.matches_any }, { '-', '-', false })
end)

t.case('Nmap version range', function()
  local info = parse('3.X - 4.X')
  t.eq({ info.is_range, info.from, info.to }, { true, '3.X', '4.X' })
end)

t.case('trailing x wildcard becomes a range', function()
  local info = parse('2.4.x')
  t.eq({ info.is_range, info.from, info.to },
    { true, '2.4.0', '2.4.9999999999' })
end)

t.case('Nmap for_windows_ marker is removed', function()
  t.eq(parse('for_windows_7.1').version, '7.1')
end)

t.case('build suffix -log is not part of the version', function()
  local info = parse('5.5.20-log')
  t.eq({ info.version, info.update }, { '5.5.20', '*' })
end)

t.case('distro suffix is dropped from the update field', function()
  local info = parse('5.0.51a-3ubuntu5')
  t.eq({ info.version, info.update }, { '5.0.51', 'a' })
end)

t.case('leading v prefix is accepted', function()
  local info = parse('v1.2.3')
  t.eq({ info.matches_any, info.version }, { false, '1.2.3' })
end)

t.suite('split_cpe / parse_cpe_version')

t.case('CPE 2.2 URI', function()
  local _, offset, kind, vendor, product, version, update =
      s.modules.cpe.split_cpe('cpe:/a:apache:http_server:2.4.7')
  t.eq({ offset, kind, vendor, product, version, update },
    { 2, 'a', 'apache', 'http_server', '2.4.7', '' })
end)

t.case('CPE 2.3 formatted string', function()
  local _, offset, kind, vendor, product, version, update =
      s.modules.cpe.split_cpe('cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*')
  t.eq({ offset, kind, vendor, product, version, update },
    { 3, 'a', 'openbsd', 'openssh', '7.4', 'p1' })
end)

t.case('escaped colon stays inside the field', function()
  local _, _, _, vendor, product =
      s.modules.cpe.split_cpe('cpe:2.3:a:acme:a\\:b:1.0')
  t.eq({ vendor, product }, { 'acme', 'a:b' })
end)

t.case('non-CPE strings are rejected', function()
  t.eq(s.modules.cpe.split_cpe('foo:bar'), nil)
  t.eq(s.modules.version.parse_cpe_version('foo:bar', '1.0'), nil)
end)

t.case('CPE version wins over the Nmap version string', function()
  local vendor, product, info = s.modules.version.parse_cpe_version(
    'cpe:/a:openbsd:openssh:4.7p1', '4.7p1 Debian 8ubuntu1')
  t.eq({ vendor, product, info.version, info.update },
    { 'openbsd', 'openssh', '4.7', 'p1' })
end)

t.case('Nmap version fills a CPE without version', function()
  local _, _, info = s.modules.version.parse_cpe_version('cpe:/a:apache:http_server',
    '2.2.8')
  t.eq({ info.version, info.update, info.matches_any }, { '2.2.8', '*', false })
end)

t.case('CPE 2.3 update is used', function()
  local _, _, info =
      s.modules.version.parse_cpe_version('cpe:2.3:a:openbsd:openssh:7.4:p1', '')
  t.eq({ info.version, info.update }, { '7.4', 'p1' })
end)

t.case('Nmap version range beats a CPE without patch level', function()
  local _, _, info, source = s.modules.version.parse_cpe_version(
    'cpe:/a:postgresql:postgresql:8.3', '8.3.0 - 8.3.7')
  t.eq({ info.is_range, info.from, info.to, source },
    { true, '8.3.0', '8.3.7', 'nmap_version' })
end)

t.case('more specific Nmap version extends the CPE version', function()
  local _, _, info, source = s.modules.version.parse_cpe_version(
    'cpe:/a:postgresql:postgresql:8.3', '8.3.5')
  t.eq({ info.version, source }, { '8.3.5', 'nmap_version' })
end)

t.case('equal CPE and Nmap versions keep the CPE source', function()
  local _, _, info, source = s.modules.version.parse_cpe_version(
    'cpe:/a:apache:http_server:2.2.8', '2.2.8')
  t.eq({ info.version, source }, { '2.2.8', 'nmap_cpe' })
end)

t.case('wildcard CPE version takes the Nmap version', function()
  local _, _, info, source = s.modules.version.parse_cpe_version('cpe:/a:x:y:*',
    '1.0')
  t.eq({ info.version, source }, { '1.0', 'nmap_version' })
end)

t.case('empty Nmap version keeps the CPE source', function()
  local _, _, info, source = s.modules.version.parse_cpe_version(
    'cpe:/a:apache:http_server:2.4.7', '')
  t.eq({ info.version, source }, { '2.4.7', 'nmap_cpe' })
end)

t.suite('match bookkeeping')

local function new_match_table()
  return { data = { nmap = {}, http = {} }, size = 0 }
end

t.case('add_cpe_version strips a trailing dot and deduplicates', function()
  local matches = new_match_table()
  s.modules.match_table.add_cpe_version('cpe:/a:x:y', '1.2.', matches, 'http')
  s.modules.match_table.add_cpe_version('cpe:/a:x:y', '1.2', matches, 'http')
  t.eq(matches.size, 1)
  t.truthy(matches.data.http['cpe:/a:x:y']['1.2'])
end)

t.case('product aliases add an alternative CPE', function()
  local scanner = t.load_scanner()
  scanner.modules.state.product_aliases = { iis = { 'internet_information_services' } }
  local matches = new_match_table()
  scanner.modules.match_table.add_cpe_aliases('cpe:/a:microsoft:iis:7.5', '7.5',
    matches, 'nmap')
  t.truthy(matches.data.nmap[
  'cpe:/a:microsoft:internet_information_services:7.5']['7.5'])
end)

t.case('display_version renders ranges', function()
  t.eq({ s.modules.version.display_version({
      is_range = true,
      from = '1',
      to = '2'
    }) },
    { '1 - 2', '*' })
  t.eq({ s.modules.version.display_version({
      is_range = false,
      version = '1',
      update = 'p1'
    }) },
    { '1', 'p1' })
end)

t.suite('os_context / distro_backport')

local function os_scanner()
  local scanner = t.load_scanner()
  scanner.modules.state.platform_families = {
    linux = 'linux',
    microsoft = 'windows',
  }
  return scanner
end

t.case('CPE o: vendor maps to a platform family', function()
  local scanner = os_scanner()
  local port = { version = { cpe = { 'cpe:/o:linux:linux_kernel' } } }
  t.eq(scanner.modules.os_context.os_context({ ip = '10.0.0.1' }, port),
    { family = 'linux', source = 'cpe' })
end)

t.case('ostype Windows maps to windows', function()
  local scanner = os_scanner()
  local port = { version = { ostype = 'Windows' } }
  t.eq(scanner.modules.os_context.os_context({ ip = '10.0.0.2' }, port),
    { family = 'windows', source = 'ostype' })
end)

t.case('extrainfo Ubuntu gives linux with distro ubuntu', function()
  local scanner = os_scanner()
  local port = { version = { extrainfo = 'Ubuntu' } }
  t.eq(scanner.modules.os_context.os_context({ ip = '10.0.0.3' }, port),
    { family = 'linux', distro = 'ubuntu', source = 'extrainfo' })
end)

t.case('no OS data gives an empty context', function()
  local scanner = os_scanner()
  t.eq(scanner.modules.os_context.os_context({ ip = '10.0.0.4' },
    { version = {} }), {})
  t.eq(scanner.modules.os_context.os_context({ ip = '10.0.0.4' }, {}), {})
end)

t.case('host.os first match gives the family and is cached per IP', function()
  local scanner = os_scanner()
  local host = {
    ip = '10.0.0.5',
    os = {
      { cpe = { 'cpe:/o:microsoft:windows_10' } },
    }
  }
  t.eq(scanner.modules.os_context.os_context(host, { version = {} }),
    { family = 'windows', source = 'host_os' })
  t.eq(scanner.modules.state.host_os_family['10.0.0.5'], 'windows')
end)

t.case('host.os classes give the family from osfamily and cpe', function()
  local scanner = os_scanner()
  local host = {
    ip = '10.0.0.6',
    os = { {
      classes = {
        { osfamily = 'Linux', cpe = { 'cpe:/o:linux:linux_kernel:2.6' } },
      }
    } }
  }
  t.eq(scanner.modules.os_context.os_context(host, { version = {} }),
    { family = 'linux', source = 'host_os' })
end)

t.case('ostype Unix is not a family without host.os', function()
  local scanner = os_scanner()
  local port = { version = { ostype = 'Unix' } }
  t.eq(scanner.modules.os_context.os_context({ ip = '10.0.0.7' }, port), {})
end)

t.case('distro backport detects distro package suffixes', function()
  local port = { version = { version = '4.7p1 Debian 8ubuntu1' } }
  t.eq(t.load_scanner().modules.os_context.distro_backport(port), true)
  t.eq(t.load_scanner().modules.os_context.distro_backport(
    { version = { version = '2.2.8' } }), false)
end)

t.suite('compare_version cache')

local cache_pairs = {
  { '1.2.3',             '1.2.3',  0 },
  { '1.2',               '1.2.0',  0 },
  { '1.0',               '1.0.0',  0 },
  { '1.0.1',             '1.0.1a', -1 },
  { '1.0.1e',            '1.0.1g', -1 },
  { '1.10',              '1.9',    1 },
  { '2.2.8',             '2.2.10', -1 },
  { '2.4.7',             '2.4.10', -1 },
  { '4.7p1',             '4.7p2',  -1 },
  { '4.7p1',             '4.7',    1 },
  { '7.4p10',            '7.4p9',  1 },
  { '5.2.4-2ubuntu5.10', '5.2.4',  0 },
  { '5.5.20-log',        '5.5.20', 0 },
  { '1.0rc1',            '1.0',    -1 },
  { '1.0',               '1.0rc1', 1 },
  { '1.0rc1',            '1.0rc2', -1 },
  { '1.0beta2',          '1.0',    -1 },
  { '0.9.8a',            '0.9.8b', -1 },
  { '-',                 '-',      0 },
  { '*',                 '*',      0 },
  { 'abc',               '1.0',    nil },
  { '1.0',               'abc',    nil },
  { '-',                 '1.0',    nil },
  { nil,                 '1.0',    nil },
  { '1.0',               nil,      nil },
}

local function mismatches(compare)
  local bad = {}
  for _, row in ipairs(cache_pairs) do
    local got = compare(row[1], row[2])
    if got ~= row[3] then
      table.insert(bad, string.format('%s vs %s: got %s',
        tostring(row[1]), tostring(row[2]), tostring(got)))
    end
  end
  return bad
end

t.case('cold and warm cache give the same results', function()
  local compare = s.modules.version.compare_version
  t.eq(mismatches(compare), {})
  t.eq(mismatches(compare), {})
end)

t.suite('version_scope reason strength')

-- Scope one NVD row against a range, adding into an existing result.
local function scope_range(row, from, to, result)
  s.modules.version_scope.scoped_multi_versions({ row }, from, to, result,
    false)
end

-- Scope one NVD row as an exact version, adding into an existing result.
local function scope_exact(row, version, result)
  s.modules.version_scope.scoped_versions({ row }, version, version, '*',
    result)
end

t.case('strongest range reason wins regardless of row order', function()
  local row = { id = 'C1', StartInc = '1.0', EndExc = '2.0' }
  local overlap = { '1.5', '3.0' }
  local contains = { '1.5', '1.8' }

  local a = {}
  scope_range(row, overlap[1], overlap[2], a)
  scope_range(row, contains[1], contains[2], a)

  local b = {}
  scope_range(row, contains[1], contains[2], b)
  scope_range(row, overlap[1], overlap[2], b)

  t.eq(a.C1.reasons, { 'range_contains' })
  t.eq(b.C1.reasons, { 'range_contains' })
end)

t.case('exact version beats unbounded range in either order', function()
  local row = { id = 'C2', version = '1.0' }

  local a = {}
  s.modules.version_scope.scoped_multi_versions({ { id = 'C2' } }, '1.0',
    '1.0', a, true)
  scope_exact(row, '1.0', a)

  local b = {}
  scope_exact(row, '1.0', b)
  s.modules.version_scope.scoped_multi_versions({ { id = 'C2' } }, '1.0',
    '1.0', b, true)

  t.eq(a.C2.reasons, { 'exact_version' })
  t.eq(b.C2.reasons, { 'exact_version' })
end)

t.case('tie keeps the existing reason', function()
  local row = { id = 'C3', StartInc = '1.0', EndExc = '2.0' }
  local result = {}
  scope_range(row, '1.5', '3.0', result)
  scope_range(row, '1.2', '3.0', result)
  t.eq(result.C3.reasons, { 'range_overlap' })
end)

t.case('exact row inside an observed range does not beat range_overlap', function()
  local overlap_row = { id = 'C4', StartInc = '2.0', EndExc = '2.4.8' }
  local exact_row = { id = 'C4', version = '2.4.5' }
  local from, to = '2.4.0', '2.4.10'

  local a = {}
  s.modules.version_scope.scoped_multi_versions({ overlap_row }, from, to, a,
    false)
  s.modules.version_scope.scoped_versions({ exact_row }, from, to, '*', a)

  local b = {}
  s.modules.version_scope.scoped_versions({ exact_row }, from, to, '*', b)
  s.modules.version_scope.scoped_multi_versions({ overlap_row }, from, to, b,
    false)

  t.eq(a.C4.reasons, { 'range_overlap' })
  t.eq(b.C4.reasons, { 'range_overlap' })
end)

t.suite('compare_version cache')

t.case('results stay correct after the cache is reset', function()
  local compare = s.modules.version.compare_version
  t.eq(mismatches(compare), {})
  for i = 1, 25000 do
    compare('9.' .. i, '9.' .. i + 1)
  end
  t.eq(mismatches(compare), {})
  t.eq(compare('2.2.8', '2.2.10'), -1)
end)

t.suite('mssql_build')

local MSSQL = 'cpe:/a:microsoft:sql_server:2014'

t.load_scanner()
local mssql_build = require 'cvescannerv2.mssql_build'

local function refine(cpe, version)
  return mssql_build.refine(cpe, version)
end

t.case('2014 SP3 build maps to sp3', function()
  t.eq(refine(MSSQL, '12.00.6329'), { 'cpe:/a:microsoft:sql_server:2014:sp3' })
end)

t.case('2014 SP1 and RTM builds', function()
  t.eq(refine(MSSQL, '12.00.4100'), { 'cpe:/a:microsoft:sql_server:2014:sp1' })
  t.eq(refine(MSSQL, '12.00.2000'), { MSSQL })
end)

t.case('2016 SP3 keeps the SP CPE and the build CPE', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2016', '13.00.6300'), {
    'cpe:/a:microsoft:sql_server:2016:sp3',
    'cpe:/a:microsoft:sql_server_2016:13.0.6300',
  })
end)

t.case('2016 RTM build keeps the original CPE and the build CPE', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2016', '13.00.1601'), {
    'cpe:/a:microsoft:sql_server:2016',
    'cpe:/a:microsoft:sql_server_2016:13.0.1601',
  })
end)

t.case('2019 keeps the original CPE and the build CPE', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2019', '15.00.4003'), {
    'cpe:/a:microsoft:sql_server:2019',
    'cpe:/a:microsoft:sql_server_2019:15.0.4003',
  })
end)

t.case('2017 keeps the original CPE and the build CPE', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2017', '14.00.3465'), {
    'cpe:/a:microsoft:sql_server:2017',
    'cpe:/a:microsoft:sql_server_2017:14.0.3465',
  })
end)

t.case('2008 R2 SP1 build', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2008', '10.50.2500'), {
    'cpe:/a:microsoft:sql_server:2008:r2_sp1',
  })
end)

t.case('4 component version with suffix keeps the revision in the build CPE', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2019', '15.00.2000.00; RTM'), {
    'cpe:/a:microsoft:sql_server:2019',
    'cpe:/a:microsoft:sql_server_2019:15.0.2000.0',
  })
  t.eq(refine(MSSQL, '12.00.4100.00; SP1'), {
    'cpe:/a:microsoft:sql_server:2014:sp1',
  })
end)

t.case('4 component version without suffix keeps the revision', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2016', '13.00.6300.2'), {
    'cpe:/a:microsoft:sql_server:2016:sp3',
    'cpe:/a:microsoft:sql_server_2016:13.0.6300.2',
  })
end)

t.case('malformed build suffixes are left unchanged', function()
  t.eq(refine(MSSQL, '12.00.6329x'), { MSSQL })
  t.eq(refine(MSSQL, '12.00'), { MSSQL })
end)

t.case('CPE with update is left unchanged', function()
  local cpe = 'cpe:/a:microsoft:sql_server:2014:sp1'
  t.eq(refine(cpe, '12.00.6329'), { cpe })
end)

t.case('CPE with update keeps the build CPE when the release has one', function()
  local cpe = 'cpe:/a:microsoft:sql_server:2016:sp3'
  t.eq(refine(cpe, '13.00.6300'), {
    cpe,
    'cpe:/a:microsoft:sql_server_2016:13.0.6300',
  })
end)

t.case('CPE wildcard update is refined like an unset update', function()
  t.eq(refine(MSSQL .. ':*', '12.00.6329'), {
    'cpe:/a:microsoft:sql_server:2014:sp3',
  })
end)

t.case('other vendor is left unchanged', function()
  local cpe = 'cpe:/a:oracle:sql_server:2014'
  t.eq(refine(cpe, '12.00.6329'), { cpe })
end)

t.case('versions that are not build numbers are left unchanged', function()
  t.eq(refine(MSSQL, '2014'), { MSSQL })
  t.eq(refine(MSSQL, '12.00'), { MSSQL })
  t.eq(refine(MSSQL, nil), { MSSQL })
end)

t.case('refine does not mutate its input and is repeatable', function()
  local first = refine(MSSQL, '12.00.6329')
  local second = refine(MSSQL, '12.00.6329')
  t.eq(first, second)
  t.eq(MSSQL, 'cpe:/a:microsoft:sql_server:2014')
end)

t.case('CPE year that does not match the build is replaced', function()
  local expected = {
    'cpe:/a:microsoft:sql_server:2022',
    'cpe:/a:microsoft:sql_server_2022:16.0.1000',
  }
  t.eq(refine('cpe:/a:microsoft:sql_server:2019', '16.00.1000'), expected)
  t.eq(refine('cpe:/a:microsoft:sql_server:2019', '16.00.1000.0; RTM'), {
    'cpe:/a:microsoft:sql_server:2022',
    'cpe:/a:microsoft:sql_server_2022:16.0.1000.0',
  })
end)

t.case('CPE update is ignored when its year does not match', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2019:sp1', '16.00.1000'), {
    'cpe:/a:microsoft:sql_server:2022',
    'cpe:/a:microsoft:sql_server_2022:16.0.1000',
  })
end)

t.case('CPE year that does not match a release with service packs', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2014', '13.00.6300'), {
    'cpe:/a:microsoft:sql_server:2016:sp3',
    'cpe:/a:microsoft:sql_server_2016:13.0.6300',
  })
end)

t.case('CPE year that matches the build is kept', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2019', '15.00.4003'), {
    'cpe:/a:microsoft:sql_server:2019',
    'cpe:/a:microsoft:sql_server_2019:15.0.4003',
  })
end)

t.case('CPE without product version is refined as before', function()
  t.eq(refine('cpe:/a:microsoft:sql_server', '12.00.6329'), {
    'cpe:/a:microsoft:sql_server:2014:sp3',
  })
end)

t.case('CPE 2.3 year that does not match the build is replaced', function()
  t.eq(refine('cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*',
    '16.00.1000'), {
    'cpe:/a:microsoft:sql_server:2022',
    'cpe:/a:microsoft:sql_server_2022:16.0.1000',
  })
end)

t.case('2008 R2 update is kept only for an R2 build', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:2008:r2_sp1', '10.50.2500'), {
    'cpe:/a:microsoft:sql_server:2008:r2_sp1',
  })
  t.eq(refine('cpe:/a:microsoft:sql_server:2008:sp1', '10.50.2500'), {
    'cpe:/a:microsoft:sql_server:2008:r2_sp1',
  })
  t.eq(refine('cpe:/a:microsoft:sql_server:2008:r2_sp1', '10.00.2531'), {
    'cpe:/a:microsoft:sql_server:2008:sp1',
  })
end)

t.case('mismatched year refinement is repeatable', function()
  local cpe = 'cpe:/a:microsoft:sql_server:2019'
  local first = refine(cpe, '16.00.1000')
  t.eq(refine(cpe, '16.00.1000'), first)
  t.eq(cpe, 'cpe:/a:microsoft:sql_server:2019')
end)

t.case('overflowing version components return the CPE unchanged', function()
  for _, version in ipairs({
    '999999999999999999999999.0.1',
    '13.00.6300.99999999999999999999',
    '13.99999999999999999999.1',
    '13.00.99999999999999999999',
  }) do
    local ok, result = pcall(refine, 'cpe:/a:microsoft:sql_server:2016',
      version)
    t.eq(ok, true, 'refine raised for ' .. version)
    t.eq(result, { 'cpe:/a:microsoft:sql_server:2016' }, version)
  end
end)

t.case('overflowing version components keep an unversioned CPE', function()
  for _, version in ipairs({
    '999999999999999999999999.0.1',
    '13.00.6300.99999999999999999999',
    '13.99999999999999999999.1',
  }) do
    local ok, result = pcall(refine, 'cpe:/a:microsoft:sql_server', version)
    t.eq(ok, true, 'refine raised for ' .. version)
    t.eq(result, { 'cpe:/a:microsoft:sql_server' }, version)
  end
end)

t.case('leading zeros and long build numbers do not raise', function()
  local ok, result = pcall(refine, MSSQL, '0')
  t.eq(ok, true)
  t.eq(result, { MSSQL })
  ok, result = pcall(refine, MSSQL, '00000013.00.06300')
  t.eq(ok, true)
  t.eq(result, {
    'cpe:/a:microsoft:sql_server:2016:sp3',
    'cpe:/a:microsoft:sql_server_2016:13.0.6300',
  })
  ok, result = pcall(refine, 'cpe:/a:microsoft:sql_server:2016',
    '13.00.' .. string.rep('9', 30))
  t.eq(ok, true)
  t.eq(result, { 'cpe:/a:microsoft:sql_server:2016' })
end)

t.case('unversioned CPE gets the release year and the build CPE', function()
  local expected = {
    'cpe:/a:microsoft:sql_server:2019',
    'cpe:/a:microsoft:sql_server_2019:15.0.4003.23',
  }
  t.eq(refine('cpe:/a:microsoft:sql_server', '15.00.4003.23'), expected)
  t.eq(refine('cpe:/a:microsoft:sql_server:*', '15.00.4003.23'), expected)
  t.eq(refine('cpe:/a:microsoft:sql_server:-', '15.00.4003.23'), expected)
end)

t.case('unversioned CPE with a build reaching a service pack', function()
  t.eq(refine('cpe:/a:microsoft:sql_server', '12.00.6329'), {
    'cpe:/a:microsoft:sql_server:2014:sp3',
  })
  t.eq(refine('cpe:/a:microsoft:sql_server', '12.00.2000'), {
    'cpe:/a:microsoft:sql_server:2014',
  })
  t.eq(refine('cpe:/a:microsoft:sql_server', '10.50.2500'), {
    'cpe:/a:microsoft:sql_server:2008:r2_sp1',
  })
end)

t.case('unversioned 2.3 CPE gets the release year', function()
  t.eq(refine('cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*',
    '16.00.1000'), {
    'cpe:/a:microsoft:sql_server:2022',
    'cpe:/a:microsoft:sql_server_2022:16.0.1000',
  })
end)

t.case('unversioned CPE keeps a coherent update', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:-:sp1', '12.00.6329'), {
    'cpe:/a:microsoft:sql_server:2014:sp1',
  })
end)

t.case('unversioned CPE drops an update not matching the release', function()
  t.eq(refine('cpe:/a:microsoft:sql_server:-:r2_sp1', '10.00.2531'), {
    'cpe:/a:microsoft:sql_server:2008:sp1',
  })
end)
