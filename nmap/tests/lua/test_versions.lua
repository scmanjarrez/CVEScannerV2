-- SPDX-License-Identifier: GPL-3.0-or-later
-- Version comparison, version parsing, and CPE parsing.

local t = require 'harness'
local s = t.load_scanner()

t.suite('compare_version')

local ordered = {
  { '1.2.3', '1.2.3', 0 },
  { '1.2', '1.2.0', 0 },
  { '1.10', '1.9', 1 },
  { '2.4.7', '2.4.10', -1 },
  { '4.7p1', '4.7p2', -1 },
  { '4.7p1', '4.7', 1 },
  { '7.4p10', '7.4p9', 1 },
  { '1.0rc1', '1.0', -1 },
  { '1.0', '1.0rc1', 1 },
  { '1.0rc1', '1.0rc2', -1 },
  { '1.0beta2', '1.0', -1 },
  { '1.0.1e', '1.0.1g', -1 },
  { '1.0.1g', '1.0.1e', 1 },
  { '5.5.20', '5.5.21', -1 },
  { '-', '-', 0 },
  { '*', '*', 0 },
}
for _, row in ipairs(ordered) do
  t.case(string.format('%s vs %s = %d', row[1], row[2], row[3]), function()
    t.eq(s.compare_version(row[1], row[2]), row[3])
  end)
end

t.case('non-numeric versions are not comparable', function()
  t.eq(s.compare_version('abc', '1.0'), nil)
  t.eq(s.compare_version('1.0', 'abc'), nil)
  t.eq(s.compare_version(nil, '1.0'), nil)
  t.eq(s.compare_version('*', '1.0'), nil)
end)

t.case('OpenSSL letter release 1.0.1a is newer than 1.0.1', function()
  t.eq(s.compare_version('1.0.1', '1.0.1a'), -1)
  t.eq(s.compare_version('1.0.1b', '1.0.1'), 1)
  t.eq(s.compare_version('0.9.8a', '0.9.8b'), -1)
end)

t.case('build suffix -log equals the base version', function()
  t.eq(s.compare_version('5.5.20-log', '5.5.20'), 0)
end)

t.case('distro suffix -3ubuntu5 does not change ordering', function()
  t.eq(s.compare_version('5.0.51a-3ubuntu5', '5.0.51a'), 0)
end)

t.suite('version_parser')

local function parse(version, update)
  local _, info = s.version_parser('product', version, update)
  return info
end

t.case('plain version', function()
  t.eq(parse('2.4.7'), { ver = '2.4.7', vup = '*', empty = false,
    range = false })
end)

t.case('update embedded in version', function()
  local info = parse('4.7p1')
  t.eq({ info.ver, info.vup }, { '4.7', 'p1' })
end)

t.case('CPE update overrides the version suffix', function()
  local info = parse('4.7', 'p1')
  t.eq({ info.ver, info.vup }, { '4.7', 'p1' })
end)

t.case('missing, empty and wildcard versions are unknown', function()
  t.eq(parse(nil).empty, true)
  t.eq(parse('').empty, true)
  t.eq(parse('*').empty, true)
end)

t.case('NA version is kept as a concrete value', function()
  local info = parse('-')
  t.eq({ info.ver, info.vup, info.empty }, { '-', '-', false })
end)

t.case('Nmap version range', function()
  local info = parse('3.X - 4.X')
  t.eq({ info.range, info.from, info.to }, { true, '3.X', '4.X' })
end)

t.case('trailing x wildcard becomes a range', function()
  local info = parse('2.4.x')
  t.eq({ info.range, info.from, info.to },
    { true, '2.4.0', '2.4.9999999999' })
end)

t.case('Nmap for_windows_ marker is removed', function()
  t.eq(parse('for_windows_7.1').ver, '7.1')
end)

t.case('build suffix -log is not part of the version', function()
  local info = parse('5.5.20-log')
  t.eq({ info.ver, info.vup }, { '5.5.20', '*' })
end)

t.case('distro suffix is dropped from the update field', function()
  local info = parse('5.0.51a-3ubuntu5')
  t.eq({ info.ver, info.vup }, { '5.0.51', 'a' })
end)

t.case('leading v prefix is accepted', function()
  local info = parse('v1.2.3')
  t.eq({ info.empty, info.ver }, { false, '1.2.3' })
end)

t.suite('split_cpe / cpe_parser')

t.case('CPE 2.2 URI', function()
  local _, offset, kind, vendor, product, version, update =
      s.split_cpe('cpe:/a:apache:http_server:2.4.7')
  t.eq({ offset, kind, vendor, product, version, update },
    { 2, 'a', 'apache', 'http_server', '2.4.7', '' })
end)

t.case('CPE 2.3 formatted string', function()
  local _, offset, kind, vendor, product, version, update =
      s.split_cpe('cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*')
  t.eq({ offset, kind, vendor, product, version, update },
    { 3, 'a', 'openbsd', 'openssh', '7.4', 'p1' })
end)

t.case('escaped colon stays inside the field', function()
  local _, _, _, vendor, product = s.split_cpe('cpe:2.3:a:acme:a\\:b:1.0')
  t.eq({ vendor, product }, { 'acme', 'a:b' })
end)

t.case('non-CPE strings are rejected', function()
  t.eq(s.split_cpe('foo:bar'), nil)
  t.eq(s.cpe_parser('foo:bar', '1.0'), nil)
end)

t.case('CPE version wins over the Nmap version string', function()
  local vendor, product, info = s.cpe_parser(
    'cpe:/a:openbsd:openssh:4.7p1', '4.7p1 Debian 8ubuntu1')
  t.eq({ vendor, product, info.ver, info.vup },
    { 'openbsd', 'openssh', '4.7', 'p1' })
end)

t.case('Nmap version fills a CPE without version', function()
  local _, _, info = s.cpe_parser('cpe:/a:apache:http_server', '2.2.8')
  t.eq({ info.ver, info.vup, info.empty }, { '2.2.8', '*', false })
end)

t.case('CPE 2.3 update is used', function()
  local _, _, info = s.cpe_parser('cpe:2.3:a:openbsd:openssh:7.4:p1', '')
  t.eq({ info.ver, info.vup }, { '7.4', 'p1' })
end)

t.case('Nmap version range beats a CPE without patch level', function()
  local _, _, info, source = s.cpe_parser(
    'cpe:/a:postgresql:postgresql:8.3', '8.3.0 - 8.3.7')
  t.eq({ info.range, info.from, info.to, source },
    { true, '8.3.0', '8.3.7', 'nmap_version' })
end)

t.case('more specific Nmap version extends the CPE version', function()
  local _, _, info, source = s.cpe_parser(
    'cpe:/a:postgresql:postgresql:8.3', '8.3.5')
  t.eq({ info.ver, source }, { '8.3.5', 'nmap_version' })
end)

t.case('equal CPE and Nmap versions keep the CPE source', function()
  local _, _, info, source = s.cpe_parser(
    'cpe:/a:apache:http_server:2.2.8', '2.2.8')
  t.eq({ info.ver, source }, { '2.2.8', 'nmap_cpe' })
end)

t.case('wildcard CPE version takes the Nmap version', function()
  local _, _, info, source = s.cpe_parser('cpe:/a:x:y:*', '1.0')
  t.eq({ info.ver, source }, { '1.0', 'nmap_version' })
end)

t.case('empty Nmap version keeps the CPE source', function()
  local _, _, info, source = s.cpe_parser(
    'cpe:/a:apache:http_server:2.4.7', '')
  t.eq({ info.ver, source }, { '2.4.7', 'nmap_cpe' })
end)

t.suite('match bookkeeping')

local function new_matches()
  return { data = { nmap = {}, http = {} }, size = 0 }
end

t.case('add_cpe_version strips a trailing dot and deduplicates', function()
  local matches = new_matches()
  s.add_cpe_version('cpe:/a:x:y', '1.2.', matches, 'http')
  s.add_cpe_version('cpe:/a:x:y', '1.2', matches, 'http')
  t.eq(matches.size, 1)
  t.truthy(matches.data.http['cpe:/a:x:y']['1.2'])
end)

t.case('product aliases add an alternative CPE', function()
  local scanner = t.load_scanner()
  scanner.registry.aliases = { iis = { 'internet_information_services' } }
  local matches = new_matches()
  scanner.add_cpe_aliases('cpe:/a:microsoft:iis:7.5', '7.5', matches, 'nmap')
  t.truthy(matches.data.nmap[
    'cpe:/a:microsoft:internet_information_services:7.5']['7.5'])
end)

t.case('correct_version renders ranges', function()
  t.eq({ s.correct_version({ range = true, from = '1', to = '2' }) },
    { '1 - 2', '*' })
  t.eq({ s.correct_version({ range = false, ver = '1', vup = 'p1' }) },
    { '1', 'p1' })
end)

t.suite('os_context / distro_backport')

local function os_scanner()
  local scanner = t.load_scanner()
  scanner.registry.platform_families = {
    linux = 'linux',
    microsoft = 'windows',
  }
  return scanner
end

t.case('CPE o: vendor maps to a platform family', function()
  local scanner = os_scanner()
  local port = { version = { cpe = { 'cpe:/o:linux:linux_kernel' } } }
  t.eq(scanner.os_context({ ip = '10.0.0.1' }, port),
    { family = 'linux', source = 'cpe' })
end)

t.case('ostype Windows maps to windows', function()
  local scanner = os_scanner()
  local port = { version = { ostype = 'Windows' } }
  t.eq(scanner.os_context({ ip = '10.0.0.2' }, port),
    { family = 'windows', source = 'ostype' })
end)

t.case('extrainfo Ubuntu gives linux with distro ubuntu', function()
  local scanner = os_scanner()
  local port = { version = { extrainfo = 'Ubuntu' } }
  t.eq(scanner.os_context({ ip = '10.0.0.3' }, port),
    { family = 'linux', distro = 'ubuntu', source = 'extrainfo' })
end)

t.case('no OS data gives an empty context', function()
  local scanner = os_scanner()
  t.eq(scanner.os_context({ ip = '10.0.0.4' }, { version = {} }), {})
  t.eq(scanner.os_context({ ip = '10.0.0.4' }, {}), {})
end)

t.case('host.os first match gives the family and is cached per IP', function()
  local scanner = os_scanner()
  local host = { ip = '10.0.0.5', os = {
    { cpe = { 'cpe:/o:microsoft:windows_10' } },
  } }
  t.eq(scanner.os_context(host, { version = {} }),
    { family = 'windows', source = 'host_os' })
  t.eq(scanner.registry.host_os['10.0.0.5'], 'windows')
end)

t.case('host.os classes give the family from osfamily and cpe', function()
  local scanner = os_scanner()
  local host = { ip = '10.0.0.6', os = { { classes = {
    { osfamily = 'Linux', cpe = { 'cpe:/o:linux:linux_kernel:2.6' } },
  } } } }
  t.eq(scanner.os_context(host, { version = {} }),
    { family = 'linux', source = 'host_os' })
end)

t.case('ostype Unix is not a family without host.os', function()
  local scanner = os_scanner()
  local port = { version = { ostype = 'Unix' } }
  t.eq(scanner.os_context({ ip = '10.0.0.7' }, port), {})
end)

t.case('distro backport detects distro package suffixes', function()
  local port = { version = { version = '4.7p1 Debian 8ubuntu1' } }
  t.eq(t.load_scanner().distro_backport(port), true)
  t.eq(t.load_scanner().distro_backport(
    { version = { version = '2.2.8' } }), false)
end)
