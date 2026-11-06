-- SPDX-License-Identifier: GPL-3.0-or-later
-- HTTP fingerprint catalogue validation and response matching.

local t = require 'harness'
local s = t.load_scanner()

local function new_match_table()
  return { data = { nmap = {}, http = {} }, size = 0 }
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

t.suite('pattern validation')

t.case('capture_count ignores escapes, classes and balances', function()
  t.eq(s.modules.validate.capture_count('(%d+)'), 1)
  t.eq(s.modules.validate.capture_count('%((%d+)%)'), 1)
  t.eq(s.modules.validate.capture_count('[(]x'), 0)
  t.eq(s.modules.validate.capture_count('(a)(b)'), 2)
  t.eq(s.modules.validate.capture_count('%b()'), 0)
  t.eq(s.modules.validate.capture_count('%f[%w](%d)'), 1)
end)

t.case('valid_pattern checks captures, syntax and size', function()
  t.truthy(s.modules.validate.valid_pattern('nginx/([%d.]+)', 1))
  t.eq(s.modules.validate.valid_pattern('nginx/([%d.]+)', 0), false)
  t.eq(s.modules.validate.valid_pattern('[a', 0), false)
  t.eq(s.modules.validate.valid_pattern('', 0), false)
  t.eq(s.modules.validate.valid_pattern(string.rep('a', 2049), 0), false)
end)

-- valid_pattern probes the pattern against an empty subject. Lua reports an
-- unfinished capture only when matching reaches the end of the pattern, so
-- the parentheses are counted explicitly in capture_count.
t.case('unbalanced capture is rejected', function()
  t.eq(s.modules.validate.valid_pattern('(%d+', 1), false)
end)

t.case('valid_alias accepts vendor:product CPEs only', function()
  t.truthy(s.modules.validate.valid_alias('cpe:/a:apache:http_server'))
  t.eq(s.modules.validate.valid_alias('cpe:/a:apache:http_server:2.4'), false)
  t.eq(s.modules.validate.valid_alias('cpe:2.3:a:apache:http_server'), false)
  t.eq(s.modules.validate.valid_alias(42), false)
end)

t.case('valid_channel', function()
  for _, channel in ipairs({ 'raw', 'body', 'title', 'script', 'cookie',
    'banner', 'hdr:server', 'meta:generator' }) do
    t.truthy(s.modules.validate.valid_channel(channel), channel)
  end
  t.eq(s.modules.validate.valid_channel('hdr:'), false)
  t.eq(s.modules.validate.valid_channel('foo'), false)
end)

t.case('valid_path', function()
  t.truthy(s.modules.validate.valid_path('/admin/'))
  t.eq(s.modules.validate.valid_path('admin'), false)
  t.eq(s.modules.validate.valid_path('/a b'), false)
  t.eq(s.modules.validate.valid_path('/x#y'), false)
end)

t.suite('catalogue validation')

local rule = { alias = 'cpe:/a:f5:nginx', channel = 'hdr:server',
  regex = 'nginx/([%d.]+)', anchor = 'nginx' }

local probe = {
  alias = 'cpe:/a:acme:portal', name = 'portal',
  detect = { { channel = 'title', anchor = 'Acme', regex = 'Acme Portal' } },
  extract = { { anchor = 'version', regex = 'version ([%d.]+)' } },
  paths = { '/about' }
}

t.case('fingerprints are grouped by channel', function()
  local by_channel = s.modules.validate.validate_fingerprints(
    { rules = { nginx = rule } })
  t.eq(by_channel['hdr:server'][1].alias, 'cpe:/a:f5:nginx')
end)

t.case('one invalid rule rejects the whole catalogue', function()
  local bad = { alias = 'cpe:/a:x:y', channel = 'body', regex = '([%d' }
  t.eq(s.modules.validate.validate_fingerprints({ rules = { nginx = rule,
      bad = bad } }), nil)
  t.eq(s.modules.validate.validate_fingerprints({ rules = {} }), nil)
end)

t.case('paths are deduplicated and validated', function()
  t.eq(s.modules.validate.validate_paths({ paths = { '/a', '/a', '/b' } }),
      { '/a', '/b' })
  t.eq(s.modules.validate.validate_paths({ paths = { '/a', 'b' } }), nil)
  t.eq(s.modules.validate.validate_paths({ paths = {} }), nil)
end)

t.case('probes require schema 1 and valid parts', function()
  t.eq(#s.modules.validate.validate_probes({ schema = 1, probes = { probe } }),
      1)
  t.eq(s.modules.validate.validate_probes({ schema = 2, probes = { probe } }),
      nil)
  local broken = { alias = probe.alias, detect = probe.detect,
    extract = probe.extract, paths = { 'about' } }
  t.eq(s.modules.validate.validate_probes({ schema = 1, probes = { broken } }),
      nil)
end)

t.case('build_catalog loads the three catalogue files', function()
  local index = { schema = 1, catalogs = {
    fingerprints = { file = 'fingerprints.json' },
    paths = { file = 'paths.json' },
    probes = { file = 'probes.json' } } }
  local files = {
    ['fingerprints.json'] = { rules = { nginx = rule } },
    ['paths.json'] = { paths = { '/' } },
    ['probes.json'] = { schema = 1, probes = { probe } },
  }
  local loaded = s.modules.validate.build_catalog(index,
      function(name) return files[name] end)
  t.truthy(loaded and loaded.fingerprints and loaded.paths and loaded.probes)
  index.catalogs.paths.file = 'other.json'
  t.eq(s.modules.validate.build_catalog(index,
      function(name) return files[name] end), nil)
end)

t.suite('response matching')

t.case('safe_version trims and rejects junk', function()
  t.eq(s.modules.fingerprint_match.safe_version(' 1.2 '), '1.2')
  t.eq(s.modules.fingerprint_match.safe_version('*'), nil)
  t.eq(s.modules.fingerprint_match.safe_version(''), nil)
  t.eq(s.modules.fingerprint_match.safe_version('...'), nil)
  t.eq(s.modules.fingerprint_match.safe_version('1.2\n3'), nil)
  t.eq(s.modules.fingerprint_match.safe_version(string.rep('1', 129)), nil)
end)

t.case('anchored_capture searches near the anchor only', function()
  t.eq(s.modules.fingerprint_match.anchored_capture('nginx/([%d.]+)', 'nginx',
      'Server: nginx/1.4.6'),
    '1.4.6')
  t.eq(s.modules.fingerprint_match.anchored_capture('nginx/([%d.]+)', 'apache',
      'nginx/1.4.6'), nil)
  local far = 'Acme' .. string.rep(' ', 600) .. 'v9.9'
  t.eq(s.modules.fingerprint_match.anchored_capture('v([%d.]+)', 'Acme', far), nil)
end)

t.case('html_attribute handles quoting styles', function()
  t.eq(s.modules.fingerprint_match.html_attribute(
    '<meta name="generator" content="WP 5.8">', 'content'), 'WP 5.8')
  t.eq(s.modules.fingerprint_match.html_attribute("<meta CONTENT='x 1'>", 'content'),
      'x 1')
  t.eq(s.modules.fingerprint_match.html_attribute('<script src=a.js>', 'src'),
      'a.js')
end)

t.case('unquoted attribute with slashes', function()
  t.eq(s.modules.fingerprint_match.html_attribute('<script src=/js/a.js>', 'src'),
      '/js/a.js')
end)

t.case('response_subjects splits a response into channels', function()
  local subjects = s.modules.fingerprint_match.response_subjects({
    rawheader = { 'Server: nginx/1.4.6' },
    header = { server = 'nginx/1.4.6', ['x-powered-by'] = 'PHP/5.4.1' },
    cookies = { { name = 'PHPSESSID', value = 'abc' } },
    body = '<title>Hi</title><meta name="Generator" content="Joomla! 3.9">'
        .. '<script src="/js/jquery-1.8.3.min.js"></script>'
  })
  t.eq(subjects.raw, { 'Server: nginx/1.4.6' })
  t.eq(subjects['hdr:server'], { 'nginx/1.4.6' })
  t.eq(subjects['hdr:x-powered-by'], { 'PHP/5.4.1' })
  t.eq(subjects.cookie, { 'PHPSESSID=abc' })
  t.eq(subjects.title, { 'Hi' })
  t.eq(subjects['meta:generator'], { 'Joomla! 3.9' })
  t.eq(subjects.script, { '/js/jquery-1.8.3.min.js' })
end)

t.case('response_is_usable accepts 2xx and 3xx only', function()
  t.eq(s.modules.http_fingerprint.response_is_usable({ status = 200 }), true)
  t.eq(s.modules.http_fingerprint.response_is_usable({ status = 302 }), true)
  t.eq(s.modules.http_fingerprint.response_is_usable({ status = 403 }), false)
  t.eq(s.modules.http_fingerprint.response_is_usable({ status = 404 }), false)
  t.eq(s.modules.http_fingerprint.response_is_usable({}), false)
end)

t.case('match_subjects records versions and triggers probes', function()
  local scanner = t.load_scanner()
  scanner.modules.state.catalog_loaded = true
  scanner.modules.state.catalog = {
    fingerprints = s.modules.validate.validate_fingerprints(
      { rules = { nginx = rule } }),
    paths = { '/' },
    probes = s.modules.validate.validate_probes(
      { schema = 1, probes = { probe } })
  }
  local matches, triggered = new_match_table(), {}
  scanner.modules.fingerprint_match.match_subjects({
    ['hdr:server'] = { 'nginx/1.4.6' },
    title = { 'Acme Portal' }
  }, matches, 'http', triggered)
  t.truthy(matches.data.http['cpe:/a:f5:nginx']['1.4.6'])
  t.eq(triggered['cpe:/a:acme:portal'], true)
end)

t.case('targeted probes fetch at most three paths per probe', function()
  local requested = {}
  local http = {
    get = function(_, _, path)
      table.insert(requested, path)
      if path == '/p3' then
        return { status = 200, body = 'version 2.1.0' }
      end
      return { status = 404, body = '' }
    end
  }
  local scanner = t.load_scanner({ http = http })
  local many = { alias = probe.alias, detect = probe.detect,
    extract = probe.extract, paths = { '/p1', '/p2', '/p3', '/p4' } }
  scanner.modules.state.catalog_loaded = true
  scanner.modules.state.catalog = { fingerprints = {}, paths = {},
    probes = s.modules.validate.validate_probes({ schema = 1,
        probes = { many } }) }
  local matches = new_match_table()
  scanner.modules.http_fingerprint.run_targeted_probes({}, {}, matches,
    { [probe.alias] = true })
  t.eq(requested, { '/p1', '/p2', '/p3' })
  t.truthy(matches.data.http[probe.alias]['2.1.0'])
end)

-- Runs the targeted probe once against a stub server and returns the
-- matches, the requested paths and the matches size.
local function run_probe(initial, body, status)
  local requested = {}
  local http = {
    get = function(_, _, path)
      table.insert(requested, path)
      return { status = status or 200, body = body }
    end
  }
  local scanner = t.load_scanner({ http = http })
  scanner.modules.state.catalog_loaded = true
  scanner.modules.state.catalog = { fingerprints = {}, paths = {},
    probes = s.modules.validate.validate_probes({ schema = 1,
        probes = { probe } }) }
  local matches = new_match_table()
  for version in pairs(initial or {}) do
    matches.data.nmap[probe.alias] = matches.data.nmap[probe.alias] or {}
    matches.data.nmap[probe.alias][version] = true
    matches.size = matches.size + 1
  end
  scanner.modules.http_fingerprint.run_targeted_probes({}, {}, matches,
    { [probe.alias] = true })
  return matches, requested
end

t.case('targeted probe refines a series version to a precise one', function()
  local matches = run_probe({ ['5.5'] = true }, 'version 5.5.25')
  t.keys_eq(matches.data.nmap[probe.alias], {})
  t.keys_eq(matches.data.http[probe.alias], { '5.5.25' })
  t.eq(matches.size, 1)
end)

t.case('series version is kept when the probe finds nothing', function()
  local matches = run_probe({ ['5.5'] = true }, '', 404)
  t.keys_eq(matches.data.nmap[probe.alias], { '5.5' })
  t.eq(matches.size, 1)
end)

t.case('targeted probe is skipped with a precise version', function()
  local matches, requested = run_probe({ ['5.5.25'] = true }, 'version 1')
  t.eq(requested, {})
  t.keys_eq(matches.data.nmap[probe.alias], { '5.5.25' })
end)

t.case('targeted probe runs without any version', function()
  local matches, requested = run_probe(nil, 'version 5.5.25')
  t.eq(requested, { '/about' })
  t.keys_eq(matches.data.http[probe.alias], { '5.5.25' })
  t.eq(matches.size, 1)
end)

t.suite('smb samba probe')

local samba_port = { number = 445, service = 'microsoft-ds',
  version = { cpe = { 'cpe:/a:samba:samba' }, version = '3.X - 4.X' } }

--- Run fn with a stubbed smb library exposing get_os.
local function with_smb(get_os, fn)
  package.loaded.smb = { get_os = get_os }
  local ok, err = pcall(fn)
  package.loaded.smb = nil
  if not ok then error(err, 0) end
end

t.case('samba lanmanager sets exact version, drops nmap range', function()
  with_smb(function()
    return true, { lanmanager = 'Samba 3.0.20-Debian' }
  end, function()
    local scanner = t.load_scanner()
    local matches = new_match_table()
    matches.data.smb = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.0.0.1' }, samba_port,
        matches)
    t.truthy(matches.data.smb['cpe:/a:samba:samba']['3.0.20'])
    t.keys_eq(matches.data.nmap, {})
  end)
end)

t.case('smb get_os status false falls back to nmap cpe', function()
  with_smb(function() return false, 'error' end, function()
    local scanner = t.load_scanner()
    local matches = new_match_table()
    matches.data.smb = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.0.0.6' }, samba_port,
        matches)
    t.keys_eq(matches.data.smb, {})
    t.truthy(matches.data.nmap['cpe:/a:samba:samba']['3.X - 4.X'])
  end)
end)

t.case('smb probe error falls back to nmap cpe', function()
  with_smb(function() error('timeout') end, function()
    local scanner = t.load_scanner()
    local matches = new_match_table()
    matches.data.smb = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.0.0.2' }, samba_port,
        matches)
    t.keys_eq(matches.data.smb, {})
    t.truthy(matches.data.nmap['cpe:/a:samba:samba']['3.X - 4.X'])
  end)
end)

t.case('port 80 never calls get_os', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { lanmanager = 'Samba 3.0.20' }
  end, function()
    local scanner = t.load_scanner()
    local http_port = { number = 80, service = 'http',
      version = { cpe = { 'cpe:/a:samba:samba' }, version = '3.X' } }
    local matches = new_match_table()
    matches.data.smb = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.0.0.4' }, http_port,
        matches)
    t.eq(calls, 0)
    t.keys_eq(matches.data.smb, {})
  end)
end)

t.case('smb probe is cached per host', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { lanmanager = 'Samba 4.5.16-Debian' }
  end, function()
    local scanner = t.load_scanner()
    local host = { ip = '10.0.0.5' }
    local matches = new_match_table()
    matches.data.smb = {}
    scanner.modules.port_matches.add_nmap_matches(host, samba_port, matches)
    scanner.modules.port_matches.add_nmap_matches(host, samba_port, matches)
    t.truthy(matches.data.smb['cpe:/a:samba:samba']['4.5.16'])
    t.keys_eq(matches.data.nmap, {})
    t.eq(calls, 1)
  end)
end)

t.suite('service probes dispatcher')

local samba_nmap = 'cpe:/a:samba:samba'

t.case('probes=none never calls get_os and keeps the nmap cpe', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { lanmanager = 'Samba 3.0.20' }
  end, function()
    local scanner = t.load_scanner({ args = { probes = 'none' } })
    local matches = new_match_table()
    matches.data.smb = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.0.1.1' }, samba_port,
        matches)
    t.eq(calls, 0)
    t.truthy(matches.data.nmap[samba_nmap]['3.X - 4.X'])
  end)
end)

t.case('probes=smb runs the smb probe', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { lanmanager = 'Samba 3.0.20' }
  end, function()
    local scanner = t.load_scanner({ args = { probes = 'smb' } })
    local matches = new_match_table()
    matches.data.smb = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.0.1.2' }, samba_port,
        matches)
    t.eq(calls, 1)
    t.truthy(matches.data.smb[samba_nmap]['3.0.20'])
  end)
end)

t.case('probes=irc does not run the smb probe', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { lanmanager = 'Samba 3.0.20' }
  end, function()
    local scanner = t.load_scanner({ args = { probes = 'irc' } })
    local matches = new_match_table()
    matches.data.smb = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.0.1.3' }, samba_port,
        matches)
    t.eq(calls, 0)
    t.keys_eq(matches.data.smb, {})
  end)
end)

t.case('probes csv list enables each named probe', function()
  with_smb(function() return false, 'unused' end, function()
    local scanner = t.load_scanner({ args = { probes = 'smb,irc' } })
    t.eq(scanner.modules.probes.probe_enabled('smb'), true)
    t.eq(scanner.modules.probes.probe_enabled('irc'), true)
    t.eq(scanner.modules.probes.probe_enabled('http'), false)
  end)
end)

t.case('failing version probe is cached as a miss', function()
  local calls = 0
  local fake = { name = 'fake', run = function()
    calls = calls + 1
    error('boom')
  end }
  local scanner = t.load_scanner()
  local host, port = { ip = '10.0.2.1' }, { number = 9001 }
  t.eq(scanner.modules.probes.run_version_probe(host, port, fake), nil)
  t.eq(scanner.modules.probes.run_version_probe(host, port, fake), nil)
  t.eq(calls, 1)
end)

t.case('version probe result is cached per ip and port', function()
  local calls = 0
  local fake = { name = 'fake', run = function()
    calls = calls + 1
    return { cpe = 'cpe:/a:acme:portal', version = '1.0' }
  end }
  local scanner = t.load_scanner()
  local host = { ip = '10.0.2.2' }
  local first = scanner.modules.probes.run_version_probe(host,
      { number = 8080 }, fake)
  t.eq(first.version, '1.0')
  scanner.modules.probes.run_version_probe(host, { number = 8080 }, fake)
  t.eq(calls, 1)
  scanner.modules.probes.run_version_probe(host, { number = 8081 }, fake)
  t.eq(calls, 2)
end)

-- Real luasql module for the database case; nil when it is not installed.
local fixture = require 'fixture'
local sqlite = fixture.load_sqlite()

-- Run a database case, or skip it when luasql.sqlite3 is not installed.
local function db_case(name, fn)
  if sqlite then
    t.case(name, fn)
  else
    t.skip(name, 'luasql.sqlite3 is not installed')
  end
end

db_case('analysis reports a non-nmap origin as its own source', function()
  local path = fixture.create({
    cves = { { 'CVE-EXACT', '5.0', nil, 2000 } },
    products = { { 1, 'apache', 'tomcat', '5.5', '*' } },
    affected = { { 'CVE-EXACT', 1 } },
  }, sqlite)
  local env, conn = fixture.open(path, sqlite)
  local scanner = t.load_scanner()
  scanner.modules.state.db_env, scanner.modules.state.db_conn = env, conn
  scanner.modules.state.log_file = { write = function() end }
  scanner.modules.state.service_cache = {}
  scanner.modules.state.json_report = {}
  scanner.modules.state.json_hosts = {}
  local matches = new_match_table()
  matches.data.irc = {}
  matches.data.irc['cpe:/a:apache:tomcat:5.5'] = { ['5.5'] = true }
  matches.size = 1
  local host = { ip = '10.0.2.3' }
  local port = { number = 80, protocol = 'tcp', service = 'http' }
  scanner.modules.port_analysis.analyze_port(host, port, matches,
    { os = {} })
  local product = find_product(scanner.modules.state.json_report, host.ip, 80)
  conn:close()
  env:close()
  os.remove(path)
  assert(product, 'product missing from json report')
  t.eq(product.version_source, 'irc')
end)

t.suite('irc probe')

local irc_nmap = 'cpe:/a:unrealircd:unrealircd'
local irc_port = { number = 6667, service = 'irc',
  version = { cpe = { irc_nmap }, version = '' } }
local IRC_351 = ':irc.local 351 cvescan Unreal3.2.8.1. irc.local :FhiXOoE\r\n'

--- Return a socket factory that replays script.lines, one per read.
-- The log counts created and closed sockets and records sent data.
-- Reads past the scripted lines time out.
local function irc_stub(script)
  local log = { created = 0, closed = 0, sent = {} }
  local function new_socket()
    log.created = log.created + 1
    local reads = 0
    local sock = {}
    function sock.set_timeout() end
    function sock.connect()
      if script.connect_err then return false, script.connect_err end
      return true
    end
    function sock.send(_, data)
      table.insert(log.sent, data)
      return #data
    end
    function sock.receive_lines()
      reads = reads + 1
      local line = (script.lines or {})[reads]
      if line == nil then return false, 'timeout' end
      return true, line
    end
    function sock.close() log.closed = log.closed + 1 end
    return sock
  end
  return log, new_socket
end

t.case('351 reply sets the UnrealIRCd version', function()
  local log, new_socket = irc_stub({ lines = { IRC_351 } })
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  local matches = new_match_table()
  matches.data.irc = {}
  scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.1' }, irc_port,
      matches)
  t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
  t.keys_eq(matches.data.nmap, {})
  t.eq(log.closed, 1)
end)

t.case('precise Nmap version skips the irc probe', function()
  local log, new_socket = irc_stub({ lines = { IRC_351 } })
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  local port = { number = 6667, service = 'irc',
    version = { cpe = { irc_nmap }, version = '3.2.8.1' } }
  local matches = new_match_table()
  matches.data.irc = {}
  scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.2' }, port, matches)
  t.eq(log.created, 0)
  t.truthy(matches.data.nmap[irc_nmap]['3.2.8.1'])
end)

t.case('http service never runs the irc probe', function()
  local log, new_socket = irc_stub({ lines = { IRC_351 } })
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  local port = { number = 6667, service = 'http',
    version = { cpe = { irc_nmap }, version = '' } }
  local matches = new_match_table()
  matches.data.irc = {}
  scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.3' }, port, matches)
  t.eq(log.created, 0)
  t.truthy(matches.data.nmap[irc_nmap]['*'])
end)

t.case('other product on an irc service never runs the probe', function()
  local log, new_socket = irc_stub({ lines = { IRC_351 } })
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  local port = { number = 6667, service = 'irc',
    version = { cpe = { 'cpe:/a:ngircd:ngircd' }, version = '' } }
  local matches = new_match_table()
  matches.data.irc = {}
  scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.4' }, port, matches)
  t.eq(log.created, 0)
  t.truthy(matches.data.nmap['cpe:/a:ngircd:ngircd']['*'])
end)

t.case('probes=none and probes=smb skip the irc probe', function()
  for _, arg in ipairs({ 'none', 'smb' }) do
    local log, new_socket = irc_stub({ lines = { IRC_351 } })
    local scanner = t.load_scanner({ args = { probes = arg } })
    scanner.stubs.nmap.new_socket = new_socket
    local matches = new_match_table()
    matches.data.irc = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.5' }, irc_port,
        matches)
    t.eq(log.created, 0, arg)
    t.truthy(matches.data.nmap[irc_nmap]['*'], arg)
  end
end)

t.case('failed or non-Unreal replies fall back to the nmap cpe', function()
  local cases = {
    { lines = { ':irc.local 001 cvescan :Welcome\r\n' } },
    { connect_err = 'refused', lines = { IRC_351 } },
    { lines = { ':irc.local 351 cvescan ngIRCd-26 irc.local :x\r\n' } },
  }
  for i, script in ipairs(cases) do
    local log, new_socket = irc_stub(script)
    local scanner = t.load_scanner()
    scanner.stubs.nmap.new_socket = new_socket
    local matches = new_match_table()
    matches.data.irc = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.6' }, irc_port,
        matches)
    t.keys_eq(matches.data.irc, {}, tostring(i))
    t.truthy(matches.data.nmap[irc_nmap]['*'], tostring(i))
    t.eq(log.created, 1, tostring(i))
    t.eq(log.closed, 1, tostring(i))
  end
end)

t.case('PING is answered with PONG before the 351 reply', function()
  local log, new_socket = irc_stub({
    lines = { 'PING :LAG123\r\n', IRC_351 },
  })
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  local matches = new_match_table()
  matches.data.irc = {}
  scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.7' }, irc_port,
      matches)
  t.eq(log.sent[2], 'PONG LAG123\r\n')
  t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
  t.keys_eq(matches.data.nmap, {})
end)

t.case('irc probe is cached per ip and port', function()
  local log, new_socket = irc_stub({ lines = { IRC_351 } })
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  local host = { ip = '10.1.0.8' }
  for _ = 1, 2 do
    local matches = new_match_table()
    matches.data.irc = {}
    scanner.modules.port_matches.add_nmap_matches(host, irc_port, matches)
    t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
    t.keys_eq(matches.data.nmap, {})
  end
  t.eq(log.created, 1)
end)

--- Return a socket factory that gives each new socket its own script.
-- The log lists one per-socket log from irc_stub in creation order.
local function irc_sequence(scripts)
  local log = { created = 0, sockets = {} }
  local function new_socket()
    log.created = log.created + 1
    local socket_log, factory = irc_stub(scripts[log.created] or {})
    table.insert(log.sockets, socket_log)
    return factory()
  end
  return log, new_socket
end

--- Return a stdnse.sleep replacement that records the requested delays.
local function irc_sleeps()
  local sleeps = {}
  return sleeps, function(seconds)
    table.insert(sleeps, seconds)
  end
end

local IRC_THROTTLED = 'ERROR :Closing Link: [10.1.0.1] (Throttled: '
  .. 'Reconnecting too fast) - Please wait 10 seconds\r\n'

--- Return n throttled scripts followed by one successful 351 reply.
local function throttled_then_ok(n)
  local scripts = {}
  for _ = 1, n do
    table.insert(scripts, { lines = { IRC_THROTTLED } })
  end
  table.insert(scripts, { lines = { IRC_351 } })
  return scripts
end

--- Run the irc probe on scripted sockets; return socket log, sleeps, matches.
local function run_irc_retry(scripts)
  local log, new_socket = irc_sequence(scripts)
  local sleeps, sleep = irc_sleeps()
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  scanner.stubs.stdnse.sleep = sleep
  local matches = new_match_table()
  matches.data.irc = {}
  scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.20' }, irc_port,
      matches)
  return log, sleeps, matches
end

--- Assert that every socket opened by the probe was closed once.
local function assert_all_closed(log)
  for _, socket_log in ipairs(log.sockets) do
    t.eq(socket_log.closed, 1)
  end
end

t.case('irc probe with no throttling never retries', function()
  local log, sleeps, matches = run_irc_retry(throttled_then_ok(0))
  t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
  t.eq(log.created, 1)
  t.eq(sleeps, {})
  assert_all_closed(log)
end)

t.case('throttled irc probe succeeds after one 30 s retry',
  function()
    local log, sleeps, matches = run_irc_retry(throttled_then_ok(1))
    t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
    t.eq(log.created, 2)
    t.eq(sleeps, { 30 })
    assert_all_closed(log)
  end)

t.case('throttled irc probe succeeds after two 30 s retries',
  function()
    local log, sleeps, matches = run_irc_retry(throttled_then_ok(2))
    t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
    t.eq(log.created, 3)
    t.eq(sleeps, { 30, 30 })
    assert_all_closed(log)
  end)

t.case('irc probe gives up after two retries when throttled three times',
  function()
    local log, sleeps, matches = run_irc_retry(throttled_then_ok(3))
    t.keys_eq(matches.data.irc, {})
    t.truthy(matches.data.nmap[irc_nmap]['*'])
    t.eq(log.created, 3)
    t.eq(sleeps, { 30, 30 })
    assert_all_closed(log)
  end)

t.case('unthrottled irc probe never sleeps', function()
  local log, new_socket = irc_sequence({ { lines = { IRC_351 } } })
  local sleeps, sleep = irc_sleeps()
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  scanner.stubs.stdnse.sleep = sleep
  local matches = new_match_table()
  matches.data.irc = {}
  scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.22' }, irc_port,
      matches)
  t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
  t.keys_eq(matches.data.nmap, {})
  t.eq(log.created, 1)
  t.eq(sleeps, {})
end)

t.case('precise samba version skips the smb get_os call', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { lanmanager = 'Samba 4.5.16' }
  end, function()
    local scanner = t.load_scanner()
    local port = { number = 445, service = 'microsoft-ds',
      version = { cpe = { samba_nmap }, version = '4.5.16' } }
    local matches = new_match_table()
    matches.data.smb = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.1.0.9' }, port,
        matches)
    t.eq(calls, 0)
    t.truthy(matches.data.nmap[samba_nmap]['4.5.16'])
  end)
end)

t.suite('os probe')

local WIN_OS = 'Windows Server 2008 R2 Standard 7601 Service Pack 1'
local SAMBA_OS = 'Unix (Samba 3.0.20-Debian)'
local SMB_PORT = { number = 445, protocol = 'tcp', service = 'microsoft-ds' }
local HTTP_PORT = { number = 80, protocol = 'tcp', service = 'http' }
local OS_FAMILIES = { linux = 'linux', microsoft = 'windows' }
local OS_INFO = { version = '5.5.3', update = '*', from = nil, to = nil,
  matches_any = false, is_range = false }

--- Return a cursor over fixed rows (local copy for this suite).
local function os_rows(rows)
  local i = 0
  return {
    fetch = function()
      i = i + 1
      if rows[i] == nil then return nil end
      return table.unpack(rows[i], 1, 8)
    end,
    close = function() end,
  }
end

--- Scanner with one CVE for apache:tomcat 5.5.3 and the given platform rows.
-- Default platform rows make the CVE Linux-only.
local function os_scanner(args, platform)
  local sc = t.load_scanner({ args = args })
  sc.modules.state.platform_families = OS_FAMILIES
  sc.modules.state.log_file = { write = function() end }
  sc.modules.state.json_report = {}
  sc.modules.state.json_hosts = {}
  platform = platform or { { 'CVE-LIN', 0, 'o', 'linux', 'kernel' } }
  sc.modules.state.db_conn = { execute = function(_, sql)
    if sql:find('pragma_table_info', 1, true) then
      return os_rows({ { 'cvss_v4' } })
    elseif sql:find('sqlite_master', 1, true) then
      return os_rows({ { 'conditions' } })
    elseif sql:find('FROM conditions', 1, true) then
      return os_rows(platform)
    elseif sql:find('SELECT DISTINCT vendor', 1, true) then
      return os_rows({ { 'apache' } })
    elseif sql:find('INNER JOIN affected', 1, true) then
      return os_rows({ { 'CVE-LIN', '5.0', nil, nil, '5.5.3', '*', 0, 0 } })
    end
    return os_rows({})
  end }
  return sc
end

--- Install an nmap.get_ports stub that yields the given open ports.
local function open_ports(sc, ports)
  sc.stubs.nmap.get_ports = function()
    local i = 0
    return function()
      i = i + 1
      return ports[i]
    end
  end
end

--- Run vulnerabilities for the tomcat CVE of one host.
local function os_scan(sc, ip, scan_ctx)
  local host = { ip = ip }
  return sc.modules.service_cves.find_service_cves(host, HTTP_PORT,
      'cpe:/a:apache:tomcat:5.5.3',
    'apache', 'tomcat', OS_INFO, scan_ctx or { os = {}, backport = false })
end

t.case('smb windows probe sets the family, one get_os call', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { os = WIN_OS }
  end, function()
    local sc = os_scanner()
    open_ports(sc, { HTTP_PORT, SMB_PORT })
    -- Probe V runs first on the same host and shares the get_os result.
    sc.modules.port_matches.add_nmap_matches({ ip = '10.2.0.2' }, { number = 445,
      protocol = 'tcp', service = 'microsoft-ds',
      version = { cpe = { 'cpe:/a:samba:samba' }, version = '3.X' } },
      new_match_table())
    local meta = os_scan(sc, '10.2.0.2')
    t.eq(meta.os_context.family, 'windows')
    t.eq(meta.os_context.source, 'probe:smb_os')
    local again = os_scan(sc, '10.2.0.2')
    t.eq(again.os_context.family, 'windows')
    t.eq(calls, 1)
  end)
end)

t.case('samba os string is not an os family', function()
  with_smb(function() return true, { os = SAMBA_OS } end, function()
    local sc = os_scanner()
    open_ports(sc, { SMB_PORT })
    local meta = os_scan(sc, '10.2.0.3')
    t.eq(meta.os_context.family, nil)
    t.eq(sc.modules.state.host_os_probe_result['10.2.0.3'], false)
  end)
end)

t.case('samba lanmanager on a windows-looking os is not windows', function()
  with_smb(function()
    return true, { os = 'Windows 6.1', lanmanager = 'Samba 4.3.11-Ubuntu' }
  end, function()
    local sc = os_scanner()
    open_ports(sc, { SMB_PORT })
    local meta = os_scan(sc, '10.2.0.6')
    t.eq(meta.os_context.family, nil)
  end)
end)

t.case('windows lanmanager or missing lanmanager stays windows', function()
  local cases = {
    { os = WIN_OS, lanmanager = 'Windows Server 2008 R2 Standard 6.1' },
    { os = WIN_OS },
  }
  for i, info in ipairs(cases) do
    with_smb(function() return true, info end, function()
      local sc = os_scanner()
      open_ports(sc, { SMB_PORT })
      local ip = '10.2.0.7' .. i
      local meta = os_scan(sc, ip)
      t.eq(meta.os_context.family, 'windows')
    end)
  end
end)

t.case('no smb port open means get_os is never called', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { os = WIN_OS }
  end, function()
    local sc = os_scanner()
    open_ports(sc, { HTTP_PORT })
    local meta = os_scan(sc, '10.2.0.4')
    t.eq(meta.os_context.family, nil)
    t.eq(calls, 0)
  end)
end)

t.case('probes=none, probes=smb and probes=irc skip the os probe', function()
  for _, args in ipairs({
    { probes = 'none' }, { probes = 'smb' }, { probes = 'irc' } }) do
    local calls = 0
    with_smb(function()
      calls = calls + 1
      return true, { os = WIN_OS }
    end, function()
      local sc = os_scanner(args)
      open_ports(sc, { SMB_PORT })
      local meta = os_scan(sc, '10.2.0.5')
      t.eq(meta.os_context.family, nil)
      t.eq(calls, 0)
    end)
  end
end)

t.case('os_context uses a cached probe before the cpe', function()
  local sc = t.load_scanner()
  sc.modules.state.platform_families = OS_FAMILIES
  sc.modules.state.host_os_probe_result['10.2.0.6'] = {
    family = 'windows', source = 'probe:smb_os' }
  local port = { number = 445, service = 'microsoft-ds',
    version = { cpe = { 'cpe:/o:linux:linux_kernel' } } }
  local scan_ctx = sc.modules.os_context.os_context({ ip = '10.2.0.6' }, port)
  t.eq(scan_ctx.family, 'windows')
  t.eq(scan_ctx.source, 'probe:smb_os')
  local plain = sc.modules.os_context.os_context({ ip = '10.2.0.7' }, port)
  t.eq(plain.family, 'linux')
  t.eq(plain.source, 'cpe')
  t.eq(sc.modules.state.host_os_probe_result['10.2.0.7'], nil)
end)

t.case('get_os error is cached as a negative result', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    error('timeout')
  end, function()
    local sc = os_scanner()
    open_ports(sc, { SMB_PORT })
    local first = os_scan(sc, '10.2.0.8')
    local second = os_scan(sc, '10.2.0.8')
    t.eq(first.os_context.family, nil)
    t.eq(second.os_context.family, nil)
    t.eq(calls, 1)
    t.eq(sc.modules.state.host_os_probe_result['10.2.0.8'], false)
  end)
end)

t.case('probe turns requires_platform into platform_mismatch', function()
  with_smb(function() return true, { os = WIN_OS } end, function()
    local sc = os_scanner()
    open_ports(sc, { SMB_PORT })
    local meta = os_scan(sc, '10.2.0.9')
    t.eq(meta.counts.low, 1)
    t.eq(meta.counts.medium, 0)
    t.eq(meta.os_context.source, 'probe:smb_os')
  end)
end)

t.case('without a probe the Linux-only CVE stays requires_platform', function()
  local sc = os_scanner()
  open_ports(sc, { HTTP_PORT })
  local meta = os_scan(sc, '10.2.0.10')
  t.eq(meta.counts.medium, 1)
  t.eq(meta.os_context.family, nil)
end)

t.case('known os or no conditional CVE never runs the probe', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { os = WIN_OS }
  end, function()
    local known = os_scanner()
    open_ports(known, { SMB_PORT })
    local meta = os_scan(known, '10.2.0.11',
      { os = { family = 'linux', source = 'cpe' }, backport = false })
    t.eq(meta.os_context.family, 'linux')
    t.eq(calls, 0)
    local plain = os_scanner(nil, {})
    local ports_calls = 0
    plain.stubs.nmap.get_ports = function()
      ports_calls = ports_calls + 1
      return function() return nil end
    end
    local plain_meta = os_scan(plain, '10.2.0.12')
    t.eq(plain_meta.counts.high, 1)
    t.eq(ports_calls, 0)
    t.eq(calls, 0)
  end)
end)

--- Run analysis for one tomcat 5.5.3 service on ip and port.
local function os_analysis(sc, ip, port, scan_ctx)
  sc.modules.state.service_cache = sc.modules.state.service_cache or {}
  local matches = { data = { nmap = {
    ['cpe:/a:apache:tomcat:5.5.3'] = { ['5.5.3'] = true } } }, size = 1 }
  sc.modules.port_analysis.analyze_port({ ip = ip }, port, matches, scan_ctx)
  return find_product(sc.modules.state.json_report, ip, port.number)
end

--- Count CVE queries issued through registry.db_conn from now on.
local function count_cve_queries(sc)
  local n = 0
  local real = sc.modules.state.db_conn.execute
  sc.modules.state.db_conn.execute = function(conn, sql)
    if sql:find('INNER JOIN affected', 1, true) then n = n + 1 end
    return real(conn, sql)
  end
  return function() return n end
end

t.case('unknown os cache is not shared across hosts', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { os = WIN_OS }
  end, function()
    local sc = os_scanner()
    open_ports(sc, { SMB_PORT })
    local first = os_analysis(sc, '10.2.0.13', HTTP_PORT, { os = {},
      backport = false })
    assert(first, 'first analysis missing')
    assert(first.os_context, 'first analysis has no os_context')
    t.eq(first.os_context.family, 'windows')
    local second = os_analysis(sc, '10.2.0.14', HTTP_PORT, { os = {},
      backport = false })
    t.eq(calls, 2)
    assert(second, 'second analysis missing')
    t.eq(second.cached, false)
  end)
end)

t.case('unknown os cache is shared by ports of the same host', function()
  local sc = os_scanner()
  open_ports(sc, { HTTP_PORT })
  local queries = count_cve_queries(sc)
  os_analysis(sc, '10.2.0.15', HTTP_PORT, { os = {}, backport = false })
  local after_first = queries()
  local alt_port = { number = 8080, protocol = 'tcp', service = 'http' }
  local second = os_analysis(sc, '10.2.0.15', alt_port,
    { os = {}, backport = false })
  t.eq(queries(), after_first)
  assert(second, 'second analysis missing')
  t.eq(second.cached, true)
end)

t.case('known os cache is shared across hosts', function()
  local sc = os_scanner()
  open_ports(sc, { HTTP_PORT })
  local scan_ctx = { os = { family = 'linux', source = 'cpe' }, backport = false }
  local queries = count_cve_queries(sc)
  os_analysis(sc, '10.2.0.16', HTTP_PORT, scan_ctx)
  local after_first = queries()
  local second = os_analysis(sc, '10.2.0.17', HTTP_PORT, scan_ctx)
  t.eq(queries(), after_first)
  assert(second, 'second analysis missing')
  t.eq(second.cached, true)
end)

t.suite('http engine abort')

local ABORT_PORT = { number = 8080, protocol = 'tcp', service = 'http' }

--- Scanner whose catalogue sweep records pipeline_go calls.
-- batches(n) returns the reply table for the n-th pipeline_go call.
-- args are the script arguments; the sweep is opted in by default.
local function abort_catalog(batches, args)
  local calls = 0
  local scanner = t.load_scanner({
    args = args or { sweep = '1' },
    http = {
      pipeline_add = function(_, _, requests)
        return requests or {}
      end,
      pipeline_go = function()
        calls = calls + 1
        return batches(calls)
      end,
    },
  })
  local paths = {}
  for i = 1, 300 do paths[i] = '/r' .. i end
  scanner.modules.state.json_report = {}
  scanner.modules.state.catalog_loaded = true
  scanner.modules.state.catalog = { fingerprints = {}, paths = paths,
    probes = {} }
  scanner.stubs.shortport.http = function() return true end
  return scanner, function() return calls end
end

t.case('catalog stops when a batch has no status', function()
  local scanner, calls = abort_catalog(function() return {} end)
  scanner.portaction({ ip = '10.4.0.4' }, ABORT_PORT)
  t.eq(calls(), 1)
end)

t.case('catalog continues when a batch has one answer', function()
  local scanner, calls = abort_catalog(function(n)
    if n == 1 then return { {}, { status = 404 } } end
    return {}
  end, { sweep = '2' })
  scanner.portaction({ ip = '10.4.0.5' }, ABORT_PORT)
  t.eq(calls(), 2)
end)

t.case('catalogue sweep is off by default', function()
  local scanner, calls = abort_catalog(function() return {} end, {})
  scanner.portaction({ ip = '10.4.0.6' }, ABORT_PORT)
  t.eq(calls(), 0)
end)

t.case('catalogue sweep runs with sweep=1', function()
  local scanner, calls = abort_catalog(function() return {} end,
    { sweep = '1' })
  scanner.portaction({ ip = '10.4.0.7' }, ABORT_PORT)
  t.eq(calls(), 1)
end)

do
t.suite('tiered sweep')

local TIER_PORT = { number = 80, protocol = 'tcp', service = 'http' }
local WP_ROOT = '<html><head><meta name="generator" '
  .. 'content="WordPress 6.0"></head></html>'

--- Return a reply function that answers '/' with body and 404 otherwise.
local function root_reply(body)
  return function(path)
    if path == '/' then
      return { status = 200, header = {}, body = body }
    end
    return { status = 404, header = {}, body = '' }
  end
end

--- Return true when list holds item.
local function listed(list, item)
  for _, value in ipairs(list) do
    if value == item then return true end
  end
  return false
end

--- Return true when any entry of list matches the Lua pattern.
local function any_match(list, pattern)
  for _, value in ipairs(list) do
    if value:find(pattern) then return true end
  end
  return false
end

--- Return true when some entry of list appears more than once.
local function has_duplicates(list)
  local seen = {}
  for _, value in ipairs(list) do
    if seen[value] then return true end
    seen[value] = true
  end
  return false
end

--- Build a scanner whose sweep requests are recorded and answered.
-- opts.args: script arguments (default sweep=1).
-- opts.reply: function(path) returning one response (default 404).
-- opts.go: optional function(requests) replacing the pipeline reply.
-- opts.extra: catalogue paths appended to the base catalogue.
-- Returns the scanner, the requested paths and the catalogue paths.
local function tiered_scanner(opts)
  local requested = {}
  local reply = opts.reply or function(_path)
    return { status = 404, header = {}, body = '' }
  end
  local scanner = t.load_scanner({
    args = opts.args or { sweep = '1' },
    http = {
      pipeline_add = function(path, _, requests)
        table.insert(requested, path)
        requests = requests or {}
        table.insert(requests, path)
        return requests
      end,
      pipeline_go = function(_, _, requests)
        if opts.go then return opts.go(requests) end
        local replies = {}
        for idx, path in ipairs(requests) do
          replies[idx] = reply(path)
        end
        return replies
      end,
    },
  })
  local paths = { '/', '/wp-content/plugins/a/readme.txt', '/wp-login.php',
    '/x.php', '/y.aspx', '/z.jsp' }
  for _, path in ipairs(scanner.modules.tiers.CORE) do
    table.insert(paths, path)
  end
  for i = 1, 20 do
    table.insert(paths, '/otro' .. i)
  end
  for _, path in ipairs(opts.extra or {}) do
    table.insert(paths, path)
  end
  scanner.modules.state.json_report = {}
  scanner.modules.state.catalog_loaded = true
  scanner.modules.state.catalog = { fingerprints = {}, paths = paths,
    probes = {} }
  scanner.stubs.shortport.http = function() return true end
  return scanner, requested, paths
end

t.case('sweep without evidence requests root, random and core', function()
  local scanner, requested = tiered_scanner({})
  scanner.portaction({ ip = '10.5.1.1' }, TIER_PORT)
  t.eq(#requested, 18, 'expected root, random and 16 core paths')
  t.eq(listed(requested, '/'), true)
  for _, path in ipairs(scanner.modules.tiers.CORE) do
    t.eq(listed(requested, path), true, 'missing core ' .. path)
  end
  t.eq(any_match(requested, '^/wp%-'), false)
  t.eq(any_match(requested, '%.php$'), false)
  t.eq(any_match(requested, '%.aspx$'), false)
  t.eq(any_match(requested, '%.jsp$'), false)
  t.eq(any_match(requested, '^/otro%d'), false)
end)

t.case('wordpress generator requests wordpress paths only', function()
  local scanner, requested = tiered_scanner({
    reply = root_reply(WP_ROOT) })
  scanner.portaction({ ip = '10.5.1.2' }, TIER_PORT)
  t.eq(listed(requested, '/wp-content/plugins/a/readme.txt'), true)
  t.eq(listed(requested, '/wp-login.php'), true)
  t.eq(any_match(requested, '%.aspx$'), false)
  t.eq(any_match(requested, '%.jsp$'), false)
end)

t.case('wordpress requests never repeat a path', function()
  local scanner, requested = tiered_scanner({
    reply = root_reply(WP_ROOT) })
  scanner.portaction({ ip = '10.5.1.3' }, TIER_PORT)
  t.eq(has_duplicates(requested), false)
end)

t.case('nmap tomcat version requests z.jsp without root evidence', function()
  local scanner, requested = tiered_scanner({})
  local port = { number = 80, protocol = 'tcp', service = 'http',
    version = { product = 'Apache Tomcat' } }
  scanner.portaction({ ip = '10.5.1.4' }, port)
  t.eq(listed(requested, '/z.jsp'), true)
end)

t.case('linked prefix requests its tail paths and not others', function()
  local scanner, requested = tiered_scanner({
    reply = root_reply('<a href="/otro3/index">x</a>'),
    extra = { '/otro3/panel' } })
  scanner.portaction({ ip = '10.5.1.5' }, TIER_PORT)
  t.eq(listed(requested, '/otro3'), true)
  t.eq(listed(requested, '/otro3/panel'), true)
  t.eq(any_match(requested, '^/otro4'), false)
end)

t.case('catch-all root body does not reveal wordpress', function()
  local catch_all = root_reply('catchall /wp-content/')
  local scanner, requested = tiered_scanner({
    reply = function(path)
      if path == '/' then return catch_all(path) end
      return { status = 200, header = {}, body = 'catchall /wp-content/' }
    end })
  scanner.portaction({ ip = '10.5.1.6' }, TIER_PORT)
  t.eq(any_match(requested, '^/wp%-'), false)
end)

t.case('sweep budget caps the requests', function()
  local scanner, requested = tiered_scanner({
    args = { sweep = '1', sweep_budget = '5' },
    reply = root_reply(WP_ROOT) })
  scanner.portaction({ ip = '10.5.1.7' }, TIER_PORT)
  t.eq(#requested <= 5, true, 'requests exceed the budget of 5')
end)

t.case('sweep level 2 requests each catalogue path once', function()
  local scanner, requested, paths = tiered_scanner({
    args = { sweep = '2' } })
  scanner.portaction({ ip = '10.5.1.8' }, TIER_PORT)
  for _, path in ipairs(paths) do
    local count = 0
    for _, value in ipairs(requested) do
      if value == path then count = count + 1 end
    end
    t.eq(count, 1, 'requested times for ' .. path)
  end
  t.eq(#requested, #paths + 1, 'expected catalogue plus random path')
end)

t.case('silent batch stops the sweep after one call', function()
  local calls = 0
  local scanner, requested = tiered_scanner({
    args = { sweep = '2' },
    go = function()
      calls = calls + 1
      return {}
    end })
  scanner.portaction({ ip = '10.5.1.9' }, TIER_PORT)
  t.eq(calls, 1)
  t.eq(#requested, 2, 'expected only root and random path')
end)
end

t.suite('sweep args')

--- Config module of a scanner loaded with the given script arguments.
local function sweep_config(args)
  return t.load_scanner({ args = args }).modules.config
end

t.case('sweep defaults to level 0 and budget 50', function()
  local cfg = sweep_config({})
  t.eq(cfg.sweep_level, 0)
  t.eq(cfg.sweep_budget, 50)
  t.eq(cfg.sweep_budget_set, false)
end)

t.case('sweep=1 sets level 1', function()
  t.eq(sweep_config({ sweep = '1' }).sweep_level, 1)
end)

t.case('sweep=2 sets level 2', function()
  t.eq(sweep_config({ sweep = '2' }).sweep_level, 2)
end)

t.case('sweep=true and sweep=3 fall back to level 0', function()
  t.eq(sweep_config({ sweep = 'true' }).sweep_level, 0)
  t.eq(sweep_config({ sweep = '3' }).sweep_level, 0)
end)

t.case('sweep_budget=20 sets budget 20 and marks it set', function()
  local cfg = sweep_config({ sweep_budget = '20' })
  t.eq(cfg.sweep_budget, 20)
  t.eq(cfg.sweep_budget_set, true)
end)

t.case('invalid sweep_budget falls back to 50 and is not set', function()
  for _, raw in ipairs({ '-1', 'abc' }) do
    local cfg = sweep_config({ sweep_budget = raw })
    t.eq(cfg.sweep_budget, 50)
    t.eq(cfg.sweep_budget_set, false)
  end
end)

t.suite('ntp probe')

local NTP_CPE = 'cpe:/a:ntp:ntp'
local NTP_PORT = { number = 123, protocol = 'udp', service = 'ntp',
  version = { cpe = { NTP_CPE }, version = '' } }
local NTP_READVAR = '\x16\x02\x00\x01' .. string.rep('\0', 8)

--- Return a readvar reply with a version field and a system field.
local function ntp_reply(version, system)
  return string.rep('\0', 12) .. 'version="' .. version
    .. '", system="' .. (system or 'Linux/2.6.24') .. '"'
end

--- Return a comm.exchange stub that replays script.reply or script.err.
-- The log counts the calls and records the requests sent.
local function ntp_stub(script)
  local log = { calls = 0, requests = {} }
  local function exchange(_, _, data, opts)
    log.calls = log.calls + 1
    table.insert(log.requests, { data = data, opts = opts })
    if script.err then return false, script.err end
    return true, script.reply
  end
  return log, exchange
end

--- Run add_nmap_matches on a host and an NTP port.
local function ntp_matches(scanner, ip, port)
  local matches = new_match_table()
  matches.data.ntp = {}
  scanner.modules.port_matches.add_nmap_matches({ ip = ip }, port or NTP_PORT,
      matches)
  return matches
end

t.case('ntpd 4.2.6p5 reply sets the version and patch level', function()
  local log, exchange = ntp_stub({
    reply = ntp_reply('ntpd 4.2.6p5@1.2349-o Mon Dec 1 2008'),
  })
  local scanner = t.load_scanner()
  scanner.stubs.comm.exchange = exchange
  local matches = ntp_matches(scanner, '10.2.0.1')
  t.truthy(matches.data.ntp[NTP_CPE]['4.2.6p5'])
  t.keys_eq(matches.data.nmap, {})
  t.eq(log.calls, 1)
  t.eq(log.requests[1].data, NTP_READVAR)
  t.eq(log.requests[1].opts.proto, 'udp')
end)

t.case('ntpd 4.2.8p15 reply sets the version and patch level', function()
  local _, exchange = ntp_stub({
    reply = ntp_reply('ntpd 4.2.8p15@1.3728-o Thu Jan 1 2026'),
  })
  local scanner = t.load_scanner()
  scanner.stubs.comm.exchange = exchange
  local matches = ntp_matches(scanner, '10.2.0.2')
  t.truthy(matches.data.ntp[NTP_CPE]['4.2.8p15'])
  t.keys_eq(matches.data.nmap, {})
end)

t.case('ntpd reply without a patch level keeps only the version', function()
  local _, exchange = ntp_stub({
    reply = ntp_reply('ntpd 4.2.8@1.3728-o'),
  })
  local scanner = t.load_scanner()
  scanner.stubs.comm.exchange = exchange
  local matches = ntp_matches(scanner, '10.2.0.3')
  t.truthy(matches.data.ntp[NTP_CPE]['4.2.8'])
  t.keys_eq(matches.data.nmap, {})
end)

t.case('non-ntpd, garbage and failed replies fall back to nmap', function()
  local cases = {
    { reply = ntp_reply('ntpsec 1.2.0') },
    { reply = ntp_reply('chrony 4.0') },
    { reply = 'garbage without a header' },
    { err = 'timeout' },
  }
  for i, script in ipairs(cases) do
    local _, exchange = ntp_stub(script)
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = exchange
    local matches = ntp_matches(scanner, '10.2.0.4')
    t.keys_eq(matches.data.ntp, {}, tostring(i))
    t.truthy(matches.data.nmap[NTP_CPE]['*'], tostring(i))
  end
end)

t.case('precise nmap version skips the ntp probe', function()
  local log, exchange = ntp_stub({ reply = ntp_reply('ntpd 4.2.6p5') })
  local scanner = t.load_scanner()
  scanner.stubs.comm.exchange = exchange
  local port = { number = 123, service = 'ntp',
    version = { cpe = { NTP_CPE }, version = '4.2.8p15' } }
  local matches = ntp_matches(scanner, '10.2.0.5', port)
  t.eq(log.calls, 0)
  t.truthy(matches.data.nmap[NTP_CPE]['4.2.8p15'])
end)

t.case('nmap series versions 4 and v4 still run the ntp probe', function()
  for _, version in ipairs({ '4', 'v4' }) do
    local log, exchange = ntp_stub({ reply = ntp_reply('ntpd 4.2.6p5') })
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = exchange
    local port = { number = 123, service = 'ntp',
      version = { cpe = { NTP_CPE }, version = version } }
    local matches = ntp_matches(scanner, '10.2.0.6', port)
    t.eq(log.calls, 1, version)
    t.truthy(matches.data.ntp[NTP_CPE]['4.2.6p5'], version)
  end
end)

t.case('ntp probe does not run on an http service', function()
  local log, exchange = ntp_stub({ reply = ntp_reply('ntpd 4.2.6p5') })
  local scanner = t.load_scanner()
  scanner.stubs.comm.exchange = exchange
  local port = { number = 123, service = 'http',
    version = { cpe = { NTP_CPE }, version = '' } }
  local matches = ntp_matches(scanner, '10.2.0.7', port)
  t.eq(log.calls, 0)
  t.truthy(matches.data.nmap[NTP_CPE]['*'])
end)

t.case('probes=none and probes=irc skip the ntp probe', function()
  for _, arg in ipairs({ 'none', 'irc' }) do
    local log, exchange = ntp_stub({ reply = ntp_reply('ntpd 4.2.6p5') })
    local scanner = t.load_scanner({ args = { probes = arg } })
    scanner.stubs.comm.exchange = exchange
    local matches = ntp_matches(scanner, '10.2.0.8')
    t.eq(log.calls, 0, arg)
    t.truthy(matches.data.nmap[NTP_CPE]['*'], arg)
  end
end)

t.case('ntp probe is cached per ip and port', function()
  local log, exchange = ntp_stub({ reply = ntp_reply('ntpd 4.2.6p5') })
  local scanner = t.load_scanner()
  scanner.stubs.comm.exchange = exchange
  for _ = 1, 2 do
    local matches = ntp_matches(scanner, '10.2.0.9')
    t.truthy(matches.data.ntp[NTP_CPE]['4.2.6p5'])
    t.keys_eq(matches.data.nmap, {})
  end
  t.eq(log.calls, 1)
end)

--- Return an NTP port that Nmap identified without a CPE.
local function ntp_no_cpe_port(version, service)
  return { number = 123, protocol = 'udp', service = service or 'ntp',
    version = { version = version } }
end

t.case('ntp without nmap cpe runs the no_cpe probe', function()
  for _, version in ipairs({ '', 'NTP v4', 'v4' }) do
    local log, exchange = ntp_stub({
      reply = ntp_reply('ntpd 4.2.8p4@1.3265-o'),
    })
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = exchange
    local port = ntp_no_cpe_port(version)
    local matches = ntp_matches(scanner, '10.2.0.10', port)
    t.eq(log.calls, 1, version)
    t.truthy(matches.data.ntp[NTP_CPE]['4.2.8p4'], version)
    t.keys_eq(matches.data.nmap, {}, version)
  end
end)

t.case('ntp without nmap cpe and no reply adds nothing', function()
  local log, exchange = ntp_stub({ err = 'timeout' })
  local scanner = t.load_scanner()
  scanner.stubs.comm.exchange = exchange
  local matches = ntp_matches(scanner, '10.2.0.11', ntp_no_cpe_port(''))
  t.eq(log.calls, 1)
  t.keys_eq(matches.data.ntp, {})
  t.keys_eq(matches.data.nmap, {})
end)

t.case('ntp without nmap cpe and precise version skips probe', function()
  local log, exchange = ntp_stub({ reply = ntp_reply('ntpd 4.2.8p4') })
  local scanner = t.load_scanner()
  scanner.stubs.comm.exchange = exchange
  local matches = ntp_matches(scanner, '10.2.0.12',
    ntp_no_cpe_port('4.2.8p4'))
  t.eq(log.calls, 0)
  t.keys_eq(matches.data.ntp, {})
end)

t.case('no_cpe probe never runs on a non-ntp service', function()
  local log, exchange = ntp_stub({ reply = ntp_reply('ntpd 4.2.8p4') })
  local scanner = t.load_scanner()
  scanner.stubs.comm.exchange = exchange
  local matches = ntp_matches(scanner, '10.2.0.13',
    ntp_no_cpe_port('', 'http'))
  t.eq(log.calls, 0)
  t.keys_eq(matches.data.ntp, {})
end)

t.case('probes=none skips the no_cpe ntp probe', function()
  local log, exchange = ntp_stub({ reply = ntp_reply('ntpd 4.2.8p4') })
  local scanner = t.load_scanner({ args = { probes = 'none' } })
  scanner.stubs.comm.exchange = exchange
  local matches = ntp_matches(scanner, '10.2.0.14', ntp_no_cpe_port(''))
  t.eq(log.calls, 0)
  t.keys_eq(matches.data.ntp, {})
end)

t.suite('local catalogue overlay')

-- The overlay file holds plain text; the stubbed parser maps that text to
-- the decoded table, so no JSON library is needed.
local function overlay_file(body)
  local path = os.tmpname()
  local file = assert(io.open(path, 'w'))
  file:write(body)
  file:close()
  return path
end

local function overlay_scanner(decoded)
  return t.load_scanner({ json = {
    parse = function(body)
      if decoded[body] then return true, decoded[body] end
      return false
    end,
    generate = function() return '{}' end
  } })
end

local function upstream_scanner(decoded)
  local scanner = overlay_scanner(decoded)
  scanner.modules.state.catalog_loaded = true
  scanner.modules.state.catalog = {
    fingerprints = s.modules.validate.validate_fingerprints(
      { rules = { nginx = rule } }),
    paths = { '/' },
    probes = {}
  }
  return scanner
end

local local_rule = { alias = 'cpe:/a:acme:portal', channel = 'hdr:server',
  regex = 'Portal/([%d.]+)', anchor = 'Portal' }

t.case('valid overlay fingerprint is merged and matches a banner', function()
  local path = overlay_file('fp')
  local scanner = upstream_scanner({
    fp = { fingerprints = { rules = { portal = local_rule } } } })
  local store = package.loaded['cvescannerv2.catalog.store']
  t.eq(store.load_local_catalog(path), true)
  os.remove(path)
  t.eq(#scanner.modules.state.catalog.fingerprints['hdr:server'], 2)
  local matches, triggered = new_match_table(), {}
  scanner.modules.fingerprint_match.match_subjects(
    { ['hdr:server'] = { 'Portal/2.3' } }, matches, 'http', triggered)
  t.truthy(matches.data.http['cpe:/a:acme:portal']['2.3'])
end)

t.case('invalid overlay section is dropped, valid ones are kept', function()
  local path = overlay_file('mixed')
  local bad_rule = { alias = 'cpe:/a:x:y', channel = 'body', regex = '([%d' }
  local scanner = upstream_scanner({ mixed = {
    fingerprints = { rules = { bad = bad_rule } },
    paths = { paths = { '/admin/' } } } })
  local store = package.loaded['cvescannerv2.catalog.store']
  store.load_local_catalog(path)
  os.remove(path)
  t.eq(#scanner.modules.state.catalog.fingerprints['hdr:server'], 1)
  t.eq(scanner.modules.state.catalog.fingerprints.body, nil)
  t.eq(scanner.modules.state.catalog.paths, { '/', '/admin/' })
end)

t.case('absent overlay file leaves the catalogue identical', function()
  local scanner = upstream_scanner({})
  local store = package.loaded['cvescannerv2.catalog.store']
  local before = t.serialize(scanner.modules.state.catalog)
  t.eq(store.load_local_catalog('data/no-such-overlay.json'), false)
  t.eq(t.serialize(scanner.modules.state.catalog), before)
end)

t.case('invalid JSON overlay leaves the catalogue identical', function()
  local path = overlay_file('broken')
  local scanner = upstream_scanner({})
  local store = package.loaded['cvescannerv2.catalog.store']
  local before = t.serialize(scanner.modules.state.catalog)
  t.eq(store.load_local_catalog(path), false)
  os.remove(path)
  t.eq(t.serialize(scanner.modules.state.catalog), before)
end)

t.case('local_catalog=none leaves the catalogue identical', function()
  local path = overlay_file('fp')
  local scanner = upstream_scanner({
    fp = { fingerprints = { rules = { portal = local_rule } } } })
  local store = package.loaded['cvescannerv2.catalog.store']
  local before = t.serialize(scanner.modules.state.catalog)
  t.eq(store.load_local_catalog('none'), false)
  os.remove(path)
  t.eq(t.serialize(scanner.modules.state.catalog), before)
end)

t.case('overlay is ignored without an upstream catalogue', function()
  local path = overlay_file('fp')
  local scanner = overlay_scanner({
    fp = { fingerprints = { rules = { portal = local_rule } } } })
  local store = package.loaded['cvescannerv2.catalog.store']
  t.eq(store.load_local_catalog(path), false)
  os.remove(path)
  t.eq(scanner.modules.state.catalog.fingerprints, {})
end)

t.case('overlay never writes files', function()
  local path = overlay_file('fp')
  upstream_scanner({
    fp = { fingerprints = { rules = { portal = local_rule } } } })
  local store = package.loaded['cvescannerv2.catalog.store']
  local original_open = io.open
  local modes = {}
  io.open = function(name, mode)
    table.insert(modes, mode or 'r')
    return original_open(name, mode)
  end
  local ok, err = pcall(store.load_local_catalog, path)
  io.open = original_open
  os.remove(path)
  t.truthy(ok, err)
  for _, mode in ipairs(modes) do
    t.eq(mode:find('[wa+]') == nil, true, 'mode ' .. mode)
  end
end)

t.suite('catalogue tiers')

-- Catalogue files served from memory for data/ reads; other paths are real.
local TIER_FILES = {
  ['data/index.json'] = 'index',
  ['data/fingerprints.json'] = 'fingerprints',
  ['data/paths.json'] = 'paths',
  ['data/probes.json'] = 'probes',
}

local TIER_JSON = {
  index = { schema = 1, catalogs = {
    fingerprints = { file = 'fingerprints.json' },
    paths = { file = 'paths.json' },
    probes = { file = 'probes.json' } } },
  fingerprints = { rules = { nginx = rule } },
  paths = { paths = { '/', '/index.php' } },
  probes = { schema = 1, probes = { probe } },
  nuevo = { paths = { paths = { '/nuevo.php' } } },
}

--- Run fn with the TIER_FILES bodies served by io.open.
local function with_data_files(fn)
  local original_open = io.open
  io.open = function(name, mode)
    local body = TIER_FILES[name]
    if body == nil then return original_open(name, mode) end
    return { read = function() return body end, close = function() end }
  end
  local ok, err = pcall(fn)
  io.open = original_open
  if not ok then error(err, 0) end
end

--- Return true when list holds item.
local function contains(list, item)
  for _, value in ipairs(list or {}) do
    if value == item then return true end
  end
  return false
end

t.case('load_catalog builds the sweep tiers', function()
  local scanner = overlay_scanner(TIER_JSON)
  local store = package.loaded['cvescannerv2.catalog.store']
  with_data_files(function()
    t.eq(store.load_catalog(), true)
  end)
  local sweep = scanner.modules.state.catalog.sweep
  t.eq(type(sweep.core), 'table')
  t.eq(type(sweep.families), 'table')
  t.eq(type(sweep.tail), 'table')
end)

t.case('local overlay path is appended to the php family', function()
  local path = overlay_file('nuevo')
  local scanner = overlay_scanner(TIER_JSON)
  local store = package.loaded['cvescannerv2.catalog.store']
  with_data_files(function()
    store.load_catalog()
    t.eq(store.load_local_catalog(path), true)
  end)
  os.remove(path)
  local php = scanner.modules.state.catalog.sweep.families.php or {}
  t.eq(php[#php], '/nuevo.php')
end)

t.case('without an overlay the sweep has no local path', function()
  local scanner = overlay_scanner(TIER_JSON)
  local store = package.loaded['cvescannerv2.catalog.store']
  with_data_files(function()
    store.load_catalog()
    t.eq(store.load_local_catalog('data/no-such-overlay.json'), false)
  end)
  local sweep = scanner.modules.state.catalog.sweep
  t.eq(contains(sweep.families.php, '/nuevo.php'), false)
end)

t.suite('cups title fingerprint')

local CUPS_CPE = 'cpe:/a:apple:cups'
local CUPS_403 = '<HTML><HEAD><TITLE>Forbidden - CUPS v2.1.3</TITLE>'
  .. '</HEAD><BODY>403</BODY></HTML>'

--- Return a scanner whose overlay holds the local CUPS title rule.
-- The rule text matches data/local-catalog.json; the stubbed parser maps
-- the overlay file to the decoded table. Pass accept_403 = true to set
-- the opt-in flag that the shipped rule carries.
local function cups_scanner(http, accept_403)
  local path = overlay_file('cups')
  local scanner = t.load_scanner({ http = http, json = {
    parse = function(body)
      if body ~= 'cups' then return false end
      return true, { fingerprints = { rules = { cups = {
        alias = CUPS_CPE, anchor = 'CUPS', channel = 'title',
        regex = 'CUPS v?(%d+%.%d+[%.%d]*)',
        accept_403 = accept_403 } } } }
    end,
    generate = function() return '{}' end
  } })
  scanner.modules.state.catalog_loaded = true
  scanner.modules.state.catalog = { fingerprints = {}, paths = { '/' },
    probes = {} }
  local store = package.loaded['cvescannerv2.catalog.store']
  store.load_local_catalog(path)
  os.remove(path)
  return scanner
end

--- Return an http stub whose pipeline answers with one fixed response.
local function cups_http(status, body)
  return {
    pipeline_add = function(path, _, requests)
      requests = requests or {}
      table.insert(requests, path)
      return requests
    end,
    pipeline_go = function()
      return { { status = status, body = body, header = {} } }
    end
  }
end

t.case('shipped overlay has no CUPS rule (cups probe covers it)', function()
  local file = assert(io.open('data/local-catalog.json', 'r'))
  local body = file:read('*all')
  file:close()
  t.eq(body:find('cpe:/a:apple:cups', 1, true), nil)
  t.eq(body:find('accept_403', 1, true), nil)
end)

t.case('CUPS title with version is matched as http', function()
  local scanner = cups_scanner({})
  t.eq(#scanner.modules.state.catalog.fingerprints.title, 1)
  local matches, triggered = new_match_table(), {}
  scanner.modules.fingerprint_match.match_subjects(
    { title = { 'Forbidden - CUPS v2.1.3' } }, matches, 'http', triggered)
  t.keys_eq(matches.data.http[CUPS_CPE], { '2.1.3' })
  t.eq(matches.data.nmap[CUPS_CPE], nil)
end)

t.case('CUPS word without a version is not matched', function()
  local scanner = cups_scanner({})
  local matches, triggered = new_match_table(), {}
  scanner.modules.fingerprint_match.match_subjects({ title = { 'Forbidden - CUPS',
    'Ubuntu CUPS print server' } }, matches, 'http', triggered)
  t.eq(matches.data.http[CUPS_CPE], nil)
  t.eq(matches.size, 0)
end)

t.case('title without a version number is not matched', function()
  local scanner = cups_scanner({})
  local matches, triggered = new_match_table(), {}
  scanner.modules.fingerprint_match.match_subjects(
    { title = { 'CUPS version unknown' } }, matches, 'http', triggered)
  t.eq(matches.data.http[CUPS_CPE], nil)
end)

t.case('403 with an accept_403 rule yields the CUPS version', function()
  local scanner = cups_scanner(cups_http(403, CUPS_403), true)
  local matches, triggered = new_match_table(), {}
  scanner.modules.http_fingerprint.sweep_catalog({}, { number = 631 }, matches,
      triggered)
  t.keys_eq(matches.data.http[CUPS_CPE], { '2.1.3' })
end)

t.case('403 with a rule lacking the flag is not matched', function()
  local scanner = cups_scanner(cups_http(403, CUPS_403))
  local matches, triggered = new_match_table(), {}
  scanner.modules.http_fingerprint.sweep_catalog({}, { number = 631 }, matches,
      triggered)
  t.eq(matches.data.http[CUPS_CPE], nil)
  t.eq(matches.size, 0)
end)

t.case('403 does not trigger or run targeted probes', function()
  local gets = 0
  local http = cups_http(403, CUPS_403)
  http.get = function()
    gets = gets + 1
    return { status = 403, body = CUPS_403, header = {} }
  end
  local scanner = cups_scanner(http, true)
  scanner.modules.state.catalog.probes = { {
    alias = CUPS_CPE, name = 'cups',
    detect = { { channel = 'title', anchor = 'CUPS', regex = 'CUPS' } },
    extract = { { anchor = 'CUPS', regex = 'CUPS v?(%d+%.%d+[%.%d]*)' } },
    paths = { '/cups' }
  } }
  local matches, triggered = new_match_table(), {}
  scanner.modules.http_fingerprint.sweep_catalog({}, { number = 631 }, matches,
      triggered)
  t.eq(triggered[CUPS_CPE], nil)
  scanner.modules.http_fingerprint.run_targeted_probes({}, { number = 631 }, matches,
      triggered)
  t.eq(gets, 0)
end)

t.case('200 with the CUPS title matches a rule without the flag', function()
  local scanner = cups_scanner(cups_http(200, CUPS_403))
  local matches, triggered = new_match_table(), {}
  scanner.modules.http_fingerprint.sweep_catalog({}, { number = 631 }, matches,
      triggered)
  t.keys_eq(matches.data.http[CUPS_CPE], { '2.1.3' })
end)

t.case('accept_403 must be boolean or the rule is rejected', function()
  local accept_rule = { alias = CUPS_CPE, channel = 'title',
    regex = 'CUPS v?(%d+%.%d+[%.%d]*)' }
  accept_rule.accept_403 = 'yes'
  t.eq(s.modules.validate.validate_fingerprints({
    rules = { cups = accept_rule } }), nil)
  accept_rule.accept_403 = true
  t.eq(s.modules.validate.validate_fingerprints({
    rules = { cups = accept_rule } }).title[1].accept_403, true)
  accept_rule.accept_403 = nil
  t.eq(s.modules.validate.validate_fingerprints({
    rules = { cups = accept_rule } }).title[1].accept_403, false)
end)

t.case('404 body with the CUPS title is ignored', function()
  local scanner = cups_scanner(cups_http(404, CUPS_403))
  local matches, triggered = new_match_table(), {}
  scanner.modules.http_fingerprint.sweep_catalog({}, { number = 631 }, matches,
      triggered)
  t.eq(matches.data.http[CUPS_CPE], nil)
end)

do
  local port_ipp = { number = 631, service = 'ipp',
    version = { cpe = { CUPS_CPE }, version = '2.1' } }

  --- Return a scanner whose http.get is get, and the request counter.
  local function cups_probe_scanner(get, args)
    local calls = { gets = 0 }
    local scanner = t.load_scanner({ args = args, http = { get = function(...)
      calls.gets = calls.gets + 1
      return get(...)
    end } })
    return scanner, calls
  end

  --- Add the CUPS port to the matches through add_nmap_matches.
  local function cups_add(scanner, port)
    local matches = new_match_table()
    matches.data.cups = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = '10.2.0.1' },
        port or port_ipp, matches)
    return matches
  end

  --- Return a get function that answers one fixed page.
  local function page(status, body)
    return function()
      return { status = status, body = body, header = {} }
    end
  end

  t.suite('cups ipp probe')

  t.case('200 title with CUPS version sets the probe version', function()
    local scanner, calls = cups_probe_scanner(page(200,
      '<HTML><HEAD><TITLE>Home - CUPS 2.1.3</TITLE></HEAD></HTML>'))
    local matches = cups_add(scanner)
    t.keys_eq(matches.data.cups[CUPS_CPE], { '2.1.3' })
    t.eq(calls.gets, 1)
    t.keys_eq(matches.data.nmap, {})
  end)

  t.case('403 title with CUPS version sets the probe version', function()
    local scanner = cups_probe_scanner(page(403, CUPS_403))
    local matches = cups_add(scanner)
    t.keys_eq(matches.data.cups[CUPS_CPE], { '2.1.3' })
    t.keys_eq(matches.data.nmap, {})
  end)

  t.case('title tag is matched in any letter case', function()
    local scanner = cups_probe_scanner(page(200,
      '<title>Home - CUPS 2.1.3</title>'))
    local matches = cups_add(scanner)
    t.keys_eq(matches.data.cups[CUPS_CPE], { '2.1.3' })
    t.keys_eq(matches.data.nmap, {})
  end)

  t.case('other product title keeps the nmap cpe', function()
    local scanner = cups_probe_scanner(page(200,
      '<TITLE>Apache 2.4.7</TITLE>'))
    local matches = cups_add(scanner)
    t.keys_eq(matches.data.cups, {})
    t.truthy(matches.data.nmap[CUPS_CPE]['2.1'])
  end)

  t.case('body without a title tag is ignored', function()
    local scanner = cups_probe_scanner(page(200, 'CUPS 2.1.3'))
    local matches = cups_add(scanner)
    t.keys_eq(matches.data.cups, {})
    t.truthy(matches.data.nmap[CUPS_CPE]['2.1'])
  end)

  t.case('other status codes keep the nmap cpe', function()
    for _, status in ipairs({ 404, 500 }) do
      local scanner = cups_probe_scanner(page(status, CUPS_403))
      local matches = cups_add(scanner)
      t.keys_eq(matches.data.cups, {}, tostring(status))
      t.truthy(matches.data.nmap[CUPS_CPE]['2.1'], tostring(status))
    end
  end)

  t.case('failed or raising http.get keeps the nmap cpe', function()
    local failures = {
      function() return nil end,
      function() error('boom') end,
    }
    for i, get in ipairs(failures) do
      local scanner = cups_probe_scanner(get)
      local matches = cups_add(scanner)
      t.keys_eq(matches.data.cups, {}, tostring(i))
      t.truthy(matches.data.nmap[CUPS_CPE]['2.1'], tostring(i))
    end
  end)

  t.case('precise nmap version skips the cups probe', function()
    local scanner, calls = cups_probe_scanner(page(200, CUPS_403))
    local port = { number = 631, service = 'ipp',
      version = { cpe = { CUPS_CPE }, version = '2.1.3' } }
    local matches = cups_add(scanner, port)
    t.eq(calls.gets, 0)
    t.truthy(matches.data.nmap[CUPS_CPE]['2.1.3'])
  end)

  t.case('http service on 631 skips the cups probe', function()
    local scanner, calls = cups_probe_scanner(page(200, CUPS_403))
    local port = { number = 631, service = 'http',
      version = { cpe = { CUPS_CPE }, version = '2.1' } }
    cups_add(scanner, port)
    t.eq(calls.gets, 0)
  end)

  t.case('other product on an ipp port skips the cups probe', function()
    local scanner, calls = cups_probe_scanner(page(200, CUPS_403))
    local port = { number = 631, service = 'ipp',
      version = { cpe = { 'cpe:/a:ngircd:ngircd' }, version = '' } }
    cups_add(scanner, port)
    t.eq(calls.gets, 0)
  end)

  t.case('probes=none and probes=smb skip the cups probe', function()
    for _, arg in ipairs({ 'none', 'smb' }) do
      local scanner, calls = cups_probe_scanner(page(200, CUPS_403),
        { probes = arg })
      local matches = cups_add(scanner)
      t.eq(calls.gets, 0, arg)
      t.truthy(matches.data.nmap[CUPS_CPE]['2.1'], arg)
    end
  end)

  t.case('cups probe is cached per host and port', function()
    local scanner, calls = cups_probe_scanner(page(200, CUPS_403))
    for _ = 1, 2 do
      local matches = cups_add(scanner)
      t.keys_eq(matches.data.cups[CUPS_CPE], { '2.1.3' })
    end
    t.eq(calls.gets, 1)
  end)
end

t.suite('version script dependencies')

t.case('dependencies lists the version scripts', function()
  local file = assert(io.open('nmap/src/cvescannerv2.nse', 'r'))
  local body = file:read('*all')
  file:close()
  local block = body:match('\ndependencies = (%b{})')
  t.truthy(block, 'dependencies block missing')
  local seen = {}
  for name in block:gmatch('"([^"]+)"') do seen[name] = true end
  t.keys_eq(seen, {
    'weblogic-t3-info', 'oracle-tns-version', 'docker-version',
    'jdwp-version', 'vmware-version', 'db2-das-info', 'ike-version',
    'mqtt-subscribe', 'amqp-info', 'xmpp-info',
  })
end)

do
  t.suite('upnp probe')

  local UPNP_CPE = 'cpe:/a:miniupnp_project:miniupnpd'

  --- Return an SSDP reply with a SERVER header.
  local function upnp_reply(server)
    return 'HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n'
      .. 'ST: upnp:rootdevice\r\nSERVER: ' .. server .. '\r\n'
      .. 'EXT:\r\n\r\n'
  end

  --- Return a UPnP port that Nmap identified without a CPE.
  local function upnp_port(service, version)
    return { number = 1900, protocol = 'udp', service = service or 'upnp',
      version = { version = version or '' } }
  end

  --- Run add_nmap_matches on a host and a UPnP port.
  local function upnp_matches(scanner, ip, port)
    local matches = new_match_table()
    matches.data.upnp = {}
    scanner.modules.port_matches.add_nmap_matches({ ip = ip }, port or upnp_port(),
        matches)
    return matches
  end

  t.case('miniupnpd SERVER header sets the version', function()
    local log, exchange = ntp_stub({
      reply = upnp_reply('Debian/stretch/sid UPnP/1.1 MiniUPnPd/1.8'),
    })
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = exchange
    local matches = upnp_matches(scanner, '10.3.0.1')
    t.eq(log.calls, 1)
    t.truthy(matches.data.upnp[UPNP_CPE]['1.8'])
    t.keys_eq(matches.data.nmap, {})
  end)

  t.case('miniupnpd version with a build suffix keeps all digits', function()
    local _, exchange = ntp_stub({
      reply = upnp_reply('Linux/5.4 UPnP/1.1 miniupnpd/2.1.20190625'),
    })
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = exchange
    local matches = upnp_matches(scanner, '10.3.0.2')
    t.truthy(matches.data.upnp[UPNP_CPE]['2.1.20190625'])
    t.keys_eq(matches.data.nmap, {})
  end)

  t.case('other UPnP servers add nothing', function()
    local replies = {
      'Microsoft-Windows/10.0 UPnP/1.0 Windows-Device/1.0',
      'Linux/3.10 UPnP/1.0 IGD/1.00',
      'MiniUPnPd without version',
    }
    for i, server in ipairs(replies) do
      local _, exchange = ntp_stub({ reply = upnp_reply(server) })
      local scanner = t.load_scanner()
      scanner.stubs.comm.exchange = exchange
      local matches = upnp_matches(scanner, '10.3.0.3.' .. i)
      t.keys_eq(matches.data.upnp, {}, server)
    end
  end)

  t.case('empty, timeout and error replies add nothing', function()
    local scripts = {
      { reply = '' },
      { err = 'timeout' },
    }
    for i, script in ipairs(scripts) do
      local log, exchange = ntp_stub(script)
      local scanner = t.load_scanner()
      scanner.stubs.comm.exchange = exchange
      local matches = upnp_matches(scanner, '10.3.0.4.' .. i)
      t.eq(log.calls, 1, tostring(i))
      t.keys_eq(matches.data.upnp, {}, tostring(i))
    end
  end)

  t.case('exchange errors are caught and add nothing', function()
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = function()
      error('socket failure')
    end
    local matches = upnp_matches(scanner, '10.3.0.5')
    t.keys_eq(matches.data.upnp, {})
  end)

  t.case('upnp request is an SSDP M-SEARCH over udp', function()
    local log, exchange = ntp_stub({
      reply = upnp_reply('MiniUPnPd/1.8'),
    })
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = exchange
    upnp_matches(scanner, '10.3.0.6')
    local request = log.requests[1]
    t.eq(request.data, 'M-SEARCH * HTTP/1.1\r\n'
      .. 'HOST: 239.255.255.250:1900\r\n'
      .. 'MAN: "ssdp:discover"\r\n'
      .. 'MX: 1\r\n'
      .. 'ST: upnp:rootdevice\r\n\r\n')
    t.eq(request.opts.proto, 'udp')
    t.eq(request.opts.timeout, 3000)
  end)

  t.case('precise nmap version skips the upnp probe', function()
    local log, exchange = ntp_stub({ reply = upnp_reply('MiniUPnPd/1.8') })
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = exchange
    local matches = upnp_matches(scanner, '10.3.0.7',
      upnp_port('upnp', '2.1.20190625'))
    t.eq(log.calls, 0)
    t.keys_eq(matches.data.upnp, {})
  end)

  t.case('upnp probe does not run on an http service', function()
    local log, exchange = ntp_stub({ reply = upnp_reply('MiniUPnPd/1.8') })
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = exchange
    local matches = upnp_matches(scanner, '10.3.0.8', upnp_port('http'))
    t.eq(log.calls, 0)
    t.keys_eq(matches.data.upnp, {})
  end)

  t.case('probes=none and probes=ntp skip the upnp probe', function()
    for _, arg in ipairs({ 'none', 'ntp' }) do
      local log, exchange = ntp_stub({ reply = upnp_reply('MiniUPnPd/1.8') })
      local scanner = t.load_scanner({ args = { probes = arg } })
      scanner.stubs.comm.exchange = exchange
      local matches = upnp_matches(scanner, '10.3.0.9')
      t.eq(log.calls, 0, arg)
      t.keys_eq(matches.data.upnp, {}, arg)
    end
  end)

  t.case('upnp probe is cached per ip and port', function()
    local log, exchange = ntp_stub({ reply = upnp_reply('MiniUPnPd/1.8') })
    local scanner = t.load_scanner()
    scanner.stubs.comm.exchange = exchange
    for _ = 1, 2 do
      local matches = upnp_matches(scanner, '10.3.0.10')
      t.truthy(matches.data.upnp[UPNP_CPE]['1.8'])
      t.keys_eq(matches.data.nmap, {})
    end
    t.eq(log.calls, 1)
  end)
end

t.suite('product CPE overrides')

local GLASSFISH_CPE = 'cpe:/a:oracle:glassfish_server'
local GLASSFISH_TABLE = { ['Oracle GlassFish'] = GLASSFISH_CPE }

-- Build a port whose Nmap product, CPE and version are given.
local function product_port(product, cpe, version)
  return { number = 8080, protocol = 'tcp', service = 'http',
    version = { product = product, cpe = { cpe }, version = version } }
end

local function product_matches(scanner, port)
  local matches = new_match_table()
  scanner.modules.port_matches.add_nmap_matches({ ip = '10.4.0.1' }, port, matches)
  return matches
end

t.case('listed product replaces the wrong nmap cpe', function()
  local scanner = t.load_scanner()
  scanner.modules.state.product_cpe = GLASSFISH_TABLE
  local matches = product_matches(scanner, product_port('Oracle GlassFish',
    'cpe:/a:oracle:jsp:2.3', '4.0'))
  t.truthy(matches.data.nmap[GLASSFISH_CPE]['4.0'])
  t.eq(matches.data.nmap['cpe:/a:oracle:jsp:2.3'], nil)
  t.keys_eq(matches.data.nmap, { GLASSFISH_CPE })
  t.eq(matches.size, 1)
end)

t.case('listed product without an nmap cpe uses the table cpe', function()
  local scanner = t.load_scanner()
  scanner.modules.state.product_cpe = GLASSFISH_TABLE
  local matches = product_matches(scanner, product_port('Oracle GlassFish',
    nil, '4.0'))
  t.truthy(matches.data.nmap[GLASSFISH_CPE]['4.0'])
  t.keys_eq(matches.data.nmap, { GLASSFISH_CPE })
end)

t.case('listed product with empty version uses the wildcard', function()
  local scanner = t.load_scanner()
  scanner.modules.state.product_cpe = GLASSFISH_TABLE
  local matches = product_matches(scanner, product_port('Oracle GlassFish',
    'cpe:/a:oracle:jsp:2.3', ''))
  t.truthy(matches.data.nmap[GLASSFISH_CPE]['*'])
end)

t.case('listed product keeps the first numeric version token', function()
  local scanner = t.load_scanner()
  scanner.modules.state.product_cpe = GLASSFISH_TABLE
  local matches = product_matches(scanner, product_port('Oracle GlassFish',
    'cpe:/a:oracle:jsp:2.3', 'build 4.0.1 x'))
  t.truthy(matches.data.nmap[GLASSFISH_CPE]['4.0.1'])
end)

t.case('product aliases apply to the table cpe', function()
  local scanner = t.load_scanner()
  scanner.modules.state.product_cpe = GLASSFISH_TABLE
  scanner.modules.state.product_aliases = { glassfish_server = { 'glassfish' } }
  local matches = product_matches(scanner, product_port('Oracle GlassFish',
    'cpe:/a:oracle:jsp:2.3', '4.0'))
  t.truthy(matches.data.nmap[GLASSFISH_CPE]['4.0'])
  t.truthy(matches.data.nmap['cpe:/a:oracle:glassfish']['4.0'])
  t.eq(matches.size, 2)
end)

t.case('unlisted product keeps the nmap cpe', function()
  local scanner = t.load_scanner()
  scanner.modules.state.product_cpe = GLASSFISH_TABLE
  local matches = product_matches(scanner, product_port('Apache Tomcat',
    'cpe:/a:apache:tomcat:9.0', '9.0'))
  t.truthy(matches.data.nmap['cpe:/a:apache:tomcat:9.0']['9.0'])
  t.keys_eq(matches.data.nmap, { 'cpe:/a:apache:tomcat:9.0' })
end)

t.case('empty table keeps the nmap cpe', function()
  local scanner = t.load_scanner()
  local matches = product_matches(scanner, product_port('Oracle GlassFish',
    'cpe:/a:oracle:jsp:2.3', '4.0'))
  t.keys_eq(matches.data.nmap, { 'cpe:/a:oracle:jsp:2.3' })
end)

t.case('invalid product cpe files leave the table empty', function()
  local broken = overlay_file('{ broken')
  local scanner = overlay_scanner({})
  t.eq(scanner.modules.reference_files.load_reference_file(broken, 'product_cpe'), false)
  t.eq(scanner.modules.state.product_cpe, {})

  local wrong = overlay_file('wrong')
  local bad = overlay_scanner({ wrong = { ['Oracle GlassFish'] = 42 } })
  t.eq(bad.modules.reference_files.load_reference_file(wrong, 'product_cpe'), false)
  t.eq(bad.modules.state.product_cpe, {})

  local versioned = overlay_file('versioned')
  local versions = overlay_scanner({
    versioned = { ['Oracle GlassFish'] = 'cpe:/a:oracle:glassfish:4.0' } })
  t.eq(versions.modules.reference_files.load_reference_file(versioned, 'product_cpe'), false)
  t.eq(versions.modules.state.product_cpe, {})
end)

t.case('valid product cpe file fills the table', function()
  local path = overlay_file('good')
  local scanner = overlay_scanner({ good = GLASSFISH_TABLE })
  t.eq(scanner.modules.reference_files.load_reference_file(path, 'product_cpe'), true)
  t.eq(scanner.modules.state.product_cpe, GLASSFISH_TABLE)
end)

local MCAFEE_AGENT_CPE = 'cpe:/a:mcafee:agent'
local VENTRILO_CPE = 'cpe:/a:flagship_industries:ventrilo'

t.case('mcafee agent product maps to the agent cpe', function()
  local scanner = t.load_scanner()
  scanner.modules.state.product_cpe = {
    ['McAfee ePolicy Orchestrator Agent'] = MCAFEE_AGENT_CPE }
  local matches = product_matches(scanner, product_port(
    'McAfee ePolicy Orchestrator Agent',
    'cpe:/a:mcafee:epolicy_orchestrator', '5.0.5'))
  t.truthy(matches.data.nmap[MCAFEE_AGENT_CPE]['5.0.5'])
  t.keys_eq(matches.data.nmap, { MCAFEE_AGENT_CPE })
end)

t.case('ventrilo product maps to the ventrilo cpe', function()
  local scanner = t.load_scanner()
  scanner.modules.state.product_cpe = { ['Ventrilo'] = VENTRILO_CPE }
  local matches = product_matches(scanner, product_port('Ventrilo',
    'cpe:/a:ventrilo:ventrilo', '3.0.3'))
  t.truthy(matches.data.nmap[VENTRILO_CPE]['3.0.3'])
  t.keys_eq(matches.data.nmap, { VENTRILO_CPE })
end)
