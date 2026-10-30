-- SPDX-License-Identifier: GPL-3.0-or-later
-- HTTP fingerprint catalogue validation and response matching.

local t = require 'harness'
local s = t.load_scanner()

local function new_matches()
  return { data = { nmap = {}, http = {} }, size = 0 }
end

t.suite('pattern validation')

t.case('capture_count ignores escapes, classes and balances', function()
  t.eq(s.capture_count('(%d+)'), 1)
  t.eq(s.capture_count('%((%d+)%)'), 1)
  t.eq(s.capture_count('[(]x'), 0)
  t.eq(s.capture_count('(a)(b)'), 2)
  t.eq(s.capture_count('%b()'), 0)
  t.eq(s.capture_count('%f[%w](%d)'), 1)
end)

t.case('valid_pattern checks captures, syntax and size', function()
  t.truthy(s.valid_pattern('nginx/([%d.]+)', 1))
  t.eq(s.valid_pattern('nginx/([%d.]+)', 0), false)
  t.eq(s.valid_pattern('[a', 0), false)
  t.eq(s.valid_pattern('', 0), false)
  t.eq(s.valid_pattern(string.rep('a', 2049), 0), false)
end)

-- valid_pattern probes the pattern against an empty subject. Lua reports an
-- unfinished capture only when matching reaches the end of the pattern, so
-- the parentheses are counted explicitly in capture_count.
t.case('unbalanced capture is rejected', function()
  t.eq(s.valid_pattern('(%d+', 1), false)
end)

t.case('valid_alias accepts vendor:product CPEs only', function()
  t.truthy(s.valid_alias('cpe:/a:apache:http_server'))
  t.eq(s.valid_alias('cpe:/a:apache:http_server:2.4'), false)
  t.eq(s.valid_alias('cpe:2.3:a:apache:http_server'), false)
  t.eq(s.valid_alias(42), false)
end)

t.case('valid_channel', function()
  for _, channel in ipairs({ 'raw', 'body', 'title', 'script', 'cookie',
    'banner', 'hdr:server', 'meta:generator' }) do
    t.truthy(s.valid_channel(channel), channel)
  end
  t.eq(s.valid_channel('hdr:'), false)
  t.eq(s.valid_channel('foo'), false)
end)

t.case('valid_path', function()
  t.truthy(s.valid_path('/admin/'))
  t.eq(s.valid_path('admin'), false)
  t.eq(s.valid_path('/a b'), false)
  t.eq(s.valid_path('/x#y'), false)
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
  local by_channel = s.validate_fingerprints({ rules = { nginx = rule } })
  t.eq(by_channel['hdr:server'][1].alias, 'cpe:/a:f5:nginx')
end)

t.case('one invalid rule rejects the whole catalogue', function()
  local bad = { alias = 'cpe:/a:x:y', channel = 'body', regex = '([%d' }
  t.eq(s.validate_fingerprints({ rules = { nginx = rule, bad = bad } }), nil)
  t.eq(s.validate_fingerprints({ rules = {} }), nil)
end)

t.case('paths are deduplicated and validated', function()
  t.eq(s.validate_paths({ paths = { '/a', '/a', '/b' } }), { '/a', '/b' })
  t.eq(s.validate_paths({ paths = { '/a', 'b' } }), nil)
  t.eq(s.validate_paths({ paths = {} }), nil)
end)

t.case('probes require schema 1 and valid parts', function()
  t.eq(#s.validate_probes({ schema = 1, probes = { probe } }), 1)
  t.eq(s.validate_probes({ schema = 2, probes = { probe } }), nil)
  local broken = { alias = probe.alias, detect = probe.detect,
    extract = probe.extract, paths = { 'about' } }
  t.eq(s.validate_probes({ schema = 1, probes = { broken } }), nil)
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
  local loaded = s.build_catalog(index, function(name) return files[name] end)
  t.truthy(loaded and loaded.fingerprints and loaded.paths and loaded.probes)
  index.catalogs.paths.file = 'other.json'
  t.eq(s.build_catalog(index, function(name) return files[name] end), nil)
end)

t.suite('response matching')

t.case('safe_version trims and rejects junk', function()
  t.eq(s.safe_version(' 1.2 '), '1.2')
  t.eq(s.safe_version('*'), nil)
  t.eq(s.safe_version(''), nil)
  t.eq(s.safe_version('...'), nil)
  t.eq(s.safe_version('1.2\n3'), nil)
  t.eq(s.safe_version(string.rep('1', 129)), nil)
end)

t.case('anchored_capture searches near the anchor only', function()
  t.eq(s.anchored_capture('nginx/([%d.]+)', 'nginx', 'Server: nginx/1.4.6'),
    '1.4.6')
  t.eq(s.anchored_capture('nginx/([%d.]+)', 'apache', 'nginx/1.4.6'), nil)
  local far = 'Acme' .. string.rep(' ', 600) .. 'v9.9'
  t.eq(s.anchored_capture('v([%d.]+)', 'Acme', far), nil)
end)

t.case('html_attribute handles quoting styles', function()
  t.eq(s.html_attribute('<meta name="generator" content="WP 5.8">',
    'content'), 'WP 5.8')
  t.eq(s.html_attribute("<meta CONTENT='x 1'>", 'content'), 'x 1')
  t.eq(s.html_attribute('<script src=a.js>', 'src'), 'a.js')
end)

t.case('unquoted attribute with slashes', function()
  t.eq(s.html_attribute('<script src=/js/a.js>', 'src'), '/js/a.js')
end)

t.case('response_subjects splits a response into channels', function()
  local subjects = s.response_subjects({
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
  t.eq(s.response_is_usable({ status = 200 }), true)
  t.eq(s.response_is_usable({ status = 302 }), true)
  t.eq(s.response_is_usable({ status = 404 }), false)
  t.eq(s.response_is_usable({}), false)
end)

t.case('match_subjects records versions and triggers probes', function()
  local scanner = t.load_scanner()
  scanner.registry.catalog_loaded = true
  scanner.registry.catalog = {
    fingerprints = s.validate_fingerprints({ rules = { nginx = rule } }),
    paths = { '/' },
    probes = s.validate_probes({ schema = 1, probes = { probe } })
  }
  local matches, triggered = new_matches(), {}
  scanner.match_subjects({
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
  scanner.registry.catalog_loaded = true
  scanner.registry.catalog = { fingerprints = {}, paths = {},
    probes = s.validate_probes({ schema = 1, probes = { many } }) }
  local matches = new_matches()
  scanner.run_targeted_probes({}, {}, matches,
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
  scanner.registry.catalog_loaded = true
  scanner.registry.catalog = { fingerprints = {}, paths = {},
    probes = s.validate_probes({ schema = 1, probes = { probe } }) }
  local matches = new_matches()
  for version in pairs(initial or {}) do
    matches.data.nmap[probe.alias] = matches.data.nmap[probe.alias] or {}
    matches.data.nmap[probe.alias][version] = true
    matches.size = matches.size + 1
  end
  scanner.run_targeted_probes({}, {}, matches,
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

t.case('legacy regex files extract versions from headers', function()
  local scanner = t.load_scanner()
  scanner.registry.regex = { header = { apache = {
    cpe = 'cpe:/a:apache:http_server', regex = 'Apache/([%d.]+)' } } }
  local matches = new_matches()
  scanner.regex_match('Server: Apache/2.2.8 (Ubuntu)', 'header', matches)
  t.truthy(matches.data.http['cpe:/a:apache:http_server']['2.2.8'])
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
    local matches = new_matches()
    matches.data.smb = {}
    scanner.add_nmap_matches({ ip = '10.0.0.1' }, samba_port, matches)
    t.truthy(matches.data.smb['cpe:/a:samba:samba']['3.0.20'])
    t.keys_eq(matches.data.nmap, {})
  end)
end)

t.case('smb get_os status false falls back to nmap cpe', function()
  with_smb(function() return false, 'error' end, function()
    local scanner = t.load_scanner()
    local matches = new_matches()
    matches.data.smb = {}
    scanner.add_nmap_matches({ ip = '10.0.0.6' }, samba_port, matches)
    t.keys_eq(matches.data.smb, {})
    t.truthy(matches.data.nmap['cpe:/a:samba:samba']['3.X - 4.X'])
  end)
end)

t.case('smb probe error falls back to nmap cpe', function()
  with_smb(function() error('timeout') end, function()
    local scanner = t.load_scanner()
    local matches = new_matches()
    matches.data.smb = {}
    scanner.add_nmap_matches({ ip = '10.0.0.2' }, samba_port, matches)
    t.keys_eq(matches.data.smb, {})
    t.truthy(matches.data.nmap['cpe:/a:samba:samba']['3.X - 4.X'])
  end)
end)

t.case('smb=0 never calls get_os', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    return true, { lanmanager = 'Samba 3.0.20' }
  end, function()
    local scanner = t.load_scanner({ args = { smb = '0' } })
    local matches = new_matches()
    matches.data.smb = {}
    scanner.add_nmap_matches({ ip = '10.0.0.3' }, samba_port, matches)
    t.eq(calls, 0)
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
    local matches = new_matches()
    matches.data.smb = {}
    scanner.add_nmap_matches({ ip = '10.0.0.4' }, http_port, matches)
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
    t.eq(scanner.smb_version(host, samba_port), '4.5.16')
    t.eq(scanner.smb_version(host, samba_port), '4.5.16')
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
    local matches = new_matches()
    matches.data.smb = {}
    scanner.add_nmap_matches({ ip = '10.0.1.1' }, samba_port, matches)
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
    local matches = new_matches()
    matches.data.smb = {}
    scanner.add_nmap_matches({ ip = '10.0.1.2' }, samba_port, matches)
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
    local matches = new_matches()
    matches.data.smb = {}
    scanner.add_nmap_matches({ ip = '10.0.1.3' }, samba_port, matches)
    t.eq(calls, 0)
    t.keys_eq(matches.data.smb, {})
  end)
end)

t.case('probes csv list enables each named probe', function()
  with_smb(function() return false, 'unused' end, function()
    local scanner = t.load_scanner({ args = { probes = 'smb,irc' } })
    t.eq(scanner.probe_enabled('smb'), true)
    t.eq(scanner.probe_enabled('irc'), true)
    t.eq(scanner.probe_enabled('http'), false)
  end)
end)

t.case('smb=0 disables the smb probe even with probes=all', function()
  with_smb(function() return true, {} end, function()
    local scanner = t.load_scanner({ args = { probes = 'all', smb = '0' } })
    t.eq(scanner.probe_enabled('smb'), false)
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
  t.eq(scanner.run_version_probe(host, port, fake), nil)
  t.eq(scanner.run_version_probe(host, port, fake), nil)
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
  local first = scanner.run_version_probe(host, { number = 8080 }, fake)
  t.eq(first.version, '1.0')
  scanner.run_version_probe(host, { number = 8080 }, fake)
  t.eq(calls, 1)
  scanner.run_version_probe(host, { number = 8081 }, fake)
  t.eq(calls, 2)
end)

-- Cursor over fixed rows, as returned by registry.conn:execute.
local function rows_cursor(rows)
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

t.case('analysis reports a non-nmap origin as its own source', function()
  local scanner = t.load_scanner()
  local affected = { { 'CVE-EXACT', '5.0', nil, '5.5', '*', 0, 0 } }
  scanner.registry.conn = { execute = function(_, sql)
    if sql:find('INNER JOIN affected', 1, true) then
      return rows_cursor(affected)
    end
    return rows_cursor({})
  end }
  scanner.registry.logger = { write = function() end }
  scanner.registry.cache = {}
  scanner.registry.json_out = { ['10.0.2.3'] = { ports = {} } }
  local matches = new_matches()
  matches.data.irc = {}
  matches.data.irc['cpe:/a:apache:tomcat:5.5'] = { ['5.5'] = true }
  matches.size = 1
  local host = { ip = '10.0.2.3' }
  local port = { number = 80, protocol = 'tcp', service = 'http' }
  scanner.analysis(host, port, matches, { os = {} })
  local service = scanner.registry.json_out[host.ip].ports['80/tcp']
    .services[1]
  t.eq(service.version_source, 'irc')
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
  local matches = new_matches()
  matches.data.irc = {}
  scanner.add_nmap_matches({ ip = '10.1.0.1' }, irc_port, matches)
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
  local matches = new_matches()
  matches.data.irc = {}
  scanner.add_nmap_matches({ ip = '10.1.0.2' }, port, matches)
  t.eq(log.created, 0)
  t.truthy(matches.data.nmap[irc_nmap]['3.2.8.1'])
end)

t.case('http service never runs the irc probe', function()
  local log, new_socket = irc_stub({ lines = { IRC_351 } })
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  local port = { number = 6667, service = 'http',
    version = { cpe = { irc_nmap }, version = '' } }
  local matches = new_matches()
  matches.data.irc = {}
  scanner.add_nmap_matches({ ip = '10.1.0.3' }, port, matches)
  t.eq(log.created, 0)
  t.truthy(matches.data.nmap[irc_nmap]['*'])
end)

t.case('other product on an irc service never runs the probe', function()
  local log, new_socket = irc_stub({ lines = { IRC_351 } })
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  local port = { number = 6667, service = 'irc',
    version = { cpe = { 'cpe:/a:ngircd:ngircd' }, version = '' } }
  local matches = new_matches()
  matches.data.irc = {}
  scanner.add_nmap_matches({ ip = '10.1.0.4' }, port, matches)
  t.eq(log.created, 0)
  t.truthy(matches.data.nmap['cpe:/a:ngircd:ngircd']['*'])
end)

t.case('probes=none and probes=smb skip the irc probe', function()
  for _, arg in ipairs({ 'none', 'smb' }) do
    local log, new_socket = irc_stub({ lines = { IRC_351 } })
    local scanner = t.load_scanner({ args = { probes = arg } })
    scanner.stubs.nmap.new_socket = new_socket
    local matches = new_matches()
    matches.data.irc = {}
    scanner.add_nmap_matches({ ip = '10.1.0.5' }, irc_port, matches)
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
    local matches = new_matches()
    matches.data.irc = {}
    scanner.add_nmap_matches({ ip = '10.1.0.6' }, irc_port, matches)
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
  local matches = new_matches()
  matches.data.irc = {}
  scanner.add_nmap_matches({ ip = '10.1.0.7' }, irc_port, matches)
  t.eq(log.sent[2], 'PONG LAG123\r\n')
  t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
end)

t.case('irc probe is cached per ip and port', function()
  local log, new_socket = irc_stub({ lines = { IRC_351 } })
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  local host = { ip = '10.1.0.8' }
  for _ = 1, 2 do
    local matches = new_matches()
    matches.data.irc = {}
    scanner.add_nmap_matches(host, irc_port, matches)
    t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
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

t.case('throttled irc probe retries once after 20 seconds', function()
  local log, new_socket = irc_sequence({
    { lines = { IRC_THROTTLED } },
    { lines = { IRC_351 } },
  })
  local sleeps, sleep = irc_sleeps()
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  scanner.stubs.stdnse.sleep = sleep
  local matches = new_matches()
  matches.data.irc = {}
  scanner.add_nmap_matches({ ip = '10.1.0.20' }, irc_port, matches)
  t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
  t.eq(log.created, 2)
  t.eq(sleeps, { 20 })
  for _, socket_log in ipairs(log.sockets) do
    t.eq(socket_log.closed, 1)
  end
end)

t.case('irc probe gives up after a second throttled reply', function()
  local log, new_socket = irc_sequence({
    { lines = { IRC_THROTTLED } },
    { lines = { IRC_THROTTLED } },
  })
  local sleeps, sleep = irc_sleeps()
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  scanner.stubs.stdnse.sleep = sleep
  local matches = new_matches()
  matches.data.irc = {}
  scanner.add_nmap_matches({ ip = '10.1.0.21' }, irc_port, matches)
  t.keys_eq(matches.data.irc, {})
  t.truthy(matches.data.nmap[irc_nmap]['*'])
  t.eq(log.created, 2)
  t.eq(sleeps, { 20 })
  for _, socket_log in ipairs(log.sockets) do
    t.eq(socket_log.closed, 1)
  end
end)

t.case('unthrottled irc probe never sleeps', function()
  local log, new_socket = irc_sequence({ { lines = { IRC_351 } } })
  local sleeps, sleep = irc_sleeps()
  local scanner = t.load_scanner()
  scanner.stubs.nmap.new_socket = new_socket
  scanner.stubs.stdnse.sleep = sleep
  local matches = new_matches()
  matches.data.irc = {}
  scanner.add_nmap_matches({ ip = '10.1.0.22' }, irc_port, matches)
  t.truthy(matches.data.irc[irc_nmap]['3.2.8.1'])
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
    local matches = new_matches()
    matches.data.smb = {}
    scanner.add_nmap_matches({ ip = '10.1.0.9' }, port, matches)
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
local OS_INFO = { ver = '5.5.3', vup = '*', from = nil, to = nil,
  empty = false, range = false }

--- Return a cursor over fixed rows (local copy for this suite).
local function os_rows(rows)
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

--- Scanner with one CVE for apache:tomcat 5.5.3 and the given platform rows.
-- Default platform rows make the CVE Linux-only.
local function os_scanner(args, platform)
  local sc = t.load_scanner({ args = args })
  sc.registry.platform_families = OS_FAMILIES
  sc.registry.logger = { write = function() end }
  sc.registry.json_out = { ['10.2.0.1'] = { ports = {} } }
  platform = platform or { { 'CVE-LIN', 0, 'o', 'linux', 'kernel' } }
  sc.registry.conn = { execute = function(_, sql)
    if sql:find('sqlite_master', 1, true) then
      return os_rows({ { 'conditions' } })
    elseif sql:find('FROM conditions', 1, true) then
      return os_rows(platform)
    elseif sql:find('SELECT DISTINCT vendor', 1, true) then
      return os_rows({ { 'apache' } })
    elseif sql:find('INNER JOIN affected', 1, true) then
      return os_rows({ { 'CVE-LIN', '5.0', nil, '5.5.3', '*', 0, 0 } })
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
local function os_scan(sc, ip, ctx)
  local host = { ip = ip }
  sc.registry.json_out[ip] = { ports = {} }
  return sc.vulnerabilities(host, HTTP_PORT, 'cpe:/a:apache:tomcat:5.5.3',
    'apache', 'tomcat', OS_INFO, ctx or { os = {}, backport = false })
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
    sc.smb_version({ ip = '10.2.0.2' }, SMB_PORT)
    local _, meta = os_scan(sc, '10.2.0.2')
    t.eq(meta.os_context.family, 'windows')
    t.eq(meta.os_context.source, 'probe:smb_os')
    local _, again = os_scan(sc, '10.2.0.2')
    t.eq(again.os_context.family, 'windows')
    t.eq(calls, 1)
  end)
end)

t.case('samba os string is not an os family', function()
  with_smb(function() return true, { os = SAMBA_OS } end, function()
    local sc = os_scanner()
    open_ports(sc, { SMB_PORT })
    local _, meta = os_scan(sc, '10.2.0.3')
    t.eq(meta.os_context.family, nil)
    t.eq(sc.registry.host_os_probe['10.2.0.3'], false)
  end)
end)

t.case('samba lanmanager on a windows-looking os is not windows', function()
  with_smb(function()
    return true, { os = 'Windows 6.1', lanmanager = 'Samba 4.3.11-Ubuntu' }
  end, function()
    local sc = os_scanner()
    open_ports(sc, { SMB_PORT })
    local _, meta = os_scan(sc, '10.2.0.6')
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
      local _, meta = os_scan(sc, ip)
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
    local _, meta = os_scan(sc, '10.2.0.4')
    t.eq(meta.os_context.family, nil)
    t.eq(calls, 0)
  end)
end)

t.case('probes=none, probes=smb and smb=0 skip the os probe', function()
  for _, args in ipairs({
    { probes = 'none' }, { probes = 'smb' }, { smb = '0' } }) do
    local calls = 0
    with_smb(function()
      calls = calls + 1
      return true, { os = WIN_OS }
    end, function()
      local sc = os_scanner(args)
      open_ports(sc, { SMB_PORT })
      local _, meta = os_scan(sc, '10.2.0.5')
      t.eq(meta.os_context.family, nil)
      t.eq(calls, 0)
    end)
  end
end)

t.case('os_context uses a cached probe before the cpe', function()
  local sc = t.load_scanner()
  sc.registry.platform_families = OS_FAMILIES
  sc.registry.host_os_probe['10.2.0.6'] = {
    family = 'windows', source = 'probe:smb_os' }
  local port = { number = 445, service = 'microsoft-ds',
    version = { cpe = { 'cpe:/o:linux:linux_kernel' } } }
  local ctx = sc.os_context({ ip = '10.2.0.6' }, port)
  t.eq(ctx.family, 'windows')
  t.eq(ctx.source, 'probe:smb_os')
  local plain = sc.os_context({ ip = '10.2.0.7' }, port)
  t.eq(plain.family, 'linux')
  t.eq(plain.source, 'cpe')
  t.eq(sc.registry.host_os_probe['10.2.0.7'], nil)
end)

t.case('get_os error is cached as a negative result', function()
  local calls = 0
  with_smb(function()
    calls = calls + 1
    error('timeout')
  end, function()
    local sc = os_scanner()
    open_ports(sc, { SMB_PORT })
    local _, first = os_scan(sc, '10.2.0.8')
    local _, second = os_scan(sc, '10.2.0.8')
    t.eq(first.os_context.family, nil)
    t.eq(second.os_context.family, nil)
    t.eq(calls, 1)
    t.eq(sc.registry.host_os_probe['10.2.0.8'], false)
  end)
end)

t.case('probe turns requires_platform into platform_mismatch', function()
  with_smb(function() return true, { os = WIN_OS } end, function()
    local sc = os_scanner()
    open_ports(sc, { SMB_PORT })
    local _, meta = os_scan(sc, '10.2.0.9')
    t.eq(meta.summary.low, 1)
    t.eq(meta.summary.medium, 0)
    t.eq(meta.os_context.source, 'probe:smb_os')
  end)
end)

t.case('without a probe the Linux-only CVE stays requires_platform', function()
  local sc = os_scanner()
  open_ports(sc, { HTTP_PORT })
  local _, meta = os_scan(sc, '10.2.0.10')
  t.eq(meta.summary.medium, 1)
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
    local _, meta = os_scan(known, '10.2.0.11',
      { os = { family = 'linux', source = 'cpe' }, backport = false })
    t.eq(meta.os_context.family, 'linux')
    t.eq(calls, 0)
    local plain = os_scanner(nil, {})
    local ports_calls = 0
    plain.stubs.nmap.get_ports = function()
      ports_calls = ports_calls + 1
      return function() return nil end
    end
    local _, plain_meta = os_scan(plain, '10.2.0.12')
    t.eq(plain_meta.summary.high, 1)
    t.eq(ports_calls, 0)
    t.eq(calls, 0)
  end)
end)

--- Run analysis for one tomcat 5.5.3 service on ip and port.
local function os_analysis(sc, ip, port, ctx)
  sc.registry.cache = sc.registry.cache or {}
  sc.registry.json_out[ip] = { ports = {} }
  local matches = { data = { nmap = {
    ['cpe:/a:apache:tomcat:5.5.3'] = { ['5.5.3'] = true } } }, size = 1 }
  sc.analysis({ ip = ip }, port, matches, ctx)
  local services = sc.registry.json_out[ip].ports[
    port.number .. '/tcp'].services
  return services[#services]
end

--- Count CVE queries issued through registry.conn from now on.
local function count_cve_queries(sc)
  local n = 0
  local real = sc.registry.conn.execute
  sc.registry.conn.execute = function(conn, sql)
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
    t.eq(first.os_context.family, 'windows')
    local second = os_analysis(sc, '10.2.0.14', HTTP_PORT, { os = {},
      backport = false })
    t.eq(calls, 2)
    t.eq(second.vulnerabilities.info, 'scan')
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
  t.eq(second.vulnerabilities.info, 'cache')
end)

t.case('known os cache is shared across hosts', function()
  local sc = os_scanner()
  open_ports(sc, { HTTP_PORT })
  local ctx = { os = { family = 'linux', source = 'cpe' }, backport = false }
  local queries = count_cve_queries(sc)
  os_analysis(sc, '10.2.0.16', HTTP_PORT, ctx)
  local after_first = queries()
  local second = os_analysis(sc, '10.2.0.17', HTTP_PORT, ctx)
  t.eq(queries(), after_first)
  t.eq(second.vulnerabilities.info, 'cache')
end)

t.suite('http engine gating')

--- Scanner whose http stub records calls; the legacy path makes one GET.
local function gated_scanner(opts)
  local calls = {}
  local function record(name)
    return function()
      table.insert(calls, name)
      return {}
    end
  end
  local scanner = t.load_scanner({ http = {
    get = record('get'),
    pipeline_add = record('pipeline_add'),
    pipeline_go = record('pipeline_go'),
  } })
  scanner.registry.json_out = {}
  scanner.registry.legacy_catalog = true
  scanner.registry.path = { path = { 'probe' }, extension = { '' } }
  scanner.stubs.shortport.http = function() return opts.http end
  scanner.stubs.shortport.ssl = function() return opts.ssl end
  return scanner, calls
end

--- Run portaction on one port and return the recorded http calls.
local function gate_calls(opts, number, service)
  local scanner, calls = gated_scanner(opts)
  local port = { number = number, protocol = 'tcp', service = service }
  scanner.portaction({ ip = '10.0.3.1' }, port)
  return calls
end

t.case('ms-wbt-server with tls skips the http engine', function()
  local calls = gate_calls({ ssl = true, http = false }, 3389,
    'ms-wbt-server')
  t.eq(#calls, 0)
end)

t.case('https with tls enters the http engine', function()
  local calls = gate_calls({ ssl = true, http = false }, 443, 'https')
  t.truthy(#calls > 0, 'expected the http stub to be called')
end)

t.case('plain http enters the http engine', function()
  local calls = gate_calls({ ssl = false, http = true }, 8080, 'http')
  t.truthy(#calls > 0, 'expected the http stub to be called')
end)

t.case('upnp enters the http engine', function()
  local calls = gate_calls({ ssl = false, http = false }, 1900, 'upnp')
  t.truthy(#calls > 0, 'expected the http stub to be called')
end)

t.case('ssh with tls skips the http engine', function()
  local calls = gate_calls({ ssl = true, http = false }, 22, 'ssh')
  t.eq(#calls, 0)
end)

t.suite('http engine abort')

--- Scanner whose legacy http.get replies with the given sequence.
-- seq(n) returns the reply for the n-th GET; nil means no status.
local function abort_legacy(seq, paths)
  local calls = 0
  local scanner = t.load_scanner({ http = {
    get = function()
      calls = calls + 1
      return seq(calls)
    end,
  } })
  scanner.registry.json_out = {}
  scanner.registry.legacy_catalog = true
  scanner.registry.path = { path = paths, extension = { '' } }
  scanner.stubs.shortport.http = function() return true end
  return scanner, function() return calls end
end

local function ten_paths()
  local paths = {}
  for i = 1, 10 do paths[i] = 'p' .. i end
  return paths
end

local ABORT_PORT = { number = 8080, protocol = 'tcp', service = 'http' }

t.case('legacy stops after five consecutive failures', function()
  local scanner, calls = abort_legacy(function() return {} end,
    ten_paths())
  scanner.portaction({ ip = '10.4.0.1' }, ABORT_PORT)
  t.eq(calls(), 5)
end)

t.case('legacy stops after failures that follow successes', function()
  local scanner, calls = abort_legacy(function(n)
    if n <= 3 then return { status = 200, rawheader = {}, rawbody = '' } end
    return {}
  end, ten_paths())
  scanner.portaction({ ip = '10.4.0.2' }, ABORT_PORT)
  t.eq(calls(), 8)
end)

t.case('legacy keeps going with intermittent failures', function()
  local scanner, calls = abort_legacy(function(n)
    if n % 2 == 1 then return {} end
    return { status = 200, rawheader = {}, rawbody = '' }
  end, ten_paths())
  scanner.portaction({ ip = '10.4.0.3' }, ABORT_PORT)
  t.eq(calls(), 10)
end)

--- Scanner whose catalogue sweep records pipeline_go calls.
-- batches(n) returns the reply table for the n-th pipeline_go call.
local function abort_catalog(batches)
  local calls = 0
  local scanner = t.load_scanner({ http = {
    pipeline_add = function(_, _, requests)
      return requests or {}
    end,
    pipeline_go = function()
      calls = calls + 1
      return batches(calls)
    end,
  } })
  local paths = {}
  for i = 1, 300 do paths[i] = '/r' .. i end
  scanner.registry.json_out = {}
  scanner.registry.catalog_loaded = true
  scanner.registry.catalog = { fingerprints = {}, paths = paths,
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
  end)
  scanner.portaction({ ip = '10.4.0.5' }, ABORT_PORT)
  t.eq(calls(), 2)
end)
