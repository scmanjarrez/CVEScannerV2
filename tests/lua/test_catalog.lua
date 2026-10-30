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
