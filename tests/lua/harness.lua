-- SPDX-License-Identifier: GPL-3.0-or-later
-- Minimal test framework and NSE loader that needs no Nmap installation.
--
-- The scanner keeps its helpers as chunk locals. load_scanner() appends a
-- return statement to the script source, so the helpers are exported from
-- the same chunk without modifying cvescannerv2.nse.

local M = {}

local strict = os.getenv('CVESCANNER_STRICT') == '1'
local filter = os.getenv('CVESCANNER_FILTER')
local nse_path = os.getenv('CVESCANNER_NSE') or 'cvescannerv2.nse'

M.results = {
  passed = 0, failed = 0, xfail = 0, xpass = 0, skipped = 0,
  failures = {}, xfailures = {}, xpasses = {}
}

-- Names exported from the NSE chunk. Missing names resolve to nil, so this
-- list does not break when a helper is renamed or removed.
local EXPORTS = {
  'empty', 'fmtn', 'correct_version', 'valid_json', 'capture_count',
  'valid_pattern', 'valid_alias', 'valid_channel', 'valid_path',
  'validate_fingerprints', 'validate_paths', 'validate_probes',
  'build_catalog', 'add_cpe_version', 'split_cpe', 'add_cpe_aliases',
  'find_version', 'regex_match', 'add_subject', 'html_attribute',
  'response_subjects', 'response_is_usable', 'safe_version',
  'pattern_match', 'anchor_matches', 'anchored_capture',
  'match_fingerprint_rule', 'pattern_found', 'probe_detects',
  'match_subjects', 'match_banner', 'cpe_has_version', 'probe_version',
  'run_targeted_probes', 'sweep_catalog', 'version_parser', 'cpe_parser',
  'query', 'cvss_comparator', 'compare_version', 'default_version',
  'scoped_multi_versions', 'scoped_versions', 'vulnerabilities',
  'series_prefix', 'series_has_children', 'merge_series',
  'analysis', 'registry', 'smb_version', 'add_nmap_matches',
  'os_context', 'distro_backport', 'evaluate_platform',
  'add_platform_reasons', 'confidence_of', 'SERVICE_PROBES',
  'run_version_probe', 'probe_enabled'
}

local function read_source()
  local file = assert(io.open(nse_path, 'r'),
    'Run the tests from the repository root or set CVESCANNER_NSE')
  local source = file:read('*all')
  file:close()
  local parts = {}
  for _, name in ipairs(EXPORTS) do
    table.insert(parts, name .. ' = ' .. name)
  end
  table.insert(parts, 'portaction = portaction')
  table.insert(parts, 'preaction = preaction')
  table.insert(parts, 'postaction = postaction')
  table.insert(parts, 'portrule = portrule')
  return source .. '\nreturn { ' .. table.concat(parts, ', ') .. ' }\n'
end

local SOURCE = read_source()

--- Load a fresh copy of the scanner with stubbed Nmap libraries.
-- opts.args: script arguments returned by stdnse.get_script_args.
-- opts.http: table used as the 'http' library.
-- opts.sql: real luasql.sqlite3 module (integration tests only).
function M.load_scanner(opts)
  opts = opts or {}
  local args = opts.args or {}
  local stubs = {
    http = opts.http or {},
    nmap = { registry = {}, timing_level = function() return 4 end },
    json = opts.json or {
      parse = function() return false end,
      generate = function() return '{}' end
    },
    datetime = { format_timestamp = function() return 'T' end },
    lfs = {
      mkdir = function() return true end,
      dir = function() return function() return nil end end
    },
    shortport = {
      http = function() return false end,
      ssl = function() return false end
    },
    stdnse = {
      get_script_args = function(name) return args[name] end,
      verbose = function() end,
      sleep = function() end
    },
    comm = opts.comm or {},
    ['luasql.sqlite3'] = opts.sql or {}
  }
  for name, module in pairs(stubs) do
    package.loaded[name] = module
  end
  SCRIPT_NAME = 'cvescannerv2'
  local chunk = assert(load(SOURCE, '=cvescannerv2.nse'))
  local scanner = chunk()
  scanner.stubs = stubs
  return scanner
end

local function serialize(value, seen)
  seen = seen or {}
  if type(value) == 'string' then return string.format('%q', value) end
  if type(value) ~= 'table' then return tostring(value) end
  if seen[value] then return '<cycle>' end
  seen[value] = true
  local keys = {}
  for key in pairs(value) do table.insert(keys, key) end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  local parts = {}
  for _, key in ipairs(keys) do
    table.insert(parts, '[' .. serialize(key, seen) .. ']='
      .. serialize(value[key], seen))
  end
  return '{' .. table.concat(parts, ', ') .. '}'
end
M.serialize = serialize

local function deep_equal(a, b)
  if type(a) ~= type(b) then return false end
  if type(a) ~= 'table' then return a == b end
  for key, value in pairs(a) do
    if not deep_equal(value, b[key]) then return false end
  end
  for key in pairs(b) do
    if a[key] == nil then return false end
  end
  return true
end

function M.eq(actual, expected, message)
  if not deep_equal(actual, expected) then
    error(string.format('%s\n      expected: %s\n      actual:   %s',
      message or 'values differ', serialize(expected), serialize(actual)), 2)
  end
end

function M.truthy(value, message)
  if not value then error(message or 'expected a truthy value', 2) end
end

--- Compare the keys of a table with an expected list of names.
function M.keys_eq(actual, expected, message)
  local got = {}
  for key in pairs(actual or {}) do table.insert(got, key) end
  table.sort(got)
  local want = { table.unpack(expected) }
  table.sort(want)
  if not deep_equal(got, want) then
    error(string.format('%s\n      expected: %s\n      actual:   %s',
      message or 'key sets differ', serialize(want), serialize(got)), 2)
  end
end

local function selected(name)
  return filter == nil or name:find(filter, 1, true) ~= nil
end

local function run(fn)
  return xpcall(fn, function(err) return tostring(err) end)
end

function M.suite(name)
  M.current_suite = name
  print('\n== ' .. name)
end

local function full_name(name)
  return (M.current_suite or '?') .. ' :: ' .. name
end

--- Register a test that must pass.
function M.case(name, fn)
  if not selected(full_name(name)) then return end
  local ok, err = run(fn)
  if ok then
    M.results.passed = M.results.passed + 1
    print('  PASS  ' .. name)
  else
    M.results.failed = M.results.failed + 1
    table.insert(M.results.failures, full_name(name) .. '\n      ' .. err)
    print('  FAIL  ' .. name .. '\n      ' .. err)
  end
end

--- Register a test that documents a known defect.
-- The body asserts the desired behaviour. While the defect exists the test
-- fails and is reported as XFAIL. Once fixed it reports XPASS: move it to
-- M.case. With CVESCANNER_STRICT=1 both outcomes fail the run.
function M.known_bug(name, issue, fn)
  if not selected(full_name(name)) then return end
  local ok, err = run(fn)
  if ok then
    M.results.xpass = M.results.xpass + 1
    table.insert(M.results.xpasses, full_name(name))
    print('  XPASS ' .. name .. '  [' .. issue .. '] (fixed? move to case)')
  else
    M.results.xfail = M.results.xfail + 1
    table.insert(M.results.xfailures, full_name(name) .. ' [' .. issue .. ']')
    print('  XFAIL ' .. name .. '  [' .. issue .. ']\n      '
      .. (err:gsub('\n%s*', ' | ')))
  end
end

function M.skip(name, reason)
  if not selected(full_name(name)) then return end
  M.results.skipped = M.results.skipped + 1
  print('  SKIP  ' .. name .. ' (' .. reason .. ')')
end

function M.summary()
  local r = M.results
  print(string.format(
    '\n%d passed, %d failed, %d known bugs (xfail), %d xpass, %d skipped',
    r.passed, r.failed, r.xfail, r.xpass, r.skipped))
  if #r.failures > 0 then
    print('\nFailures:')
    for _, failure in ipairs(r.failures) do print('  - ' .. failure) end
  end
  if #r.xfailures > 0 then
    print('\nKnown bugs still present:')
    for _, item in ipairs(r.xfailures) do print('  - ' .. item) end
  end
  if #r.xpasses > 0 then
    print('\nKnown bugs that now pass (promote them to regular cases):')
    for _, item in ipairs(r.xpasses) do print('  - ' .. item) end
  end
  if r.failed > 0 then return false end
  if strict and (r.xfail > 0 or r.xpass > 0) then return false end
  return true
end

return M
