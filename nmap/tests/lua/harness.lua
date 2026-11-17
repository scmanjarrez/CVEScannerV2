-- SPDX-License-Identifier: GPL-3.0-or-later
-- Minimal test framework and NSE loader that needs no Nmap installation.
--
-- load_scanner() loads cvescannerv2.nse with load() and returns its entry
-- points (portaction, preaction, postaction, portrule). The NSE libraries
-- are replaced with stubs, exposed as scanner.stubs.
--
-- The modules under nmap/src/cvescannerv2/ are loaded with require() and
-- are reached as scanner.modules.<name>, where <name> is the last component
-- of the module name (for example scanner.modules.service_cves; probes.init
-- is modules.probes). Nothing is copied onto the scanner table, so tests call
-- the same functions Nmap calls.

local M = {}

-- Copy of the stock searchers, taken before any scanner module is loaded.
-- load_scanner() restores them on every call so that each fresh scanner
-- resolves its modules from disk again.
local ORIGINAL_SEARCHERS = table.move(package.searchers, 1,
  #package.searchers, 1, {})

local strict = os.getenv('CVESCANNER_STRICT') == '1'
local filter = os.getenv('CVESCANNER_FILTER')
local nse_path = os.getenv('CVESCANNER_NSE') or 'nmap/src/cvescannerv2.nse'

M.results = {
  passed = 0,
  failed = 0,
  xfail = 0,
  xpass = 0,
  skipped = 0,
  failures = {},
  xfailures = {},
  xpasses = {}
}

local function read_source()
  local file = assert(io.open(nse_path, 'r'),
    'Run the tests from the repository root or set CVESCANNER_NSE')
  local source = file:read('*all')
  file:close()
  local parts = {}
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

  -- Reset the module loader so every call starts from the same state.
  local searchers = package.searchers
  for i = #searchers, 1, -1 do searchers[i] = nil end
  table.move(ORIGINAL_SEARCHERS, 1, #ORIGINAL_SEARCHERS, 1, searchers)
  for name in pairs(package.loaded) do
    if type(name) == 'string' and name:find('^cvescannerv2%.') then
      package.loaded[name] = nil
    end
  end
  SCRIPT_PATH = nse_path

  local chunk = assert(load(SOURCE, '=nmap/src/cvescannerv2.nse'))
  local scanner = chunk()

  -- Snapshot taken now, so this scanner keeps its own modules even when a
  -- later load_scanner() resets package.loaded.
  local by_short_name = {}
  for name, value in pairs(package.loaded) do
    if type(name) == 'string' and type(value) == 'table'
        and name:find('^cvescannerv2%.') then
      local short = name:match('([^.]+)$')
      if short == 'init' then short = name:match('([^.]+)%.init$') end
      by_short_name[short] = value
    end
  end
  scanner.modules = setmetatable(by_short_name, {
    __index = function(_, key)
      error('unknown module ' .. tostring(key), 2)
    end
  })
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
