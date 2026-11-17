-- SPDX-License-Identifier: GPL-3.0-or-later
-- Run from the repository root: lua5.4 nmap/tests/test_scanner.lua
-- Test the scanner with deterministic HTTP responses and no network access.

local http = {}
local nmap = { timing_level = function() return 0 end }
local redirect_limit = '2'
local no_op = function() end
local modules = {
  http = http,
  nmap = nmap,
  json = {},
  datetime = {},
  lfs = {},
  shortport = {},
  ['luasql.sqlite3'] = {},
  stdnse = {
    get_script_args = function(name)
      if name == 'maxredirect' then return redirect_limit end
      if name == 'sweep' then return '2' end
      return nil
    end,
    verbose = no_op,
    sleep = no_op
  }
}
for name, module in pairs(modules) do
  package.loaded[name] = module
end
SCRIPT_NAME = 'cvescannerv2-test'
local ORIGINAL_SEARCHERS = {}
for i, searcher in ipairs(package.searchers) do
  ORIGINAL_SEARCHERS[i] = searcher
end

local file = assert(io.open('nmap/src/cvescannerv2.nse', 'r'))
local source = file:read('*all')
file:close()

local function fresh_modules()
  SCRIPT_PATH = 'nmap/src/cvescannerv2.nse'
  for name in pairs(package.loaded) do
    if name:match('^cvescannerv2%.') then package.loaded[name] = nil end
  end
  for i = #package.searchers, 1, -1 do
    package.searchers[i] = nil
  end
  for i, searcher in ipairs(ORIGINAL_SEARCHERS) do
    package.searchers[i] = searcher
  end
end

local function run_case(limit, redirect_status, fail_redirect)
  redirect_limit = tostring(limit)
  nmap.registry = {}
  fresh_modules()
  assert(load(source))()
  local http_fingerprint = require 'cvescannerv2.http_fingerprint'
  local registry = require 'cvescannerv2.state'
  local alias = 'cpe:/a:example:widget'
  registry.catalog_loaded = true
  registry.catalog = {
    -- The redirect is in the second batch to check response/path indexing.
    paths = { '/1', '/2', '/3', '/4', '/5', '/redirect', '/plain' },
    probes = {},
    fingerprints = {
      body = { { alias = alias, regex = 'Widget ([%d%.]+)', anchor = 'Widget' } }
    }
  }
  local gets = {}
  http.pipeline_add = function(path, options, requests)
    requests = requests or {}
    table.insert(requests, { path = path, options = options })
    return requests
  end
  http.pipeline_go = function(_, _, requests)
    local responses = {}
    for _, request in ipairs(requests) do
      local redirected = request.path == '/redirect'
      table.insert(responses, {
        status = redirected and redirect_status or 200,
        header = redirected and { location = '/login' } or {},
        body = request.path == '/plain' and 'Widget 2.0' or ''
      })
    end
    return responses
  end
  http.get = function(_, _, path, options)
    table.insert(gets, path)
    assert(options.redirect_ok == limit, 'Redirect limit must be preserved')
    if fail_redirect then return nil end
    return { status = 200, header = {}, body = 'Widget 1.2.3' }
  end
  local matches = { data = { http = {}, nmap = {} }, size = 0 }
  http_fingerprint.sweep_catalog({ ip = '127.0.0.1' }, { number = 80 }, matches, {})
  assert(matches.data.http[alias]['2.0'], 'Normal responses must still match')
  if limit > 0 and redirect_status ~= 200 then
    assert(#gets == 1 and gets[1] == '/redirect', 'Reissue the correct path')
    assert((matches.data.http[alias]['1.2.3'] == true) == not fail_redirect,
      'Fingerprint the destination only when following succeeds')
  else
    assert(#gets == 0, 'Do not reissue normal responses or disabled redirects')
  end
end

for _, status in ipairs({ 301, 302, 303, 307, 308 }) do
  run_case(2, status, false)
end
run_case(0, 302, false)
run_case(2, 200, false)
run_case(2, 302, true)
print('HTTP redirects: 8 cases passed')

-- The store reads data/ only. io.open is stubbed so the real data/ directory
-- is never touched and nothing is written.
fresh_modules()
assert(load(source .. [[
  return {}
]]))()
local store = require 'cvescannerv2.catalog.store'
local state = require 'cvescannerv2.state'
local MAX_BYTES = 8 * 1024 * 1024
local original_open = io.open
local original_parse = modules.json.parse
local files = {}
local parsed = {}
local opened = {}
local closed = false
-- Deliberate mock: io.open is replaced on purpose to isolate the cache read.
---@diagnostic disable-next-line: duplicate-set-field
io.open = function(path, mode)
  table.insert(opened, { path = path, mode = mode })
  local body = files[path]
  if body == nil then return nil end
  return {
    read = function(_, size)
      assert(size == MAX_BYTES + 1, 'Bound cache reads')
      return body
    end,
    close = function() closed = true end
  }
end
modules.json.parse = function(body)
  if parsed[body] == nil then return false end
  return true, parsed[body]
end

files['data/vulnerscom-index.json'] = '{}'
parsed['{}'] = {}
assert(type(store.read_catalog_json('vulnerscom-index.json')) == 'table',
  'Read a cached catalogue')
assert(closed, 'Close the cache file')
files['data/vulnerscom-index.json'] = string.rep('x', MAX_BYTES + 1)
assert(store.read_catalog_json('vulnerscom-index.json') == nil,
  'Reject an oversized catalogue')
files['data/bad.json'] = 'not json'
assert(store.read_catalog_json('bad.json') == nil,
  'Reject invalid JSON')
assert(store.read_catalog_json('missing.json') == nil,
  'Return nil for a missing catalogue')
print('Catalogue cache: 4 cases passed')

-- Case 3: an empty data/ loads nothing and creates nothing.
files = {}
opened = {}
modules.lfs.mkdir = function() error('Do not create directories') end
assert(store.load_catalog() == false, 'Report no catalogue in empty data/')
assert(state.catalog_loaded == false, 'Keep the catalogue unloaded')
for _, call in ipairs(opened) do
  assert(call.mode == 'rb', 'Open catalogue files read-only')
end

-- Case 4: the four minimal valid files load into the state.
local index_body = 'index'
local rules_body = 'fingerprints'
local paths_body = 'paths'
local probes_body = 'probes'
parsed[index_body] = {
  schema = 1,
  catalogs = {
    fingerprints = { file = 'fingerprints.json' },
    paths = { file = 'paths.json' },
    probes = { file = 'probes.json' }
  }
}
parsed[rules_body] = {
  rules = {
    widget = {
      alias = 'cpe:/a:example:widget',
      channel = 'body',
      regex = 'Widget ([%d%.]+)',
      anchor = 'Widget'
    }
  }
}
parsed[paths_body] = { paths = { '/' } }
parsed[probes_body] = { schema = 1, probes = {} }
files = {
  ['data/vulnerscom-index.json'] = index_body,
  ['data/vulnerscom-fingerprints.json'] = rules_body,
  ['data/vulnerscom-paths.json'] = paths_body,
  ['data/vulnerscom-probes.json'] = probes_body
}
closed = false
assert(store.load_catalog() == true, 'Load the minimal catalogue')
assert(state.catalog_loaded == true, 'Mark the catalogue as loaded')

io.open = original_open
modules.json.parse = original_parse or function() return true, {} end

fresh_modules()
local port = assert(load(source .. [[
  return portaction
]]))()
state = require 'cvescannerv2.state'
modules.shortport.http = function() return false end
modules.shortport.ssl = function() return false end
state.catalog_loaded = false
state.json_report = {}
state.service_cache = {}
state.log_file = { write = no_op }
state.db_conn = {
  execute = function()
    return { fetch = function() return nil end, close = no_op }
  end
}
assert(port({ ip = '127.0.0.1' }, {
  number = 22,
  protocol = 'tcp',
  service = 'ssh',
  version = { cpe = { 'cpe:/a:example:widget:1.2.3' }, version = '1.2.3' }
}) == nil, 'Return no NSE output when a detected product has no matching CVEs')
print('Empty vulnerability result: passed')
