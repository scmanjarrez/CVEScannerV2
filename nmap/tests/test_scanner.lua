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
  local scanner = assert(load(source .. [[
    return { sweep = sweep_catalog, registry = registry }
  ]]))()
  local registry = scanner.registry
  local alias = 'cpe:/a:example:widget'
  registry.catalog_loaded = true
  registry.catalog = {
    -- The redirect is in the second batch to check response/path indexing.
    paths = {'/1', '/2', '/3', '/4', '/5', '/redirect', '/plain'},
    probes = {},
    fingerprints = {
      body = {{alias = alias, regex = 'Widget ([%d%.]+)', anchor = 'Widget'}}
    }
  }
  local gets = {}
  http.pipeline_add = function(path, options, requests)
    requests = requests or {}
    table.insert(requests, {path = path, options = options})
    return requests
  end
  http.pipeline_go = function(_, _, requests)
    local responses = {}
    for _, request in ipairs(requests) do
      local redirected = request.path == '/redirect'
      table.insert(responses, {
        status = redirected and redirect_status or 200,
        header = redirected and {location = '/login'} or {},
        body = request.path == '/plain' and 'Widget 2.0' or ''
      })
    end
    return responses
  end
  http.get = function(_, _, path, options)
    table.insert(gets, path)
    assert(options.redirect_ok == limit, 'Redirect limit must be preserved')
    if fail_redirect then return nil end
    return {status = 200, header = {}, body = 'Widget 1.2.3'}
  end
  local matches = {data = {http = {}, nmap = {}}, size = 0}
  scanner.sweep({ip = '127.0.0.1'}, {number = 80}, matches, {})
  assert(matches.data.http[alias]['2.0'], 'Normal responses must still match')
  if limit > 0 and redirect_status ~= 200 then
    assert(#gets == 1 and gets[1] == '/redirect', 'Reissue the correct path')
    assert((matches.data.http[alias]['1.2.3'] == true) == not fail_redirect,
      'Fingerprint the destination only when following succeeds')
  else
    assert(#gets == 0, 'Do not reissue normal responses or disabled redirects')
  end
end

for _, status in ipairs({301, 302, 303, 307, 308}) do
  run_case(2, status, false)
end
run_case(0, 302, false)
run_case(2, 200, false)
run_case(2, 302, true)
print('HTTP redirects: 8 cases passed')

-- NSE's lfs has mkdir/dir but no attributes method. Verify both cache paths
-- without replacing it with the incompatible desktop LuaFileSystem API.
fresh_modules()
assert(load(source .. [[
  return {}
]]))()
local store = require 'cvescannerv2.catalog.store'
local cache = {
  read = store.read_catalog_json,
  ensure_dir = store.ensure_catalog_cache_dir
}
modules.lfs.mkdir = function() return true end
assert(cache.ensure_dir(), 'Create the cache directory when missing')
modules.lfs.mkdir = function() return false end
modules.lfs.dir = function() return function() return nil end end
assert(cache.ensure_dir(), 'Accept an existing cache directory')
modules.lfs.dir = function() error('Not a directory') end
assert(not cache.ensure_dir(), 'Reject a regular file at the cache path')

local original_open = io.open
local closed = false
local body = '{}'
io.open = function()
  return {
    read = function(_, size)
      assert(size == 8 * 1024 * 1024 + 1, 'Bound cache reads')
      return body
    end,
    close = function() closed = true end
  }
end
modules.json.parse = function() return true, {} end
assert(type(cache.read('index.json')) == 'table', 'Read a cached catalogue')
assert(closed, 'Close the cache file')
body = string.rep('x', 8 * 1024 * 1024 + 1)
assert(cache.read('index.json') == nil, 'Reject an oversized catalogue')
io.open = original_open
print('Catalogue cache: 5 cases passed')

fresh_modules()
local scanner = assert(load(source .. [[
  return { port = portaction, registry = registry }
]]))()
modules.shortport.http = function() return false end
modules.shortport.ssl = function() return false end
scanner.registry.catalog_loaded = false
scanner.registry.json_out = {}
scanner.registry.cache = {}
scanner.registry.logger = {write = no_op}
scanner.registry.conn = {
  execute = function()
    return {fetch = function() return nil end, close = no_op}
  end
}
assert(scanner.port({ip = '127.0.0.1'}, {
  number = 22,
  protocol = 'tcp',
  service = 'ssh',
  version = {cpe = {'cpe:/a:example:widget:1.2.3'}, version = '1.2.3'}
}) == nil, 'Return no NSE output when a detected product has no matching CVEs')
print('Empty vulnerability result: passed')
