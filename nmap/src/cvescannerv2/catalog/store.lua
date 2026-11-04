-- SPDX-License-Identifier: GPL-3.0-or-later
-- Upstream and local catalogue loading with the on-disk cache.

-- Fetches the Vulners catalogue over HTTP or reads the cached copy, validates
-- it and stores the result in the shared state. Local overlays are merged
-- into the loaded catalogue. Only this module reads and writes the catalogue
-- files.

local http = require 'http'
local json = require 'json'
local lfs = require 'lfs'
local stdnse = require 'stdnse'

local config = require 'cvescannerv2.config'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'
local validate = require 'cvescannerv2.catalog.validate'

local M = {}

local fmt = util.fmt
local MAX_CATALOG_BYTES = validate.MAX_CATALOG_BYTES
local build_catalog = validate.build_catalog
local validate_fingerprints = validate.validate_fingerprints
local validate_paths = validate.validate_paths
local validate_probes = validate.validate_probes

local CATALOG_BASE =
'https://raw.githubusercontent.com/vulnersCom/nmap-vulners/catalog/'
local CATALOG_CACHE_DIR = 'data'
local CATALOG_SOURCE_FILE = '.vulners-catalog-source'
M.CATALOG_BASE = CATALOG_BASE
M.CATALOG_CACHE_DIR = CATALOG_CACHE_DIR
M.CATALOG_SOURCE_FILE = CATALOG_SOURCE_FILE

local function catalog_file_path(filename)
  return CATALOG_CACHE_DIR .. '/' .. filename
end
M.catalog_file_path = catalog_file_path

local function read_catalog_json(filename)
  local path = catalog_file_path(filename)
  local file = io.open(path, 'rb')
  if not file then return nil end
  -- NSE's lfs module has no attributes(). Bound reads directly instead.
  local body = file:read(MAX_CATALOG_BYTES + 1)
  file:close()
  if type(body) ~= 'string' or #body > MAX_CATALOG_BYTES then
    return nil
  end
  local parsed, data = json.parse(body)
  if not parsed or type(data) ~= 'table' then return nil end
  return data
end
M.read_catalog_json = read_catalog_json

local function fetch_catalog_json(base, filename)
  local ok, response = pcall(http.get_url, base .. filename, {
    timeout = 10000,
    max_body_size = MAX_CATALOG_BYTES,
    any_af = true,
    header = { Accept = 'application/json' }
  })
  if not ok or type(response) ~= 'table'
      or tonumber(response.status) ~= 200 then
    return nil
  end
  local body = response.body or response.rawbody
  if type(body) ~= 'string' or #body > MAX_CATALOG_BYTES then
    return nil
  end
  local parsed, data = json.parse(body)
  if not parsed or type(data) ~= 'table' then return nil end
  return data, body
end
M.fetch_catalog_json = fetch_catalog_json

local function read_catalog_source()
  local file = io.open(catalog_file_path(CATALOG_SOURCE_FILE), 'r')
  if not file then return nil end
  local source = file:read('*all')
  file:close()
  return source
end
M.read_catalog_source = read_catalog_source

local function load_catalog_cache(base)
  if read_catalog_source() ~= base then return false end
  local index = read_catalog_json('index.json')
  local loaded = build_catalog(index, read_catalog_json)
  if not loaded then return false end
  state.catalog = loaded
  state.catalog_loaded = true
  stdnse.verbose(1, fmt('Using cached Vulners catalogue from %s.',
    CATALOG_CACHE_DIR))
  return true
end
M.load_catalog_cache = load_catalog_cache

local function ensure_catalog_cache_dir()
  local created = lfs.mkdir(CATALOG_CACHE_DIR)
  if created then return true end
  -- mkdir also fails when the directory already exists. dir() distinguishes
  -- that case from a file or an inaccessible path using NSE's supported API.
  local readable, iterator = pcall(lfs.dir, CATALOG_CACHE_DIR)
  return readable and type(iterator) == 'function'
end
M.ensure_catalog_cache_dir = ensure_catalog_cache_dir

local function write_catalog_file(filename, body)
  local file = io.open(catalog_file_path(filename), 'wb')
  if not file then return false end
  local written = file:write(body)
  local closed = file:close()
  return written ~= nil and closed ~= nil
end
M.write_catalog_file = write_catalog_file

local function save_catalog_cache(base, files)
  if not ensure_catalog_cache_dir() then return false end
  os.remove(catalog_file_path(CATALOG_SOURCE_FILE))
  for filename, body in pairs(files) do
    if not write_catalog_file(filename, body) then return false end
  end
  return write_catalog_file(CATALOG_SOURCE_FILE, base)
end
M.save_catalog_cache = save_catalog_cache

function M.load_catalog()
  if config.catalog == 'none' then return false end
  local base = config.catalog_url or CATALOG_BASE
  if base:match('^https?://[^/%s]+') == nil then
    stdnse.verbose(1, 'Invalid catalogue URL; using local legacy data.')
    return false
  end
  if base:sub(-1) ~= '/' then base = base .. '/' end

  if load_catalog_cache(base) then return true end

  local index, index_body = fetch_catalog_json(base, 'index.json')
  if not index or not index_body then return false end
  local cache_files = { ['index.json'] = index_body }
  local loaded = build_catalog(index, function(filename)
    local data, body = fetch_catalog_json(base, filename)
    if data and body then cache_files[filename] = body end
    return data
  end)
  if not loaded then return false end

  state.catalog = loaded
  state.catalog_loaded = true
  if save_catalog_cache(base, cache_files) then
    stdnse.verbose(1, fmt('Cached Vulners catalogue in %s.',
      CATALOG_CACHE_DIR))
  else
    stdnse.verbose(1, fmt('Could not cache Vulners catalogue in %s.',
      CATALOG_CACHE_DIR))
  end
  return true
end


function M.load_platform_families()
  local families = read_catalog_json('platform-families.json')
  if families == nil then
    stdnse.verbose(1, 'Platform families unavailable; OS context disabled.')
    return {}
  end
  return families
end


-- Local catalogue overlay. Its sections are validated with the upstream
-- validators and appended to the loaded upstream catalogue, so local entries
-- never replace upstream ones. The overlay is never written to the cache.
--- Merge the local catalogue overlay into the upstream catalogue.
-- Return true when the overlay was merged. Nothing is merged when the path
-- is 'none', the file is absent or unreadable, or no upstream catalogue was
-- loaded.
function M.load_local_catalog(path)
  if path == 'none' then return false end
  if not state.catalog_loaded then
    stdnse.verbose(1, 'Local catalogue ignored: no upstream catalogue.')
    return false
  end
  local file = io.open(path, 'rb')
  if not file then return false end
  -- Bound reads as read_catalog_json does.
  local body = file:read(MAX_CATALOG_BYTES + 1)
  file:close()
  local parsed, data = false, nil
  if type(body) == 'string' and #body <= MAX_CATALOG_BYTES then
    parsed, data = json.parse(body)
  end
  if not parsed or type(data) ~= 'table' then
    stdnse.verbose(1, fmt('Local catalogue %s is invalid; ignored.', path))
    return false
  end

  --- Return the validated section 'key' of the overlay, or nil.
  -- An absent section is skipped silently. An invalid one is logged.
  local function section(key, validate)
    if data[key] == nil then return nil end
    local valid = type(data[key]) == 'table' and validate(data[key])
    if not valid then
      stdnse.verbose(1, fmt('Invalid local catalogue section %s; skipped.',
        key))
    end
    return valid or nil
  end

  local loaded = state.catalog
  -- Fingerprints are grouped by channel: append each rule to its list.
  local by_channel = section('fingerprints', validate_fingerprints)
  for channel, rules in pairs(by_channel or {}) do
    loaded.fingerprints[channel] = loaded.fingerprints[channel] or {}
    for _, rule in ipairs(rules) do
      table.insert(loaded.fingerprints[channel], rule)
    end
  end
  -- Paths are a flat list: append the ones not already known.
  local known = {}
  for _, item in ipairs(loaded.paths) do known[item] = true end
  for _, item in ipairs(section('paths', validate_paths) or {}) do
    if not known[item] then
      known[item] = true
      table.insert(loaded.paths, item)
    end
  end
  -- Probes are a flat list: append them.
  for _, probe in ipairs(section('probes', validate_probes) or {}) do
    table.insert(loaded.probes, probe)
  end
  stdnse.verbose(1, fmt('Local catalogue %s merged.', path))
  return true
end

return M
