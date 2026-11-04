-- SPDX-License-Identifier: GPL-3.0-or-later
-- Upstream and local catalogue loading from the data/ dir.  (Layer L3)
--
-- Reads the Vulners catalogue files that scripts/download-catalog.sh stores
-- in data/, validates them and stores the result in the shared state. Local
-- overlays are merged into the loaded catalogue. Only this module reads the
-- catalogue files. I/O: read-only access to files under data/ and to the
-- local overlay file. Reads config.catalog; writes state.catalog and
-- state.catalog_loaded.

local json = require 'json'
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

local CATALOG_CACHE_DIR = 'data'

local function catalog_file_path(filename)
  return CATALOG_CACHE_DIR .. '/' .. filename
end

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
--- Return the parsed JSON of a cache file, or nil.
M.read_catalog_json = read_catalog_json

-- Load index.json and its catalogue files from data/ into the state.
local function load_catalog_files()
  local index = read_catalog_json('index.json')
  local loaded = build_catalog(index, read_catalog_json)
  if not loaded then return false end
  state.catalog = loaded
  state.catalog_loaded = true
  stdnse.verbose(1, fmt('Using Vulners catalogue from %s.',
    CATALOG_CACHE_DIR))
  return true
end

--- Return true when the local catalogue is loaded into state.
function M.load_catalog()
  if config.catalog == 'none' then return false end
  if load_catalog_files() then return true end
  stdnse.verbose(1,
    'Vulners catalogue not found in data/; run scripts/download-catalog.sh.')
  return false
end


--- Return the platform families table, or an empty table.
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
