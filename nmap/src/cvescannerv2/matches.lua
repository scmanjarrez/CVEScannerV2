-- SPDX-License-Identifier: GPL-3.0-or-later
-- Match recording and series pruning for detected CPE versions. (Layer L2)
--
-- Stores detected versions in the shared matches table and removes
-- series entries once a precise version is known for the same CPE.
-- No network or file I/O. Reads state.aliases; does not touch config.

local stdnse = require 'stdnse'
local state = require 'cvescannerv2.state'
local cpe_lib = require 'cvescannerv2.cpe'
local ver_mod = require 'cvescannerv2.version'

local M = {}

local split_cpe = cpe_lib.split_cpe
local is_precise_version = ver_mod.is_precise_version
local is_series_version = ver_mod.is_series_version


local function add_cpe_version(cpe, version, matches, location)
  if version:sub(-1) == '.' then -- strip dot at the end of version
    version = version:sub(1, -2)
  end
  if matches['data'][location][cpe] == nil then
    matches['data'][location][cpe] = {}
  end
  if matches['data'][location][cpe][version] == nil then
    stdnse.verbose(2, location .. " cpe: " .. cpe .. " | version: " .. version)
    matches['data'][location][cpe][version] = true
    matches['size'] = matches['size'] + 1
    return true
  end
end


local function add_cpe_aliases(cpe, version, matches, location)
  local parts, offset, _, _, product = split_cpe(cpe)
  if not parts then return end
  local product_index = offset + 2
  -- Product aliases
  if state.aliases[product] then
    for _, alias in pairs(state.aliases[product]) do
      parts[product_index] = alias
      add_cpe_version(table.concat(parts, ":"), version, matches, location)
    end
  end
end


local function cpe_has_precise_version(matches, cpe)
  for _, source in pairs(matches.data) do
    for version in pairs(source[cpe] or {}) do
      if is_precise_version(version) then return true end
    end
  end
  return false
end

local function prune_series_versions(matches, cpe, version)
  for _, source in pairs(matches.data) do
    local versions = source[cpe]
    if versions then
      for series in pairs(versions) do
        if is_series_version(series)
            and version:sub(1, #series + 1) == series .. '.' then
          versions[series] = nil
          matches.size = matches.size - 1
        end
      end
    end
  end
end


--- Records a version for a CPE; returns true if it was new.
M.add_cpe_version = add_cpe_version
--- Records the version under every alias of the CPE product.
M.add_cpe_aliases = add_cpe_aliases
--- Returns true if the CPE has at least one precise version recorded.
M.cpe_has_precise_version = cpe_has_precise_version
--- Removes series versions of the CPE superseded by the given version.
M.prune_series_versions = prune_series_versions

return M
