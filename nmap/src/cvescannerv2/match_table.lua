-- SPDX-License-Identifier: GPL-3.0-or-later
-- Match recording and series pruning for detected CPE versions. (Layer L2)
--
-- Stores detected versions in the shared matches table and removes
-- series entries once a precise version is known for the same CPE.
-- No network or file I/O. Reads state.product_aliases; does not touch config.

local stdnse = require 'stdnse'
local state = require 'cvescannerv2.state'
local cpe = require 'cvescannerv2.cpe'
local version = require 'cvescannerv2.version'

local M = {}

local split_cpe = cpe.split_cpe
local is_precise_version = version.is_precise_version
local is_series_version = version.is_series_version


local function add_cpe_version(cpe_str, ver, matches, location)
  if ver:sub(-1) == '.' then -- strip dot at the end of version
    ver = ver:sub(1, -2)
  end
  if matches['data'][location][cpe_str] == nil then
    matches['data'][location][cpe_str] = {}
  end
  if matches['data'][location][cpe_str][ver] == nil then
    stdnse.verbose(2, location .. " cpe: " .. cpe_str .. " | version: " .. ver)
    matches['data'][location][cpe_str][ver] = true
    matches['size'] = matches['size'] + 1
    return true
  end
end


local function add_cpe_aliases(cpe_str, ver, matches, location)
  local parts, offset, _, _, product = split_cpe(cpe_str)
  if not parts then return end
  local product_index = offset + 2
  -- Product aliases
  if state.product_aliases[product] then
    for _, alias in pairs(state.product_aliases[product]) do
      parts[product_index] = alias
      add_cpe_version(table.concat(parts, ":"), ver, matches, location)
    end
  end
end


local function cpe_has_precise_version(matches, cpe_str)
  for _, source in pairs(matches.data) do
    for ver in pairs(source[cpe_str] or {}) do
      if is_precise_version(ver) then return true end
    end
  end
  return false
end

local function prune_series_versions(matches, cpe_str, ver)
  for _, source in pairs(matches.data) do
    local versions = source[cpe_str]
    if versions then
      for series in pairs(versions) do
        if is_series_version(series)
            and ver:sub(1, #series + 1) == series .. '.' then
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
