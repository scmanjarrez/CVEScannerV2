-- SPDX-License-Identifier: GPL-3.0-or-later
-- Loads and validates the reference data files of the cvescannerv2 NSE script.

-- Each loader decodes one JSON file, checks its shape and stores the result
-- in the shared state. Legacy catalogue files are checked here as well.

local json = require 'json'

local config = require 'cvescannerv2.config'
local state = require 'cvescannerv2.state'
local util = require 'cvescannerv2.util'

local M = {}

local exists = util.exists


-- Decode the JSON file at arg and store it in the state for ftype.
local function valid_json(arg, ftype)
  local f = io.open(arg, 'r')
  if not f then return false end
  local content = f:read('*all')
  f:close()
  local status, data = json.parse(content)
  if not status or type(data) ~= 'table' then return false end
  if ftype == 'path' then
    if type(data.path) ~= 'table' or type(data.extension) ~= 'table' then
      return false
    end
    state.path = data
  elseif ftype == 'regex' then
    if type(data.header) ~= 'table'
        or type(data.body) ~= 'table'
        or type(data.external) ~= 'table' then
      return false
    end
    state.regex = data
  elseif ftype == 'aliases' then
    state.aliases = data
  elseif ftype == 'vendor_aliases' then
    state.vendor_aliases = data
  elseif ftype == 'product_cpe' then
    for product, cpe in pairs(data) do
      if type(product) ~= 'string' or type(cpe) ~= 'string'
          or cpe:match('^cpe:/a:[^:]+:[^:]+$') == nil then
        return false
      end
    end
    state.product_cpe = data
  end
  return true
end
M.valid_json = valid_json


-- Mark the legacy catalogue as loaded when both its files are valid.
local function load_legacy_catalog()
  if not exists(config.path) or not exists(config.regex) then return false end
  if not valid_json(config.path, 'path')
      or not valid_json(config.regex, 'regex') then
    return false
  end
  state.legacy_catalog = true
  return true
end
M.load_legacy_catalog = load_legacy_catalog


return M
