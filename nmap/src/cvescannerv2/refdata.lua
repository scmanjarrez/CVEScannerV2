-- SPDX-License-Identifier: GPL-3.0-or-later
-- Loads and validates the reference data files of cvescannerv2.  (Layer L2)
--
-- Each loader decodes one JSON file, checks its shape and stores the result
-- in the shared state. File reads only (io.open); no network, SQL or config
-- access. Writes state.aliases, state.vendor_aliases and state.product_cpe.

local json = require 'json'

local state = require 'cvescannerv2.state'

local M = {}


-- Decode the JSON file at arg and store it in the state for ftype.
local function valid_json(arg, ftype)
  local f = io.open(arg, 'r')
  if not f then return false end
  local content = f:read('*all')
  f:close()
  local status, data = json.parse(content)
  if not status or type(data) ~= 'table' then return false end
  if ftype == 'aliases' then
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
--- Load the JSON file arg into the state; return false if it is invalid.
M.valid_json = valid_json


return M
