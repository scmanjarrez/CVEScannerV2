-- SPDX-License-Identifier: GPL-3.0-or-later
-- Reads and normalizes the cvescannerv2 script arguments.  (Layer L0)
--
-- Only this module calls stdnse.get_script_args. It keeps the normalized
-- values in its own table and does no file, network or state I/O.

local stdnse = require 'stdnse'

local M = {}


local MINCONF_LEVELS = { low = true, medium = true, high = true }
local SWEEP_LEVELS = { ['1'] = 1, ['2'] = 2 }
local DEFAULT_SWEEP_BUDGET = 50


--- Read all script arguments once and store the normalized values in M.
function M.load()
  M.db = stdnse.get_script_args('db') or 'data/cve.db'
  M.maxcve = tonumber(stdnse.get_script_args('maxcve')) or 10
  M.maxredirect = math.max(
    0, tonumber(stdnse.get_script_args('maxredirect')) or 1)
  M.log = stdnse.get_script_args('log') or 'cvescannerv2.log'
  M.json = stdnse.get_script_args('json') or 'cvescannerv2.json'
  M.aliases = stdnse.get_script_args('aliases')
      or 'data/product-aliases.json'
  M.vendor_aliases = stdnse.get_script_args('vendor_aliases')
      or 'data/vendor-aliases.json'
  M.catalog = (stdnse.get_script_args('catalog') or 'auto'):lower()
  M.service = stdnse.get_script_args('service') or 'all'
  M.version = stdnse.get_script_args('version') or 'all'
  M.sweep_level = SWEEP_LEVELS[stdnse.get_script_args('sweep')] or 0
  local budget_raw = stdnse.get_script_args('sweep_budget')
  local budget = tonumber(budget_raw)
  M.sweep_budget_set = budget ~= nil and budget >= 0
      and budget == math.floor(budget)
  M.sweep_budget = M.sweep_budget_set and math.tointeger(budget)
      or DEFAULT_SWEEP_BUDGET
  M.probes = (stdnse.get_script_args('probes') or 'all'):lower()
  M.probes_set = {}
  for name in M.probes:gmatch('[^,%s]+') do M.probes_set[name] = true end
  M.minconf_raw = (stdnse.get_script_args('minconf') or 'low'):lower()
  M.minconf_valid = MINCONF_LEVELS[M.minconf_raw] == true
  M.minconf = M.minconf_valid and M.minconf_raw or 'low'
  M.product_cpe = stdnse.get_script_args('product_cpe')
      or 'data/product-cpe.json'
  M.local_catalog = stdnse.get_script_args('local_catalog')
      or 'data/local-catalog.json'
  return M
end

--- Build the HTTP options shared by every request to a target.
function M.options_for_target()
  return {
    redirect_ok = M.maxredirect,
    timeout = 10000,
    max_body_size = 131072,
    truncated_ok = true,
    bypass_cache = true,
    no_cache = true,
    no_cache_body = true
  }
end

return M
