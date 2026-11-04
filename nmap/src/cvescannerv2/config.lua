-- SPDX-License-Identifier: GPL-3.0-or-later
-- Reads and normalizes every script argument of the cvescannerv2 NSE script.

local stdnse = require 'stdnse'

local M = {}


local MINCONF_LEVELS = { low = true, medium = true, high = true }


-- Read all script arguments once and store the normalized values in M.
function M.load()
  M.db = stdnse.get_script_args('db') or 'data/cve.db'
  M.maxcve = tonumber(stdnse.get_script_args('maxcve')) or 10
  M.http = stdnse.get_script_args('http') or '1'
  M.maxredirect = math.max(
    0, tonumber(stdnse.get_script_args('maxredirect')) or 1)
  M.log = stdnse.get_script_args('log') or 'cvescannerv2.log'
  M.json = stdnse.get_script_args('json') or 'cvescannerv2.json'
  M.path = stdnse.get_script_args('path')
      or 'data/http-paths-vulnerscom.json'
  M.regex = stdnse.get_script_args('regex')
      or 'data/http-regex-vulnerscom.json'
  M.aliases = stdnse.get_script_args('aliases')
      or 'data/product-aliases.json'
  M.vendor_aliases = stdnse.get_script_args('vendor_aliases')
      or 'data/vendor-aliases.json'
  M.catalog = (stdnse.get_script_args('catalog') or 'auto'):lower()
  M.catalog_url = stdnse.get_script_args('catalog_url')
  M.service = stdnse.get_script_args('service') or 'all'
  M.version = stdnse.get_script_args('version') or 'all'
  M.smb = stdnse.get_script_args('smb') or '1'
  M.sweep = stdnse.get_script_args('sweep') or '0'
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


-- Build the HTTP options shared by every request to a target.
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
