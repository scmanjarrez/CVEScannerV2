-- SPDX-License-Identifier: GPL-3.0-or-later
-- Script lifecycle of the cvescannerv2 NSE script: the rules that decide
-- whether it runs and the actions Nmap calls before, per host, per port and
-- after the scan.

local datetime = require 'datetime'
local stdnse = require 'stdnse'
local analysis = require 'cvescannerv2.analysis'
local collect = require 'cvescannerv2.collect'
local config = require 'cvescannerv2.config'
local db = require 'cvescannerv2.db'
local log = require 'cvescannerv2.log'
local oscontext = require 'cvescannerv2.oscontext'
local refdata = require 'cvescannerv2.refdata'
local report = require 'cvescannerv2.report'
local state = require 'cvescannerv2.state'
local store = require 'cvescannerv2.catalog.store'
local util = require 'cvescannerv2.util'

local M = {}


-- Check the database and the data files. Return an error message or ''.
local function required_files()
  local ret = ""
  if not util.exists(config.db) then
    ret = util.fmt("Database %s could not be read. " ..
      "Run uv run --project db-manager db-manager " ..
      "before running nmap script.",
      config.db)
  else
    state.aliases = {}
    if util.exists(config.aliases)
        and not refdata.valid_json(config.aliases, 'aliases') then
      stdnse.verbose(1, util.fmt(
        'Invalid aliases file %s; skipping aliases.', config.aliases))
    end
    state.vendor_aliases = {}
    if util.exists(config.vendor_aliases)
        and not refdata.valid_json(config.vendor_aliases, 'vendor_aliases') then
      stdnse.verbose(1, util.fmt(
        'Invalid vendor aliases file %s; skipping vendor aliases.',
        config.vendor_aliases))
    end
    local product_cpe_arg = config.product_cpe
    state.product_cpe = {}
    if product_cpe_arg ~= 'none' and util.exists(product_cpe_arg)
        and not refdata.valid_json(product_cpe_arg, 'product_cpe') then
      stdnse.verbose(1, util.fmt(
        'Invalid product CPE file %s; skipping CPE overrides.',
        product_cpe_arg))
    end
    state.platform_families = store.load_platform_families()
    if config.http == '1' and config.catalog ~= 'none' then
      if not store.load_catalog() and not refdata.load_legacy_catalog() then
        stdnse.verbose(1,
          'HTTP catalogue unavailable; continuing with Nmap CPEs.')
      end
    end
    store.load_local_catalog(config.local_catalog)
  end
  return ret
end


function M.prerule()
  local req = required_files()
  if req ~= "" then
    stdnse.verbose(1, req)
    state.status = false
  end
  return state.status
end


function M.hostrule(_)
  return state.status
end


function M.portrule(_, port)
  return state.status and
      port.service ~= 'tcpwrapped' and
      port.service ~= 'unknown'
end


function M.postrule()
  return state.status
end


-- Open the database and the log, and reset the per-run state.
function M.preaction(script_version)
  db.open(config.db)
  log.open(config.log)
  state.time = datetime.format_timestamp(os.time(), 0)
  state.cache = {}
  state.json_out = {}
  log.timestamp(script_version)
  if not config.minconf_valid then
    log.log("[!] minconf '%s' is invalid, using low", config.minconf_raw)
  end
end


function M.hostaction(host)
  report.ensure_host(host.ip)
end


-- Collect and analyse the matches of one port; return the vulnerabilities.
function M.portaction(host, port)
  report.ensure_host(host.ip)
  local matches = collect.port(host, port)
  local vulns
  if matches['size'] ~= 0 then
    local ctx = {
      os = oscontext.os_context(host, port),
      backport = oscontext.distro_backport(port),
    }
    vulns = analysis.analysis(host, port, matches, ctx)
  end
  if vulns and #vulns > 0 then return vulns end
end


-- Close the database and the log, and write the JSON report.
function M.postaction()
  local closed, close_err = db.close()
  if not closed then
    log.log("[!] could not close database connection: %s", close_err)
  end
  log.close()
  report.write(config.json)
end


return M
