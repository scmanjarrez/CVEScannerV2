-- SPDX-License-Identifier: GPL-3.0-or-later
-- Script lifecycle of the cvescannerv2 NSE script.  (Layer L9)
--
-- Decides whether the script runs (prerule, hostrule, portrule, postrule)
-- and runs the pre, host, port and post actions. Opens and closes the
-- database and the log, writes the log header and footer and the JSON
-- report, and loads catalogue data from data files (store.load_catalog,
-- aliases, CPE overrides, local catalogue). Reads config; writes status,
-- time, cache, totals, json_out and the alias and CPE tables in state.

local datetime = require 'datetime'
local stdnse = require 'stdnse'
local analysis = require 'cvescannerv2.port_analysis'
local collect = require 'cvescannerv2.port_matches'
local config = require 'cvescannerv2.config'
local db = require 'cvescannerv2.db'
local log = require 'cvescannerv2.log'
local oscontext = require 'cvescannerv2.os_context'
local refdata = require 'cvescannerv2.reference_files'
local render = require 'cvescannerv2.text_output'
local report = require 'cvescannerv2.json_report'
local state = require 'cvescannerv2.state'
local store = require 'cvescannerv2.catalog.store'
local util = require 'cvescannerv2.util'

local M = {}


-- Check the database and the data files. Return an error message or ''.
local function required_files()
  local ret = ""
  if not util.is_readable_file(config.db) then
    ret = util.fmt("Database %s could not be read. " ..
      "Run uv run --project db-manager db-manager " ..
      "before running nmap script.",
      config.db)
  else
    state.product_aliases = {}
    if util.is_readable_file(config.aliases)
        and not refdata.load_reference_file(config.aliases, 'aliases') then
      stdnse.verbose(1, util.fmt(
        'Invalid aliases file %s; skipping aliases.', config.aliases))
    end
    state.vendor_aliases = {}
    if util.is_readable_file(config.vendor_aliases)
        and not refdata.load_reference_file(config.vendor_aliases,
          'vendor_aliases') then
      stdnse.verbose(1, util.fmt(
        'Invalid vendor aliases file %s; skipping vendor aliases.',
        config.vendor_aliases))
    end
    local product_cpe_arg = config.product_cpe
    state.product_cpe = {}
    if product_cpe_arg ~= 'none' and util.is_readable_file(product_cpe_arg)
        and not refdata.load_reference_file(product_cpe_arg,
          'product_cpe') then
      stdnse.verbose(1, util.fmt(
        'Invalid product CPE file %s; skipping CPE overrides.',
        product_cpe_arg))
    end
    state.platform_families = store.load_platform_families()
    if not store.load_catalog() then
      stdnse.verbose(1,
        'Vulners catalogue unavailable; continuing with Nmap CPEs.')
    end
    store.load_local_catalog(config.local_catalog)
  end
  return ret
end


--- Load the data files and return whether the script runs.
function M.prerule()
  local req = required_files()
  if req ~= "" then
    stdnse.verbose(1, req)
    state.enabled = false
  end
  return state.enabled
end

--- Return whether the script runs against a host.
function M.hostrule(_)
  return state.enabled
end

--- Return whether the script runs against a port.
function M.portrule(_, port)
  return state.enabled and
      port.service ~= 'tcpwrapped' and
      port.service ~= 'unknown'
end

--- Return whether the script runs its post actions.
function M.postrule()
  return state.enabled
end

--- Open the database and the log, and reset the per-run state.
function M.preaction(script_version)
  db.open(config.db)
  log.open(config.log)
  state.run_timestamp = datetime.format_timestamp(os.time(), 0)
  state.script_version = script_version
  state.service_cache = {}
  state.totals = { hosts = 0, services = 0, cves = 0 }
  state.json_report = {}
  state.json_hosts = {}
  log.write_lines(render.log_header(script_version, state.run_timestamp, {
    minconf = config.minconf,
    maxcve = config.maxcve,
    db = config.db,
  }))
  log.log_run_header(script_version)
  if not config.minconf_valid then
    log.write("warning: minconf '%s' is invalid, using low",
      config.minconf_raw)
  end
end

--- Create the report entry for one host and count it.
function M.hostaction(host)
  report.ensure_host(host.ip)
  if state.totals then
    state.totals.hosts = state.totals.hosts + 1
  end
end

--- Collect and analyse the matches of one port. Return the structured rows
-- and, when there is output, the Nmap text: a string that starts with a
-- newline so that it opens on its own line under the script name.
function M.portaction(host, port)
  report.ensure_host(host.ip)
  local matches = collect.collect_port_matches(host, port)
  local structured, lines
  if matches['size'] ~= 0 then
    local scan_ctx = {
      os = oscontext.os_context(host, port),
      backport = oscontext.distro_backport(port),
    }
    structured, lines = analysis.analyze_port(host, port, matches, scan_ctx)
  end
  while lines and #lines > 0 and lines[#lines] == '' do
    lines[#lines] = nil
  end
  if lines and #lines > 0 then
    return structured, '\n' .. table.concat(lines, '\n')
  end
end

--- Write the log footer, close the database and the log, and write the
-- JSON report.
function M.postaction()
  local closed, close_err = db.close()
  if not closed then
    log.write("warning: could not close database connection: %s", close_err)
  end
  log.write_lines(render.log_footer(state.totals))
  log.close()
  report.write(config.json, {
    version = state.script_version,
    minconf = config.minconf,
    maxcve = config.maxcve,
  })
end

return M
