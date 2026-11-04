-- SPDX-License-Identifier: GPL-3.0-or-later

-- cvescannerv2 - NSE script.

-- Copyright (C) 2021-2023 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
-- Universidad Carlos III de Madrid (UC3M).

-- Copyright (C) 2026 Sergio Chica Manjarrez @ csic.es.
-- Consejo Superior de Investigaciones Científicas (CSIC).

-- This file is part of CVEScannerV2.

-- CVEScannerV2 is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- CVEScannerV2 is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

description = [[
Search for probable vulnerabilities based on services discovered in open ports.
CVEs information gathered from nvd.nist.gov.
]]
--- Prerequisite: data/cve.db. Generate it with db-manager or obtain it from
-- https://github.com/scmanjarrez/CVEScannerV2DB
--
--- Run: Execute CVEscannerV2
-- @usage nmap -sV --script cvescannerv2 <target-ip>
-- @usage nmap -sV --script cvescannerv2 --script-args log=logfile.log,json=logfile.json <target-ip>
--
-- @output
-- PORT      STATE SERVICE       VERSION
-- 3306/tcp  open  mysql         MySQL 5.5.55
-- | cvescannerv2:
-- |   source: nvd.nist.gov
-- |   product: mysql
-- |   version: 5.5.55
-- |   vupdate: *
-- |   cves: 5
-- |       CVE ID           CVSSv2   CVSSv3   ExploitDB   Metasploit
-- |       CVE-2021-3278    7.5      9.8      Yes         No
-- |       CVE-2014-3631    7.2      -        Yes         Yes
-- |       CVE-2019-13401   6.8      8.8      No          No
-- |       CVE-2019-13402   6.5      8.8      No          No
-- |_      CVE-2016-3976    5.0      7.5      Yes         Yes
--
--- Optional arguments
-- db: Modify the database file location. Default: data/cve.db
-- maxcve: Limit the number of CVEs printed on screen. Default: 10
-- http: Modify HTTP analysis behaviour. Default: 1 (enabled). Possible values: 0, 1
-- maxredirect: Limit the number of redirections. Default: 1
-- sweep: Enable the catalogue path sweep over HTTP ports (slow, asks every
-- catalogue path). Default: 0 (disabled). Possible values: 0, 1.
-- Transitional: it will be removed.
-- log: Modify the output .log file location. Default: cvescannerv2.log
-- json: Modify the output .json file location. Default: cvescannerv2.json
-- catalog: Use upstream fingerprints. Default: auto. Set to none to disable
-- HTTP fingerprinting.
-- catalog_url: Override the base URL for the upstream catalogue.
-- local_catalog: Local catalogue merged on top of the upstream one.
-- Default: data/local-catalog.json. Set to none to disable.
-- path: Legacy paths file. Default:
-- data/http-paths-vulnerscom.json
-- regex: Legacy regex file. Default:
-- data/http-regex-vulnerscom.json
-- aliases: Product aliases file. Default:
-- data/product-aliases.json
-- vendor_aliases: Vendor aliases file. Default:
-- data/vendor-aliases.json
-- product_cpe: Product to CPE overrides for Nmap products, replacing the
-- CPE that Nmap reports. Default: data/product-cpe.json. Set to none to
-- disable.
-- service: Modify the search scope to specific service. Default: all
-- version: Modify the search scope to specific version. Default: all
-- smb: Probe SMB (ports 139/445) for the exact Samba version. Default: 1.
-- Possible values: 0, 1
-- probes: Service version probes to run: all, none or a comma-separated
-- list of probe names (e.g. smb, irc). Default: all. The irc probe reads
-- the exact UnrealIRCd version with a read-only IRC VERSION request.
-- minconf: Minimum confidence of the CVEs shown in the table and the log:
-- low, medium or high. Default: low. Invalid values use low. The JSON
-- report always keeps every CVE.
---

categories = { "safe" }
-- Orden por runlevel: estos scripts fijan la versión en port.version, así
-- que corren antes. Sin -sV no tienen efecto.
dependencies = {
  "weblogic-t3-info", "oracle-tns-version", "docker-version",
  "jdwp-version", "vmware-version", "db2-das-info", "ike-version",
  "mqtt-subscribe", "amqp-info", "xmpp-info",
}
author = "Sergio Chica"
version = "4.0"

local http = require 'http'
http.USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0'
local nmap = require 'nmap'
local datetime = require 'datetime'
local shortport = require 'shortport'

-- Nmap only looks for modules in nselib/ under its data directories. Resolve
-- 'cvescannerv2.*' next to this script instead; position 2 puts it before
-- Nmap's own file searcher, so the copy next to the script wins.
do
  local script_dir = SCRIPT_PATH:match('^(.*)[/\\][^/\\]*$') or '.'
  if not package.loaded['cvescannerv2.searcher'] then
    package.loaded['cvescannerv2.searcher'] = true
    table.insert(package.searchers, 2, function(name)
      local rel = name:match('^cvescannerv2%.(.+)$')
      if not rel then return nil end
      local path = script_dir .. '/cvescannerv2/'
          .. (rel:gsub('%.', '/')) .. '.lua'
      local file = io.open(path, 'r')
      if not file then return "\n\tno file '" .. path .. "'" end
      file:close()
      return assert(loadfile(path)), path
    end)
  end
end

local stdnse = require 'stdnse'

local db_arg, maxcve_arg, http_arg, maxredirect_arg, log_arg, json_arg
local aliases_arg, vendor_aliases_arg, catalog_arg
local minconf_arg, options_for_target
-- Script arguments are read once by the config module.
do
  local config = require 'cvescannerv2.config'
  config.load()
  db_arg = config.db
  maxcve_arg = config.maxcve
  http_arg = config.http
  maxredirect_arg = config.maxredirect
  log_arg = config.log
  json_arg = config.json
  aliases_arg = config.aliases
  vendor_aliases_arg = config.vendor_aliases
  catalog_arg = config.catalog
  minconf_arg = config.minconf
  options_for_target = config.options_for_target
end


-- shared state; module singleton replaces nmap.registry
local registry = require 'cvescannerv2.state'


local exists, fmt, sql_escape, fmtn
do
  local util = require 'cvescannerv2.util'
  exists, fmt = util.exists, util.fmt
  sql_escape, fmtn = util.sql_escape, util.fmtn
end


-- Version helpers moved to the version module, used by this script.
local is_series_version, is_precise_version
local compare_version, default_version, series_prefix
local spans_series
do
  local ver_mod = require 'cvescannerv2.version'
  is_series_version = ver_mod.is_series_version
  is_precise_version = ver_mod.is_precise_version
  compare_version = ver_mod.compare_version
  default_version = ver_mod.default_version
  series_prefix = ver_mod.series_prefix
  spans_series = ver_mod.spans_series
end


-- Logging helpers moved to the log module, used by this script.
local timestamp, log
do
  local log_mod = require 'cvescannerv2.log'
  timestamp = log_mod.timestamp
  log = log_mod.log
end


-- Reference data loaders moved to the refdata module, used by this script.
local valid_json, load_legacy_catalog
do
  local refdata = require 'cvescannerv2.refdata'
  valid_json = refdata.valid_json
  load_legacy_catalog = refdata.load_legacy_catalog
end


-- Catalogue loaders moved to the store module, used by this script.
-- The local catalogue overlay is also exposed on the registry for tests.
local load_catalog, load_platform_families
do
  local store = require 'cvescannerv2.catalog.store'
  load_catalog = store.load_catalog
  load_platform_families = store.load_platform_families
  registry.load_local_catalog = store.load_local_catalog
end


-- SQLite helpers moved to the db module, used by this script.
local db, vendor_scope, series_has_children, has_conditions
do
  db = require 'cvescannerv2.db'
  vendor_scope = db.vendor_scope
  series_has_children = db.series_has_children
  has_conditions = db.has_conditions
end


-- OS context helpers moved to the oscontext module, used by this script.
local os_context, distro_backport
do
  local oscontext = require 'cvescannerv2.oscontext'
  os_context = oscontext.os_context
  distro_backport = oscontext.distro_backport
end

local function required_files()
  local ret = ""
  local config = require 'cvescannerv2.config'
  if not exists(db_arg) then
    ret = fmt("Database %s could not be read. " ..
      "Run uv run --project db-manager db-manager " ..
      "before running nmap script.",
      db_arg)
  else
    registry.aliases = {}
    if exists(aliases_arg) and not valid_json(aliases_arg, 'aliases') then
      stdnse.verbose(1, fmt('Invalid aliases file %s; skipping aliases.',
        aliases_arg))
    end
    registry.vendor_aliases = {}
    if exists(vendor_aliases_arg)
        and not valid_json(vendor_aliases_arg, 'vendor_aliases') then
      stdnse.verbose(1, fmt(
        'Invalid vendor aliases file %s; skipping vendor aliases.',
        vendor_aliases_arg))
    end
    local product_cpe_arg = config.product_cpe
    registry.product_cpe = {}
    if product_cpe_arg ~= 'none' and exists(product_cpe_arg)
        and not valid_json(product_cpe_arg, 'product_cpe') then
      stdnse.verbose(1, fmt(
        'Invalid product CPE file %s; skipping CPE overrides.',
        product_cpe_arg))
    end
    registry.platform_families = load_platform_families()
    if http_arg == '1' and catalog_arg ~= 'none' then
      if not load_catalog() and not load_legacy_catalog() then
        stdnse.verbose(1,
          'HTTP catalogue unavailable; continuing with Nmap CPEs.')
      end
    end
    registry.load_local_catalog(config.local_catalog)
  end
  return ret
end


-- Match recording lives in the matches module.
local cpe_has_precise_version, prune_series_versions
do
  local match_mod = require 'cvescannerv2.matches'
  cpe_has_precise_version = match_mod.cpe_has_precise_version
  prune_series_versions = match_mod.prune_series_versions
end


-- Fingerprint matching moved to the fingerprint module, used by this
-- script.
local response_subjects, match_subjects, probe_version
do
  local fp = require 'cvescannerv2.fingerprint'
  response_subjects = fp.response_subjects
  match_subjects = fp.match_subjects
  probe_version = fp.probe_version
end


-- HTTP fingerprint engine moved to the httpscan module, used by this script.
local sweep_catalog
do
  local httpscan = require 'cvescannerv2.httpscan'
  sweep_catalog = httpscan.sweep_catalog
end




-- Scope helpers moved to the scope module, used by this script.
local scoped_multi_versions, scoped_versions, merge_series
do
  local scope = require 'cvescannerv2.scope'
  scoped_multi_versions = scope.scoped_multi_versions
  scoped_versions = scope.scoped_versions
  merge_series = scope.merge_series
end


local platform, platform_probe_needed, strip_platform_reasons
do
  platform = require 'cvescannerv2.platform'
  platform_probe_needed = platform.platform_probe_needed
  strip_platform_reasons = platform.strip_platform_reasons
end




-- Confidence helpers live in the confidence module (layer 5).
local confidence_comparator, score_vulns, add_reason
local LEVEL_RANK
do
  local confidence = require 'cvescannerv2.confidence'
  confidence_comparator = confidence.confidence_comparator
  score_vulns = confidence.score_vulns
  add_reason = confidence.add_reason
  LEVEL_RANK = confidence.LEVEL_RANK
end


-- Output text lives in the render module (layer 6).
local cve_row
do
  local render = require 'cvescannerv2.render'
  cve_row = render.cve_row
end


-- OS probes live in the probes.init module.
local host_probe_os = require 'cvescannerv2.probes.init'.host_probe_os






prerule = function()
  local req = required_files()
  if req ~= "" then
    stdnse.verbose(1, req)
    registry.status = false
  end
  return registry.status
end


hostrule = function(_)
  return registry.status
end


portrule = function(_, port)
  return registry.status and
      port.service ~= 'tcpwrapped' and
      port.service ~= 'unknown'
end


postrule = function()
  return registry.status
end


preaction = function()
  local db = require 'cvescannerv2.db'
  db.open(db_arg)
  local logfile = require 'cvescannerv2.log'
  logfile.open(log_arg)
  registry.time = datetime.format_timestamp(os.time(), 0)
  registry.cache = {}
  registry.json_out = {}
  timestamp(version)
  local config = require 'cvescannerv2.config'
  if not config.minconf_valid then
    log("[!] minconf '%s' is invalid, using low", config.minconf_raw)
  end
end


hostaction = function(host)
  local report = require 'cvescannerv2.report'
  report.ensure_host(host.ip)
end


-- Match collection lives in the collect module (layer 6).
local collect = require 'cvescannerv2.collect'
-- Match analysis lives in the analysis module (layer 8). Not named
-- 'analysis' so the test harness can expose the module function.
local analyze = require 'cvescannerv2.analysis'.analysis


portaction = function(host, port)
  local report = require 'cvescannerv2.report'
  report.ensure_host(host.ip)
  local matches = collect.port(host, port)
  local vulns
  if matches['size'] ~= 0 then
    local ctx = {
      os = os_context(host, port),
      backport = distro_backport(port),
    }
    vulns = analyze(host, port, matches, ctx)
  end
  if vulns and #vulns > 0 then return vulns end
end


postaction = function()
  local db = require 'cvescannerv2.db'
  local closed, close_err = db.close()
  if not closed then
    log("[!] could not close database connection: %s", close_err)
  end
  local logfile = require 'cvescannerv2.log'
  logfile.close()
  local report = require 'cvescannerv2.report'
  report.write(json_arg)
end


local ActionsTable = {
  prerule = preaction,
  hostrule = hostaction,
  portrule = portaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
