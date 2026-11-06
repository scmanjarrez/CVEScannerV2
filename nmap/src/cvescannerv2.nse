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
-- Catalogue: run scripts/download-catalog.sh (Docker already includes it).
--
--- Run: Execute CVEscannerV2
-- @usage nmap -sV --script cvescannerv2 <target-ip>
-- @usage nmap -sV --script cvescannerv2 --script-args log=logfile.log,json=logfile.json <target-ip>
-- @usage nmap -sV --script cvescannerv2 --script-args sweep=1 <target-ip>
--
-- @output
-- PORT      STATE SERVICE       VERSION
-- 3306/tcp  open  mysql         MySQL 5.5.55
-- | cvescannerv2:
-- | oracle mysql 5.5.55 (cpe:/a:oracle:mysql:5.5.55)  source: nmap_cpe
-- | CVEs: 4  high: 1  medium: 1  low: 2
-- |   CVE              CONF  EXPLOITS  CVSS
-- |   CVE-2021-3278    HIGH  EDB       v3:9.8 v2:7.5
-- |   CVE-2014-3631    MED   EDB MSF   v2:7.2
-- |   CVE-2019-13401   LOW   -         v3:8.8 v2:6.8
-- |_  CVE-2016-3976    LOW   EDB MSF   v3:7.5 v2:5.0
--
-- When there are more CVEs than maxcve or below minconf, the last line
-- tells how many are hidden and where the full list is:
-- |_+55 more (maxcve=10). Full list: /path/cvescannerv2.json
--
-- @args cvescannerv2.db Database file. Default: data/cve.db
-- @args cvescannerv2.maxcve Maximum number of CVEs printed on screen.
--       Default: 10
-- @args cvescannerv2.maxredirect Maximum number of redirections followed.
--       Default: 1
-- @args cvescannerv2.sweep Tiered catalogue sweep on HTTP ports.
--       Default: 0. Values: 0 (off), 1 (tiers: '/', soft-404 probe,
--       ≤16 core paths, families with evidence, linked paths; capped by
--       sweep_budget), 2 (tiers + every remaining catalogue path).
-- @args cvescannerv2.sweep_budget Maximum requests per HTTP port with
--       sweep=1. Default: 50. sweep=2 is unlimited unless set explicitly.
-- @args cvescannerv2.log Output .log file location.
--       Default: cvescannerv2.log. Header with version and args, one block
--       per service (cpe, counts, warnings), one line per visible CVE with
--       CVSS and reasons, indented exploits, and a footer with the totals.
-- @args cvescannerv2.json Output .json file location.
--       Default: cvescannerv2.json. JSON Lines: one record per run
--       (schema_version 2) with only the services that have CVEs, one
--       entry per service and port.
-- @args cvescannerv2.catalog Vulners catalogue read from data/ (index.json,
--       fingerprints.json, paths.json, probes.json). Default: auto. Set to
--       none to disable HTTP fingerprinting. The catalogue can be downloaded
--       by running scripts/download-catalog.sh.
-- @args cvescannerv2.local_catalog Local catalogue merged on top of the
--       upstream one. Default: data/local-catalog.json. Set to none to
--       disable.
-- @args cvescannerv2.aliases Product aliases file.
--       Default: data/product-aliases.json
-- @args cvescannerv2.vendor_aliases Vendor aliases file.
--       Default: data/vendor-aliases.json
-- @args cvescannerv2.product_cpe Product to CPE overrides for Nmap products,
--       replacing the CPE that Nmap reports. Default:
--       data/product-cpe.json. Set to none to disable.
-- @args cvescannerv2.service Restrict the search to a specific service.
--       Default: all
-- @args cvescannerv2.version Restrict the search to a specific version.
--       Default: all
-- @args cvescannerv2.probes Service version probes to run: all, none or a
--       comma-separated list of probe names (e.g. smb, irc). Default: all.
--       The irc probe reads the exact UnrealIRCd version with a read-only
--       IRC VERSION request.
-- @args cvescannerv2.minconf Minimum confidence of the CVEs shown in the
--       table and the log: low, medium or high. Default: low. Invalid
--       values use low. The JSON report always keeps every CVE.
---

categories = { "safe" }
-- dependencies only raises the runlevel. With -sV every "version" script
-- already runs in runlevel 1, so listing one here is not needed to read
-- its port.version; the list forces this script into runlevel 2.
dependencies = {
  "weblogic-t3-info", "oracle-tns-version", "docker-version",
  "jdwp-version", "vmware-version", "db2-das-info", "ike-version",
  "mqtt-subscribe", "amqp-info", "xmpp-info",
}
author = "Sergio Chica"
local version = "4.0"

local http = require 'http'
http.USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0'

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

-- Script arguments are read once by the config module, before any rule.
require 'cvescannerv2.config'.load()
local lifecycle = require 'cvescannerv2.lifecycle'
prerule = lifecycle.prerule
hostrule = lifecycle.hostrule
portrule = lifecycle.portrule
postrule = lifecycle.postrule
preaction = function() return lifecycle.preaction(version) end
portaction = lifecycle.portaction
postaction = lifecycle.postaction

local ActionsTable = {
  prerule = preaction,
  hostrule = lifecycle.hostaction,
  portrule = portaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
