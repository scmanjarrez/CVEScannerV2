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
-- |   vendor: oracle
-- |   product: mysql
-- |   version: 5.5.55
-- |   vupdate: *
-- |   version_source: nmap
-- |   cves: 4
-- |       CVE ID           Conf  CVSSv2  CVSSv3  ExploitDB  Metasploit
-- |       CVE-2021-3278    HIGH  7.5     9.8     Yes        No
-- |       CVE-2014-3631    MED   7.2     -       Yes        Yes
-- |       CVE-2019-13401   LOW   6.8     8.8     No         No
-- |_      CVE-2016-3976    LOW   5.0     7.5     Yes        Yes
--
-- @args cvescannerv2.db Database file. Default: data/cve.db
-- @args cvescannerv2.maxcve Maximum number of CVEs printed on screen.
--       Default: 10
-- @args cvescannerv2.maxredirect Maximum number of redirections followed.
--       Default: 1
-- @args cvescannerv2.sweep Request every catalogue path on HTTP ports
--       (slow). Default: 0. Values: 0, 1
-- @args cvescannerv2.log Output .log file location.
--       Default: cvescannerv2.log
-- @args cvescannerv2.json Output .json file location.
--       Default: cvescannerv2.json
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
