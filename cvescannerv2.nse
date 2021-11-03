-- SPDX-License-Identifier: GPL-3.0-or-later

-- cvescannerv2 - NSE script.

-- Copyright (C) 2021 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
-- Universidad Carlos III de Madrid.

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
-- along with GNU Emacs.  If not, see <https://www.gnu.org/licenses/>.

description = [[
Search for probable vulnerabilities based on services discovered in open ports.
CVEs information gathered from nvd.nist.gov.
]]
--- Prerequisite: Download Databases
-- @usage ./databases.py
--
--- Optional: Download semiupdated databases from CVEScannerV2DB repository
--
--- Run: Execute CVEscannerV2
-- @usage nmap -sV <target-ip> --script=./cvescannerv2.nse
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
-- maxcve: Limit the number of CVEs printed on screen (default 10)
-- log: Change the log file (default cvescannerv2.log)
-- db: Change the database file (default cve.db)
-- path: Change the paths file (default http-paths-vulnerscom.json)
-- regex: Change the regex file (default http-regex-vulnerscom.json)
-- @usage nmap -sV <target-ip> --script=./cvescannerv2.nse --script-args log=logfile.log
-- @usage nmap -sV <target-ip> --script=./cvescannerv2.nse --script-args log=logfile.log,maxcve=20,db=mydb.db
--
---

categories = {"discovery", "version", "safe"}
author = "Sergio Chica"

local http = require 'http'
local json = require 'json'
local nmap = require 'nmap'
local shortport = require 'shortport'
local sql = require 'luasql.sqlite3'
local stdnse = require 'stdnse'

local db_arg = stdnse.get_script_args('db') or 'cve.db'
local log_arg = stdnse.get_script_args('log') or 'cvescannerv2.log'
local maxcve_arg = stdnse.get_script_args('maxcve') or 10
local path_arg = stdnse.get_script_args('path') or 'http-paths-vulnerscom.json'
local regex_arg = stdnse.get_script_args('regex') or 'http-regex-vulnerscom.json'


if not nmap.registry[SCRIPT_NAME] then
   nmap.registry[SCRIPT_NAME] = {
      conn = nil,
      cache = nil,
      env = nil,
      logger = nil,
      path = nil,
      regex = nil,
      status = true,
      time = nil
   }
end


local registry = nmap.registry[SCRIPT_NAME]


local function empty (str)
   return str == nil or str == ''
end


local function exists (file)
   local f = io.open(file, 'r')
   return f ~= nil and f:close()
end


local function fmt (msg, ...)
   return msg:format(...)
end

-- Implementation of named parameters from RiciLake@lua-users
local function fmtn(msg, tab)
   return msg:gsub(
      '($%b{})',
      function(nparam)
         -- nparam -> ${var} => nparam:sub(3, -2) -> var
         return tab[nparam:sub(3, -2)] or "nil"
      end
   )
end


local function timestamp ()
   local pad = string.rep("#", 49)
   local pad_mid = string.rep("#", 14)
   registry.logger:write(
      fmt(pad .. "\n" .. pad_mid .. " %s " .. pad_mid .. "\n" .. pad .. "\n\n",
          registry.time))
   stdnse.verbose(1, fmt("Timestamp: %s", registry.time))
   stdnse.verbose(1, fmt("CVE data source: %s", "nvd.nist.gov"))
end


local function correct_version (info)
   if not info.range then
      return info.ver,  info.vup
   else
      return info.from .. "- ".. info.to, "*"
   end
end


local function log (msg, ...)
   registry.logger:write(fmt(msg .. "\n", ...))
end


local function log_separator ()
   log(string.rep("-", 49))
end


local function log_info (host, port, product, info)
   log("[*] host: %s", host.ip)
   log("[*] port: %s", port.number)
   log("[+] protocol: %s", port.protocol)
   log("[+] service: %s", port.service)
   log("[+] product: %s", product)
   local v, vu = correct_version(info)
   log("[+] version: %s", v)
   log("[+] vupdate: %s", vu)
end


local function log_detection (dtype, status)
   local extra = ''
   if dtype ~= 'HTTP' and status == 'failed' then
      extra = " Trying HTTP detection."
   end
   stdnse.verbose(2, fmt("%s detection %s.%s", dtype, status, extra))
end


local function check_http (cpe)
   if not cpe then
      log_detection("HTTP", "failed")
   else
      log_detection("HTTP", "worked")
   end
end


local function valid_json (arg, is_path)
   local f = io.open(arg, 'r')
   local status, data = json.parse(f:read('*all'))
   if status then
      if is_path then
         registry.path = data
      else
         registry.regex = data
      end
   end
   f:close()
   return status
end


local function required_files ()
   local ret = ""
   if not exists(db_arg) then
      ret = fmt("Database %s not found. " ..
                "Run ./databases.py before running nmap script.",
                db_arg)
   elseif not exists(path_arg) then
      ret = fmt("Paths file %s not found.", path_arg)
   elseif not valid_json(path_arg, true) then
      ret = fmt("Invalid json %s.", path_arg)
   elseif not exists(regex_arg) then
      ret = fmt("Regexes file %s not found.", regex_arg)
   elseif not valid_json(regex_arg, false) then
      ret = fmt("Invalid json %s.", regex_arg)
   end
   return ret
end


local function regex_match (text, location)
   for _, software in pairs(registry.regex[location]) do
      if type(software.regex) == 'table' then
         for _, regex in pairs(software.regex) do
            local _, _, version = text:find(regex)
            if version then
               return software.cpe, version
            end
         end
      else
         local _, _, version = text:find(software.regex)
         if version then
            return software.cpe, version
         end
      end
   end
end


local function http_match (host, port)
   for _, path in pairs(registry.path['path']) do
      for _, ext in pairs(registry.path['extension']) do
         local file = "/" .. path .. ext
         local resp = http.get(host.ip, port.number, file)
         if not resp.status then
            stdnse.verbose(2, fmt("Error processing request http://%s:%s%s => %s",
                                  host.ip, port.number, file, resp['status-line']))
         else
            if #resp.rawheader > 0 then
               for _, header in ipairs(resp.rawheader) do
                  local cpe, version = regex_match(header, 'header')
                  if cpe then
                     return cpe, version
                  end
               end
            end
            if resp.rawbody ~= "" then
               local cpe, version = regex_match(resp.rawbody, 'body')
               if cpe then
                  return cpe, version
               end
            end
         end
      end
   end
end


local function version_parser (product, version)
   if version then
      -- remove Nmap comment of version
      version = version:gsub('for_windows_', '')
   end

   -- if Nmap could not detect version, assume all versions and vupdates possible
   if empty(version) then
      return product, {ver = '*', vup = '*',
                       from = nil, to = nil,
                       empty = true, range = false}
   end

   -- if version matches patterns: 3.x - 4.x | 3.3.x - 3.4.x ...
   local p1, p2 = version:match('([^-]*)%s*-%s*([^-]*)')
   if not empty(p1) and not empty(p2) then
      local f1, f2 = p1:match('([^%a]*)(.*)')
      local t1, t2 = p2:match('([^%a]*)(.*)')
      return product, {ver = nil, vup = nil,
                       from = f1 .. f2,
                       to = t1 .. t2,
                       empty = false, range = true}
   end

   -- if version matches patterns: 4.3 | 4.3.1 ...
   p1, p2 = version:match('([%d.]*)(.*)')
   if not empty(p1) then
      if empty(p2) then
         p2 = '*'
      end
      return product, {ver = p1, vup = p2,
                       from = nil, to = nil,
                       empty = false, range = false}
   end
end


local function cpe_parser (cpe, version)
   local info = {}
   for data in (cpe .. ':'):gmatch('([^:]*):') do
      table.insert(info, data)
   end

   -- [1] = cpe, [2] = /a or /h or /o, [3] = vendor, [4] = product, [5] = version
   if #info == 4 then
      table.insert(info, version)
   end

   return version_parser(info[4], info[5])
end


local function query (qtype)
   if qtype == 'cve_score' then
      return [[
             SELECT cvss_v2, cvss_v3
             FROM cves
             WHERE cve_id = '%s'
             ]]
   elseif qtype == 'exploit_info' then
      return [[
             SELECT exploits.exploit_id, exploits.name
             FROM referenced_exploit
             INNER JOIN exploits ON referenced_exploit.exploit_id = exploits.exploit_id
             WHERE referenced_exploit.cve_id = '%s'
             ]]
   elseif qtype == 'metasploit_info' then
      return [[
             SELECT metasploits.name
             FROM referenced_metasploit
             INNER JOIN metasploits ON referenced_metasploit.metasploit_id = metasploits.metasploit_id
             WHERE referenced_metasploit.cve_id = '%s'
             ]]
   elseif qtype == 'multiaffected' then
      return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
             FROM multiaffected
             INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
             WHERE product_id =
             (SELECT product_id FROM products WHERE product = '${p}' AND version = '*')
             AND (IFNULL(versionStartIncluding, '0') < '${v}'
                  OR IFNULL(versionStartIncluding, '0') LIKE '${v}')
             AND (IFNULL(versionStartExcluding, '0') < '${v}')
             AND (IFNULL(versionEndIncluding, '9999') > '${v}'
                  OR IFNULL(versionEndIncluding, '9999') LIKE '${v}')
             AND (IFNULL(versionEndExcluding, '9999') > '${v}')
             GROUP BY multiaffected.cve_id
             ]]
   elseif qtype == 'multiaffected_empty' then
      return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
             FROM multiaffected
             INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
             WHERE product_id =
             (SELECT product_id FROM products WHERE product = '${p}' AND version = '*' and version_update = '*')
             AND versionStartIncluding IS NULL AND versionStartExcluding IS NULL
             AND versionEndIncluding IS NULL AND versionEndExcluding IS NULL
             GROUP BY multiaffected.cve_id
             ]]
   elseif qtype == 'multiaffected_range' then
      return [[
             SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
             FROM multiaffected
             INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
             WHERE product_id =
             (SELECT product_id FROM products WHERE product = '${p}' AND version = '*')
             AND (IFNULL(versionStartIncluding, '0') < '${f}'
                  OR IFNULL(versionStartIncluding, '0') LIKE '${f}')
             AND (IFNULL(versionStartExcluding, '0') < '${f}')
             AND (IFNULL(versionEndIncluding, '9999') > '${t}'
                  OR IFNULL(versionEndIncluding, '9999') LIKE '${t}')
             AND (IFNULL(versionEndExcluding, '9999') > '${t}')
             GROUP BY multiaffected.cve_id
             ]]
   elseif qtype == 'affected' then
      return [[
             SELECT affected.cve_id, cves.cvss_v2, cves.cvss_v3,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = affected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = affected.cve_id)) as msf
             FROM products
             INNER JOIN affected ON products.product_id = affected.product_id
             INNER JOIN cves ON affected.cve_id = cves.cve_id
             WHERE products.product = '${p}'
             AND ((products.version = '${v}' AND products.version_update = '${vu}')
                  OR (products.version = '${v}${vu}' AND products.version_update = '*'))
             GROUP BY affected.cve_id
             ]]
   elseif qtype == 'affected_range' then
      return [[
             SELECT affected.cve_id, cves.cvss_v2, cves.cvss_v3,
             (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = affected.cve_id)) as edb,
             (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = affected.cve_id)) as msf
             FROM products
             INNER JOIN affected ON products.product_id = affected.product_id
             INNER JOIN cves ON affected.cve_id = cves.cve_id
             WHERE products.product = '${p}'
             AND (products.version > '${f}' OR products.version LIKE '${f}')
             AND (products.version < '${t}' OR products.version LIKE '${t}')
             GROUP BY affected.cve_id
             ]]
   end
end


local function dump_exploit (vuln)
   -- Dump the CVE score
   local cur = registry.conn:execute(
      fmt(query('cve_score'), vuln)
   )
   local cvssv2, cvssv3 = cur:fetch()
   log("[-] \tid: %-18s\tcvss_v2: %-5s\tcvss_v3: %-5s", vuln, cvssv2, cvssv3)

   -- Dump exploits from Exploit-DB
   cur = registry.conn:execute(
      fmt(query('exploit_info'), vuln)
   )
   local exploit, name = cur:fetch()
   if exploit then
      log("[!] \t\tExploitDB:")
      while exploit do
         log("[#] \t\t\tname: %s", name)
         log("[#] \t\t\tid: %s", exploit)
         log("[#] \t\t\turl: https://www.exploit-db.com/exploits/%s", exploit)
         exploit, name = cur:fetch()
      end
   end

   -- Dump exploits from Metasploit
   cur = registry.conn:execute(
      fmt(query('metasploit_info'), vuln)
   )
   name = cur:fetch()
   if name then
      log("[!] \t\tMetasploit:")
      while name do
         log("[#] \t\t\tname: %s", name)
         name = cur:fetch()
      end
   end
end


local function vulnerabilities (product, info)
   local qrym = "multiaffected"
   local qry = "affected"
   if not info.empty then
      if not info.range then
         qrym = fmtn(query(qrym), {p = product, v = info.ver})
         qry = fmtn(query(qry), {p = product, v = info.ver, vu = info.vup})
      else
         local sql_f = info.from:gsub('[xX]', '%%')
         local sql_t = info.to:gsub('[xX]', '%%')
         qrym = fmtn(query(qrym .. '_range'), {p = product, f = sql_f, t = sql_t})
         qry = fmtn(query(qry .. '_range'), {p = product, f = sql_f, t = sql_t})
      end
   else
      -- Given that we assumed '*' as version and vupdate when empty,
      -- we can't search vulnerabilities for specific versions
      qrym = fmtn(query(qrym .. '_empty'), {p = product})
   end

   -- Search vulnerabilities affecting multiple versions (this one included)
   local cur = registry.conn:execute(qrym)
   local vuln, cvssv2, cvssv3, exploitdb, metasploit = cur:fetch()
   local vulns = {}
   while vuln do
      vulns[vuln] = {CVSSV2 = cvssv2, CVSSV3 = cvssv3,
                     ExploitDB = exploitdb,
                     Metasploit = metasploit}
      vuln, cvssv2, cvssv3, exploitdb, metasploit = cur:fetch()
   end

   if not info.empty then
      -- Search vulnerabilities affecting specific version
      cur = registry.conn:execute(qry)
      vuln, cvssv2, cvssv3, exploitdb, metasploit = cur:fetch()
      while vuln do
         vulns[vuln] = {CVSSV2 = cvssv2, CVSSV3 = cvssv3,
                        ExploitDB = exploitdb,
                        Metasploit = metasploit}
         vuln, cvssv2, cvssv3, exploitdb, metasploit = cur:fetch()
      end
   end

   -- Sort CVEs by CVSSv2
   local sorted = {}
   for key, value in pairs(vulns) do
      table.insert(sorted, {key,
                            value.CVSSV2, value.CVSSV3,
                            value.ExploitDB,
                            value.Metasploit})
   end
   table.sort(sorted, function(a, b) return a[2] > b[2] end)
   log("[+] cves: %d", #sorted)

   -- Insert total vulnerabilities found
   local output = {}
   table.insert(output, #sorted)

   -- Pretty print the output
   local cnt = 0
   for _, value in ipairs(sorted) do
      dump_exploit(value[1])
      if cnt < tonumber(maxcve_arg) then
         table.insert(output,
                      fmt(
                         "\t%-20s\t%-5s\t%-5s\t%-10s\t%-10s",
                         value[1],
                         value[2], value[3] and value[3] or "-",
                         value[4] == 1 and "Yes" or "No",
                         value[5] == 1 and "Yes" or "No"
                      )
         )
      end
      cnt = cnt + 1
   end
   log_separator()
   cur:close()
   return output
end


local function nmap_analysis (host, port, product, info)
   log_info(host, port, product, info)
   local v, vu = correct_version(info)
   if not registry.cache[fmt('%s|%s|%s', product, v, vu)] then
      local vulns = vulnerabilities(product, info)
      local nvulns = table.remove(vulns, 1)
      if nvulns > 0 then
         table.insert(vulns, 1, fmt("product: %s", product))
         table.insert(vulns, 2, fmt("version: %s", v))
         table.insert(vulns, 3, fmt("vupdate: %s", vu))
         table.insert(vulns, 4, fmt("cves: %d", nvulns))
         table.insert(vulns, 5,
                      fmt(
                         "\t%-20s\t%-5s\t%-5s\t%-10s\t%-10s",
                         "CVE ID", "CVSSv2", "CVSSv3", "ExploitDB", "Metasploit"
                      )
         )
         stdnse.verbose(2, "Caching product-version-vupdate vulnerabilities.")
         registry.cache[fmt('%s|%s|%s', product, v, vu)] = vulns
         return vulns
      end
   else
      log("[+] cves: cached")
      stdnse.verbose(2, "Using cached product-version-vupdate vulnerabilities.")
      return registry.cache[fmt('%s|%s|%s', product, v, vu)]
   end
end


local function http_analysis (host, port)
   if shortport.http(host, port) or shortport.ssl(host, port) then
      stdnse.verbose(2, "Reading HTTP header/body.")
      local http_cpe, http_version = http_match(host, port)
      stdnse.verbose(2,
                   fmt("HTTP detection: cpe => %s | version => %s",
                       http_cpe, http_version))
      if http_cpe then
         local product, info = cpe_parser(http_cpe, http_version)
         local vulns = nmap_analysis(host, port, product, info)
         return vulns, http_cpe, http_version
      end
   end
end


prerule = function ()
   local req = required_files()
   if req ~= "" then
      registry.status = false
      stdnse.verbose(1, req)
   end
   return registry.status
end


portrule = function (_, port)
   return registry.status and
      port.service ~= 'tcpwrapped' and
      port.service ~= 'unknown'
end


postrule = function ()
   return registry.status
end


preaction = function ()
   registry.env = sql.sqlite3()
   registry.conn = registry.env:connect(db_arg)
   registry.logger = io.open(log_arg, 'a')
   registry.time = os.date("%Y-%m-%d %H:%M:%S")
   registry.cache = {}
   timestamp()
end


portaction = function (host, port)
   local vulns = nil
   local http_scan = true
   local http_cpe = nil
   local http_version = nil
   if port.version.cpe[1] ~= nil then
      log_detection("Nmap", "worked")
      local product, info = cpe_parser(port.version.cpe[1], port.version.version)
      stdnse.verbose(2,
                     fmt("Nmap detection: cpe => %s | version => %s",
                         port.version.cpe[1], port.version.version))
      if info then
         log_detection("CVEScannerV2", "worked")
         stdnse.verbose(2,
                        fmtn("CVEScannerV2 detection: product => ${p} | " ..
                            "version => ${v} | vupdate => ${vu} | " ..
                            "range_from => ${f} | range_to => ${t}",
                            {p = product, v = info.ver, vu = info.vup,
                             f = info.from, t = info.to}))
         vulns = nmap_analysis(host, port, product, info)
         if not vulns then
            stdnse.verbose(2,
                           "No vulnerabilities found for detected version. " ..
                           "Trying HTTP detection.")
            vulns, http_cpe, http_version = http_analysis(host, port)
            check_http(http_cpe)
         else
            http_scan = false
         end
      else
         log_detection("CVEScannerV2", "failed")
         vulns, http_cpe, http_version = http_analysis(host, port)
         check_http(http_cpe)
      end
   else
      log_detection("Nmap", "failed")
      vulns, http_cpe, http_version = http_analysis(host, port)
      check_http(http_cpe)
   end

   if not vulns then
      vulns = {}
      table.insert(vulns,
                   "No vulnerabilities found in DB. " ..
                   "If you think this could be an error, open an Issue in GitHub.")
      table.insert(vulns, "Attach the following information in the Issue:")
      table.insert(vulns, fmt("\tnmap_service => %s\n" ..
                              "\tnmap_cpe => %s\n" ..
                              "\tnmap_version => %s",
                              port.version.name,
                              port.version.cpe[1],
                              port.version.version))
      if http_scan then
         table.insert(vulns, fmt("\thttp_cpe => %s\n" ..
                                 "\thttp_version => %s",
                                 http_cpe, http_version))
      end
   end
   return vulns
end


postaction = function ()
   registry.conn:close()
   registry.env:close()
   registry.logger:write("\n")
   registry.logger:close()
end


local ActionsTable = {
   prerule = preaction,
   portrule = portaction,
   postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function (...) return ActionsTable[SCRIPT_TYPE](...) end
