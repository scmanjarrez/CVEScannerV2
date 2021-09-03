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
--- Optional parameters
-- maxcve: Limit the number of CVEs printed on screen (default 10)
-- log: Change the log file (default cvescannerv2.log)
-- db: Change the database file (default cve.db)
-- @usage nmap -sV <target-ip> --script=./cvescannerv2.nse --script-args log=logfile.log
-- @usage nmap -sV <target-ip> --script=./cvescannerv2.nse --script-args log=logfile.log,maxcve=20,db=mydb.db
--
---

categories = {"discovery", "version", "safe"}
author = "Sergio Chica"

local nmap = require "nmap"
local stdnse = require "stdnse"
local sql = require "luasql.sqlite3"

local db_arg = stdnse.get_script_args('db') or 'cve.db'
local log_arg = stdnse.get_script_args('log') or 'cvescannerv2.log'
local maxcve_arg = stdnse.get_script_args('maxcve') or 10


if not nmap.registry[SCRIPT_NAME] then
   nmap.registry[SCRIPT_NAME] = {
      env = nil,
      conn = nil,
      logger = nil,
      time = nil
   }
end

local registry = nmap.registry[SCRIPT_NAME]


local function fmt (msg, ...)
   return string.format(msg, ...)
end


local function db_exists ()
   local db = io.open(db_arg, "r")
   return db ~= nil and io.close(db)
end


prerule = function ()
   if not db_exists() then
      stdnse.verbose(1,
                     fmt("Database %s not found. " ..
                         "Run ./databases.py before running nmap script.",
                         db_arg)
      )
      os.exit()
   else
      return true
   end
end

-- Returns true for every host-port open
portrule = function (host, port)
   return port.service ~= "tcpwrapped" and
      port.service ~= "unknown" and
      port.version.product ~= nil and
      port.version.version ~= nil
end


postrule = function ()
   return true
end


local function log (msg, ...)
   registry.logger:write(fmt(msg .. "\n", ...))
end


local function timestamp ()
   registry.logger:write(fmt("#################################################\n" ..
                             "############## %s ##############\n" ..
                             "#################################################\n\n", registry.time))
   stdnse.verbose(2, fmt("Timestamp: %s", registry.time))
end


local function log_exploit (vuln)
   log("[+] \tid: %s", vuln)
   local cur = registry.conn:execute(
      fmt([[
          SELECT referenced.exploit_id, exploits.name, exploits.metasploit
          FROM referenced
          INNER JOIN exploits ON referenced.exploit_id = exploits.exploit_id
          WHERE referenced.cve_id = "%s"
          ]],
          vuln)
   )
   local exploit, name, metasploit = cur:fetch()
   while exploit do
      log("[*] \t\texploit_name: %s", name)
      log("[*] \t\texploit_url: https://www.exploit-db.com/exploits/%s", exploit)
      log("[*] \t\tmetasploit_name: %s", metasploit ~= nil and metasploit or "-")
      exploit, name, metasploit = cur:fetch()
   end
end


local function vulnerabilities (product, version, vupdate, multiple)
   local cur = nil
   if not multiple then
      -- Query CVE, CVSSv2, CVSSv3, Exist_Exploits, Exist_Metasploit
      -- by product and version
      cur = registry.conn:execute(
         fmt([[
              SELECT affected.cve_id, cves.cvss_v2, cves.cvss_v3,
              (SELECT EXISTS (SELECT 1 FROM referenced WHERE cve_id = affected.cve_id)) AS ExploitDB,
              (SELECT EXISTS (SELECT 1 FROM exploits as ex
              INNER JOIN referenced AS rf ON rf.exploit_id = ex.exploit_id
              WHERE rf.cve_id = affected.cve_id AND ex.metasploit IS NOT NULL)) AS Metasploit
              FROM products
              INNER JOIN affected ON products.product_id = affected.product_id
              INNER JOIN cves ON affected.cve_id = cves.cve_id
              WHERE products.product = "%s"
              AND products.version = "%s"
              AND products.version_update = "%s"
              GROUP BY affected.cve_id
              ]],
              product, version, vupdate)
      )
   else
      -- Query CVE_ID, CVSSv2, CVSSv3, Exist_Exploits, Exist_Metasploit
      -- by product and multiple versions
      cur = registry.conn:execute(
         fmt([[
              SELECT affected.cve_id, cves.cvss_v2, cves.cvss_v3,
              (SELECT EXISTS (SELECT 1 FROM referenced WHERE cve_id = affected.cve_id)) AS ExploitDB,
              (SELECT EXISTS (SELECT 1 FROM exploits as ex
              INNER JOIN referenced AS ref ON ref.exploit_id = ex.exploit_id
              WHERE ref.cve_id = affected.cve_id AND ex.metasploit IS NOT NULL)) AS Metasploit
              FROM products
              INNER JOIN affected ON products.product_id = affected.product_id
              INNER JOIN cves ON affected.cve_id = cves.cve_id
              WHERE products.product = "%s"
              AND (products.version > "%s" OR products.version LIKE "%s")
              AND (products.version < "%s" OR products.version LIKE "%s")
              GROUP BY affected.cve_id
              ]],
              product, version, version, vupdate, vupdate)
      )
   end
   local vulns = {}
   local vuln, cvssv2, cvssv3, exploitdb, metasploit = cur:fetch()
   while vuln do
      vulns[vuln] = {CVSSV2 = cvssv2, CVSSV3 = cvssv3, ExploitDB = exploitdb, Metasploit = metasploit}
      vuln, cvssv2, cvssv3, exploitdb, metasploit = cur:fetch()
   end

   -- Sort CVEs by CVSSv2
   local sorted = {}
   for key, value in pairs(vulns) do
      table.insert(sorted, {key, value.CVSSV2, value.CVSSV3, value.ExploitDB, value.Metasploit})
   end
   table.sort(sorted, function(a, b) return a[2] > b[2] end)

   log("[+] cves: %d", #sorted)

   -- Pretty print the output
   local output = {}
   table.insert(output, #sorted)
   local counter = 0
   for _, value in ipairs(sorted) do
      log_exploit(value[1])
      if counter < tonumber(maxcve_arg) then
         table.insert(output,
                      fmt(
                         "\t%-15s\t%-5s\t%-5s\t%-10s\t%-10s",
                         value[1], value[2],
                         value[3] and value[3] or "-",
                         value[4] == 1 and "Yes" or "No",
                         value[5] == 1 and "Yes" or "No"
                      )
         )
      end
      counter = counter + 1
   end
   cur:close()
   return output
end


local function find_version(product, version, vupdate)
   local cur = registry.conn:execute(
      fmt([[
          SELECT COUNT(*)
          FROM products
          WHERE products.product = "%s"
          AND products.version = "%s"
          AND products.version_update = "%s";
          ]],
          product, version, vupdate)
   )
   return cur:fetch()
end


local function version_check(product, version)
   local ver, vup = version:match("([^-]*)- ([^-]*)")
   -- if ver match patterns: 3.x - 4.y | 3.x.y - 3.x.z | etc
   if ver ~= nil then
      local from, to = ver, vup
      if from == nil and to == nil then
         return nil
      else
         f1, f2 = from:match("([^%a]*)(.*)")
         f2 = f2:gsub("[xX]", "%%")
         t1, t2 = to:match("([^%a]*)(.*)")
         t2 = t2:gsub("[xX]", "%%")
         return product, nil, nil, f1 .. f2, t1 .. t2
      end
   else
      ver, vup = version:match("([0-9.]*)([^-]*).*")
   end
   if find_version(product, ver, vup) ~= 0 then
      return product, ver, vup
   elseif find_version(product, ver .. vup, "*") ~= 0 then
      return product, ver .. vup, "*"
   else
      return nil
   end
end


local function cpe_info(cpe, version)
   local info = {}
   for data in (cpe .. ":"):gmatch("([^:]*):") do
      table.insert(info, data)
   end
   -- [1] = cpe, [2] = /a or /h or /o, [3] = vendor, [4] = product, [5] = version
   if #info == 4 then
      table.insert(info, version)
   end
   return version_check(info[4], info[5])
end


local function log_product(product, version, vupdate)
   log("[+] product: %s", product)
   log("[+] version: %s", version)
   log("[+] vupdate: %s", vupdate)
end


local function preaction ()
   registry.env = sql.sqlite3()
   registry.conn = registry.env:connect(db_arg)
   registry.logger = io.open(log_arg, 'a')
   registry.time = os.date("%Y-%m-%d %H:%M:%S")
   timestamp()
end


local function portaction (host, port)
   if port.version.cpe[1] ~= nil then
      print(port.version.cpe[1])
      local product, version, vupdate, from, to = cpe_info(port.version.cpe[1],
                                                           port.version.version)
      -- local product, version, vupdate, from, to = cpe_info("cpe:/a:samba:samba",
      --                                                      "3.X - 4.X")
      if product ~= nil then
         local vulns = nil
         if version ~= nil then
            log_product(product, version, vupdate)
            vulns = vulnerabilities(product, version, vupdate, false)
         else
            version = port.version.version
            vupdate = "*"
            log_product(product, version, vupdate)
            vulns = vulnerabilities(product, from, to, true)
         end
         local nvulns = table.remove(vulns, 1)
         if nvulns > 0 then
            table.insert(vulns, 1, fmt("source: %s", "nvd.nist.gov"))
            table.insert(vulns, 2, fmt("product: %s", product))
            table.insert(vulns, 3, fmt("version: %s", version))
            table.insert(vulns, 4, fmt("vupdate: %s", vupdate))
            table.insert(vulns, 5, fmt("cves: %d", nvulns))
            table.insert(vulns, 6,
                         fmt(
                            "\t%-15s\t%-5s\t%-5s\t%-10s\t%-10s",
                            "CVE ID", "CVSSv2", "CVSSv3", "ExploitDB", "Metasploit"
                         )
            )
            return vulns
         end
      else
         local vulns = {}
         table.insert(vulns, 1,
                      "No match found. If you think this could be an error, open an Issue in GitHub.")
         table.insert(vulns, 2,
                      fmt("Attach the following information in the Issue: cpe => %s | version => %s.",
                          port.version.cpe[1], port.version.version))
         return vulns
      end
   end
end


local function postaction ()
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
