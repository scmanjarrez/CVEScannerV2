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
--- Execute CVEscannerV2
-- @usage nmap -sV <target-ip> --script=./cvescannerv2.nse
--
-- @output
-- PORT      STATE SERVICE       VERSION
-- 3306/tcp  open  mysql         MySQL 5.5.55
-- | cvescannerv2:
-- |   source: nvd.nist.gov
-- |   product: MySQL
-- |   version: 5.5.55
-- |   n_vulnerabilities: 5
-- |   vulnerabilities:
-- |     CVE ID           CVSSv2   CVSSv3   Exploits
-- |     CVE-2021-3278    7.5      9.8      Yes
-- |     CVE-2019-13401   6.8      8.8      No
-- |     CVE-2019-13402   6.5      8.8      No
-- |     CVE-2016-3976    5.0      7.5      Yes
-- |_    CVE-2014-3631    7.2      -        Yes
--
---

categories = {"discovery", "version", "safe"}
author = "Sergio Chica"

local nmap = require "nmap"
local stdnse = require "stdnse"
local sql = require "luasql.sqlite3"

local DB = 'cve.db'
local env = sql.sqlite3()
local conn = env:connect(DB)
local logger = assert(io.open('cvescannerv2.log', 'a'))
local time = os.date("%Y-%m-%d %H:%M:%S")

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


local function fmt (msg, ...)
   return string.format(msg, ...)
end


local function log (msg, ...)
   logger:write(fmt(msg .. "\n", ...))
   stdnse.verbose(2, msg, ...)
end


local function check_db ()
   local db = io.open(DB, "r")
   return db ~= nil and io.close(db)
end


local function timestamp ()
   logger:write(fmt("#################################################\n" ..
                    "############## %s ##############\n" ..
                    "#################################################\n\n", time))
   stdnse.verbose(2, fmt("[INFO] Starting analysis ..."))
   stdnse.verbose(2, fmt("[INFO] timestamp: %s", time))
end


local function log_exploit (vuln)
   local cur = conn:execute(
      fmt([[
          SELECT Referenced.Exploit, Exploits.Name, Exploits.Metasploit
          FROM Referenced
          INNER JOIN Exploits ON Referenced.Exploit = Exploits.Exploit
          WHERE Referenced.CVE = "%s"
          ]],
          vuln)
   )
   local exploit, name, metasploit = cur:fetch()
   while exploit do
      log("[INFO] cve_id: %s", vuln)
      log("[INFO] exploit_name: %s", name)
      log("[INFO] metasploit_name: %s", metasploit)
      log("[INFO] exploit_url: https://www.exploit-db.com/exploits/%s", exploit)
      exploit, name, metasploit = cur:fetch()
   end
end


local function vulnerabilities (product, version)
   -- Query CVE, CVSSv2, CVSSv3, Exist_Exploits, Exist_Metasploit
   -- by product and version
   local cur = conn:execute(
      fmt([[
          SELECT Affected.CVE, CVEs.CVSSV2, CVEs.CVSSV3,
          (SELECT EXISTS (SELECT 1 FROM Referenced WHERE CVE = Affected.CVE)) AS ExploitDB,
          (SELECT EXISTS (SELECT 1 FROM Exploits as ex
          INNER JOIN Referenced AS rf ON rf.Exploit = ex.Exploit
          WHERE rf.CVE = Affected.CVE AND ex.Metasploit IS NOT NULL)) AS Metasploit
          FROM Products
          INNER JOIN Affected ON Products.ProductID = Affected.ProductID
          INNER JOIN CVEs ON Affected.CVE = CVEs.CVE
          INNER JOIN Referenced on Affected.CVE = Referenced.CVE
          INNER JOIN Exploits ON Referenced.Exploit = Exploits.Exploit
          WHERE Products.Product = "%s" AND Products.Version = "%s"
          GROUP BY Affected.CVE
          ]],
          product, version)
   )
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

   log("[INFO] n_vulnerabilities: %d", #sorted)

   -- Pretty print the output
   local output = {}
   for _, value in ipairs(sorted) do
      log_exploit(value[1])
      table.insert(output,
                   fmt(
                      "%-15s\t%-5s\t%-5s\t%-10s\t%-10s",
                      value[1], value[2],
                      value[3] and value[3] or "-",
                      value[4] == 1 and "Yes" or "No",
                      value[5] == 1 and "Yes" or "No"
                   )
      )
   end
   cur:close()
   return output
end


local function portaction (host, port)
   if check_db() then
      timestamp()
      local product = port.version.product
      local version = port.version.version

      log("[INFO] product: %s", product)
      log("[INFO] version: %s", version)

      local vulns = vulnerabilities(string.lower(product), version)
      local nvulns = #vulns
      if nvulns > 0 then
         table.insert(vulns, 1, "source: nvd.nist.gov")
         table.insert(vulns, 2, fmt("product: %s", product))
         table.insert(vulns, 3, fmt("version: %s", version))
         table.insert(vulns, 4, fmt("n_vulnerabilities: %d", nvulns))
         table.insert(vulns, 5, "vulnerabilities:")
         table.insert(vulns, 6,
                      fmt(
                         "%-15s\t%-5s\t%-5s\t%-10s\t%-10s",
                         "CVE ID", "CVSSv2", "CVSSv3", "ExploitDB", "Metasploit"
                      )
         )
         return vulns
      end
   else
      stdnse.verbose(1,
                     "Database not found. " ..
                     "Run ./databases.py before running nmap script.")
   end
end


local function postaction ()
        conn:close()
        env:close()
        logger:write("\n")
        logger:close()
end


local ActionsTable = {
  portrule = portaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function (...) return ActionsTable[SCRIPT_TYPE](...) end
